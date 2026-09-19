"""T-050..T-053 - systems import with an error report, asset binding into an
explicit unassigned bucket, retention inference, and dependencies."""

from __future__ import annotations

import pytest
from _policy import real_policy
from qavach_core.context import (
    BindingKey,
    SystemBindings,
    bind_assets,
    infer_retention,
    keys_for_locus,
    normalise_repo,
    parse_system_rows,
    parse_systems_csv,
    system_dependency_edges,
)
from qavach_core.model.identity import AssetIdentity, IdentityKind
from qavach_core.model.locus import (
    CloudLocus,
    ContainerLocus,
    FileLocus,
    HostLocus,
    NetworkLocus,
    SourceLocus,
)
from qavach_core.model.system import DataClass

POLICY = real_policy()
HEADER = (
    "id,name,owner,criticality,data_classification,internet_facing,retention_years,"
    "regulatory_regimes,depends_on,repos,endpoints\n"
)


def _csv(*lines: str) -> str:
    return HEADER + "\n".join(lines) + "\n"


def _row(**over: str) -> dict[str, str]:
    base = {
        "id": "pay",
        "name": "Payments",
        "owner": "team-a",
        "criticality": "5",
        "data_classification": "restricted",
        "internet_facing": "yes",
        "retention_years": "10",
    }
    base.update(over)
    return base


# ---- T-050 import ----


def test_a_valid_csv_imports_every_field() -> None:
    result = parse_systems_csv(
        _csv(
            'pay,Payments,team-a,5,restricted,true,10,cii;sebi-re,ledger,github.com/acme/pay,"pay.acme.in:443"',
            "ledger,Ledger,team-b,4,confidential,no,7,,,,",
        ),
        POLICY,
    )
    assert result.ok and len(result.systems) == 2
    pay = next(s for s in result.systems if s.id == "pay")
    assert (pay.criticality, pay.data_classification, pay.retention_years) == (
        5,
        DataClass.RESTRICTED,
        10.0,
    )
    assert pay.internet_facing and pay.regulatory_regimes == {"cii", "sebi-re"}
    assert pay.depends_on == {"ledger"} and not pay.retention_inferred
    assert result.bindings["pay"].repos == {"github.com/acme/pay"}


def test_every_problem_is_reported_with_its_row_and_field_not_just_the_first() -> None:
    rows = [
        _row(id="a", criticality="9"),
        _row(id="b", data_classification="top-secret"),
        _row(id="c", internet_facing="maybe"),
        _row(id="d", retention_years="-3"),
        _row(id="", name=""),
        _row(id="ok"),
    ]
    result = parse_system_rows(rows, POLICY)
    assert [s.id for s in result.systems] == ["ok"]
    fields = {(i.row, i.field) for i in result.errors}
    assert {
        (1, "criticality"),
        (2, "data_classification"),
        (3, "internet_facing"),
        (4, "retention_years"),
        (5, "id"),
        (5, "name"),
    } <= fields
    assert all(i.message for i in result.issues)


def test_a_bad_row_is_excluded_never_half_imported() -> None:
    result = parse_system_rows([_row(id="bad", criticality="x"), _row(id="good")], POLICY)
    assert [s.id for s in result.systems] == ["good"] and "bad" not in result.bindings


def test_missing_required_columns_is_one_clear_file_level_error() -> None:
    result = parse_systems_csv("id,name\nx,y\n", POLICY)
    assert not result.ok and result.systems == () and result.issues[0].row == 0
    assert "criticality" in result.issues[0].message


def test_duplicate_ids_are_rejected_naming_the_first_row() -> None:
    result = parse_system_rows([_row(id="a"), _row(id="a", name="Other")], POLICY)
    assert len(result.systems) == 1
    assert any("duplicate" in i.message and "row 1" in i.message for i in result.errors)


def test_unknown_columns_are_a_warning_not_a_failure() -> None:
    result = parse_system_rows([_row(**{"cost_centre": "x"})], POLICY)
    assert result.ok and any(
        i.severity == "warning" and i.field == "cost_centre" for i in result.issues
    )


def test_internet_facing_is_required_because_a_blank_would_under_report_risk() -> None:
    result = parse_system_rows([_row(internet_facing="")], POLICY)
    assert not result.ok and result.errors[0].field == "internet_facing"


def test_yaml_style_rows_with_real_lists_and_numbers_import() -> None:
    result = parse_system_rows(
        [
            {
                **_row(),
                "criticality": 5,
                "internet_facing": True,
                "retention_years": 10,
                "regulatory_regimes": ["CII"],
                "repos": ["github.com/a/b"],
            }
        ],
        POLICY,
    )
    assert result.ok and result.systems[0].regulatory_regimes == {"cii"}


# ---- T-052 retention inference ----


def test_blank_retention_is_inferred_flagged_and_surfaced() -> None:
    result = parse_system_rows(
        [_row(retention_years="", data_classification="confidential")], POLICY
    )
    s = result.systems[0]
    assert s.retention_inferred is True and s.retention_years == 7.0
    info = [i for i in result.issues if i.severity == "info"]
    assert info and "inferred 7 years" in info[0].message and "HEURISTIC" in info[0].message


def test_a_supplied_retention_is_never_overridden_by_inference() -> None:
    s = parse_system_rows(
        [_row(retention_years="2", data_classification="restricted")], POLICY
    ).systems[0]
    assert s.retention_years == 2.0 and s.retention_inferred is False


@pytest.mark.parametrize("dc", list(DataClass))
def test_inference_exists_for_every_data_class_and_grows_with_sensitivity(dc: DataClass) -> None:
    years, basis = infer_retention(dc, POLICY)
    assert years >= 0 and basis
    assert (
        infer_retention(DataClass.RESTRICTED, POLICY)[0]
        >= infer_retention(DataClass.PUBLIC, POLICY)[0]
    )


# ---- T-053 dependencies ----


def test_dependencies_are_validated_and_exposed_as_sorted_edges() -> None:
    result = parse_system_rows(
        [_row(id="a", depends_on="b;c"), _row(id="b", depends_on="c"), _row(id="c")], POLICY
    )
    assert result.ok
    assert system_dependency_edges(result.systems) == (("a", "b"), ("a", "c"), ("b", "c"))


def test_a_dangling_dependency_is_an_error_and_exclusion_cascades() -> None:
    result = parse_system_rows(
        [_row(id="a", depends_on="ghost"), _row(id="b", depends_on="a"), _row(id="c")], POLICY
    )
    assert [s.id for s in result.systems] == ["c"]
    assert {i.row for i in result.errors} == {1, 2}


def test_a_self_dependency_is_an_error() -> None:
    result = parse_system_rows([_row(id="a", depends_on="a")], POLICY)
    assert result.systems == () and "itself" in result.errors[0].message


def test_a_cycle_is_not_an_import_error_because_the_roadmap_handles_it() -> None:
    result = parse_system_rows([_row(id="a", depends_on="b"), _row(id="b", depends_on="a")], POLICY)
    assert result.ok and len(result.systems) == 2


# ---- T-051 binding ----


def _id(n: int) -> AssetIdentity:
    return AssetIdentity(kind=IdentityKind.ALGO, key=f"{n:064x}")


BINDINGS = {
    "pay": SystemBindings(
        repos=frozenset({"https://GitHub.com/acme/pay.git"}),
        images=frozenset({"sha256:aaa"}),
        endpoints=frozenset({"pay.acme.in", "*.api.acme.in", "db.acme.in:5432"}),
        cloud_accounts=frozenset({"aws:123456789012"}),
        hosts=frozenset({"agent-7"}),
    ),
    "ledger": SystemBindings(repos=frozenset({"git@github.com:acme/ledger"})),
}


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://GitHub.com/acme/pay.git", "git@github.com:acme/pay"),
        ("github.com/acme/pay/", "https://github.com/acme/pay"),
        ("https://user:tok@github.com/acme/pay.git", "github.com/acme/pay"),
    ],
)
def test_repo_urls_normalise_to_one_canonical_form(a: str, b: str) -> None:
    assert normalise_repo(a) == normalise_repo(b)


def _bind(keys):  # type: ignore[no-untyped-def]
    return bind_assets({_id(1): keys}, BINDINGS)


def test_binds_by_repo_from_a_source_locus_and_from_the_scan_target() -> None:
    src = keys_for_locus(
        SourceLocus(repo="git@github.com:acme/pay", commit="c", path="a", start_line=1, end_line=1)
    )
    assert _bind(src).systems_for(_id(1)) == ("pay",)
    # a FileLocus carries no repo: the scan target supplies it
    file_keys = keys_for_locus(
        FileLocus(path="a.py", offset=3), scan_target=BindingKey("repo", "github.com/acme/ledger")
    )
    assert _bind(file_keys).systems_for(_id(1)) == ("ledger",)


def test_binds_by_image_endpoint_cloud_account_and_host() -> None:
    cases = [
        ContainerLocus(image_digest="sha256:AAA", layer_digest="l", path="/x"),
        NetworkLocus(host="PAY.acme.in", port=443, sni=None, protocol="tls"),
        NetworkLocus(host="v2.api.acme.in", port=8443, sni=None, protocol="tls"),
        NetworkLocus(host="db.acme.in", port=5432, sni=None, protocol="tls"),
        CloudLocus(provider="aws", account="123456789012", region="ap-south-1", resource_arn="arn"),
        HostLocus(host_identity="agent-7", path="/etc/x", offset=0),
    ]
    for locus in cases:
        assert _bind(keys_for_locus(locus)).systems_for(_id(1)) == ("pay",), locus


def test_endpoint_port_and_wildcard_rules_are_exact_not_fuzzy() -> None:
    def bound(host: str, port: int) -> tuple[str, ...]:
        return _bind(
            keys_for_locus(NetworkLocus(host=host, port=port, sni=None, protocol="tls"))
        ).systems_for(_id(1))

    assert bound("db.acme.in", 5433) == ()  # wrong port for a host:port binding
    assert bound("api.acme.in", 443) == ()  # '*.api.acme.in' does not match the bare apex
    assert bound("evil-api.acme.in", 443) == ()
    assert bound("pay.acme.in", 9999) == ("pay",)  # a bare host matches any port


def test_an_asset_matching_two_systems_is_bound_to_both_with_its_basis() -> None:
    keys = [BindingKey("repo", "github.com/acme/pay"), BindingKey("repo", "github.com/acme/ledger")]
    result = _bind(keys)
    assert result.systems_for(_id(1)) == ("ledger", "pay")
    assert result.matches[_id(1)][0].basis == ("repo:github.com/acme/ledger",)


def test_an_unmatched_asset_goes_to_the_visible_unassigned_bucket_never_dropped() -> None:
    assets = {
        _id(1): keys_for_locus(
            SourceLocus(repo="github.com/acme/pay", commit="c", path="a", start_line=1, end_line=1)
        ),
        _id(2): keys_for_locus(FileLocus(path="/etc/x", offset=0)),  # no key at all
        _id(3): [BindingKey("repo", "github.com/other/thing")],
    }
    result = bind_assets(assets, BINDINGS)
    assert set(result.matches) | set(result.unassigned) == set(assets)  # conservation
    assert set(result.unassigned) == {_id(2), _id(3)}


def test_binding_is_deterministic_and_order_independent() -> None:
    keys = [BindingKey("repo", "github.com/acme/ledger"), BindingKey("repo", "github.com/acme/pay")]
    assert _bind(keys).matches == _bind(list(reversed(keys))).matches
