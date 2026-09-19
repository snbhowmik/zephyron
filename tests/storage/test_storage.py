"""T-070, T-071, T-076, T-077 - models, migrations, repositories. Runs on SQLite
(portable types), so `make test-unit` needs no Docker or Postgres."""

from __future__ import annotations

import importlib.util
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from qavach_core.export import RegisterInput, register_entry
from qavach_core.model.enums import ConfidenceTier, FindingClass
from qavach_core.reconcile import adjudicate, apply_adjudications
from qavach_storage import (
    UNASSIGNED,
    AssetFilter,
    Repository,
    asset_id_for,
    create_all,
    make_engine,
    models,
    session_factory,
)
from sqlalchemy import inspect

ROOT = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("schema_check", ROOT / "scripts/schema_check.py")
assert _spec and _spec.loader
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
POLICY = sc.load_policy()


@pytest.fixture
def repo():  # type: ignore[no-untyped-def]
    engine = make_engine("sqlite://")
    create_all(engine)
    with session_factory(engine)() as session:
        yield Repository(session)


def _seed(repo: Repository, scan_id: str = "scan-1"):  # type: ignore[no-untyped-def]
    repo.create_scan(
        scan_id=scan_id,
        target_ref="repo",
        policy=POLICY,
        z_scenario="nominal",
        as_of="2026-09-20",
        now=NOW,
    )
    _, _, items = sc.sample_documents()
    ids = repo.save_assets(scan_id, [i.asset for i in items])
    repo.save_scores(
        scan_id,
        POLICY.snapshot_id,
        [(ids[i.asset.identity.key], i.score.system_id, register_entry(i)) for i in items],
    )
    return items, ids


# ---- schema and migrations ----


def test_every_arch_table_exists() -> None:
    engine = make_engine("sqlite://")
    create_all(engine)
    tables = set(inspect(engine).get_table_names())
    assert {
        "scan_runs",
        "collector_runs",
        "crypto_assets",
        "occurrences",
        "systems",
        "asset_systems",
        "system_deps",
        "risk_scores",
        "recommendations",
        "migration_units",
        "migration_edges",
        "suppressions",
        "audit_log",
    } <= tables


def test_the_alembic_baseline_produces_exactly_the_schema_the_models_declare(
    tmp_path: Path,
) -> None:
    """Migrations and models must not drift: upgrade to head, then diff every
    table and column against a create_all() database."""
    from alembic import command
    from alembic.config import Config

    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = Config(str(ROOT / "packages/storage/alembic.ini"))
    cfg.set_main_option(
        "script_location", str(ROOT / "packages/storage/src/qavach_storage/migrations")
    )
    import os

    os.environ["QAVACH_DATABASE_URL"] = url
    try:
        command.upgrade(cfg, "head")
    finally:
        del os.environ["QAVACH_DATABASE_URL"]
    migrated = inspect(make_engine(url))
    reference_engine = make_engine("sqlite://")
    create_all(reference_engine)
    reference = inspect(reference_engine)
    for table in reference.get_table_names():
        assert table in migrated.get_table_names(), table
        assert {c["name"] for c in migrated.get_columns(table)} == {
            c["name"] for c in reference.get_columns(table)
        }, table
        assert {tuple(i["column_names"]) for i in migrated.get_indexes(table)} == {
            tuple(i["column_names"]) for i in reference.get_indexes(table)
        }, table


def test_policy_snapshot_is_stored_whole_and_reloads_identically(repo: Repository) -> None:
    repo.create_scan(
        scan_id="s",
        target_ref="t",
        policy=POLICY,
        z_scenario="nominal",
        as_of="2026-09-20",
        now=NOW,
    )
    loaded = repo.policy_snapshot("s")
    assert (
        loaded.snapshot_id == POLICY.snapshot_id
        and loaded.canonical_json() == POLICY.canonical_json()
    )


# ---- round trip ----


def test_assets_round_trip_exactly_including_loci_disputes_and_tiers(repo: Repository) -> None:
    items, _ = _seed(repo)
    original = sorted((i.asset for i in items), key=lambda a: a.identity.key)
    loaded = repo.load_assets("scan-1")
    assert len(loaded) == len(original)
    for a, b in zip(original, loaded, strict=True):
        assert a == b


def test_ids_are_deterministic_and_saving_twice_is_idempotent(repo: Repository) -> None:
    items, ids = _seed(repo)
    again = repo.save_assets("scan-1", [i.asset for i in items])
    assert again == ids
    assert ids[items[0].asset.identity.key] == asset_id_for("scan-1", items[0].asset.identity.key)
    assert len(repo.load_assets("scan-1")) == len(items)


def test_a_dispute_survives_the_round_trip() -> None:
    from qavach_core.model.dispute import AttributeClaim, Dispute
    from qavach_core.model.locus import FileLocus
    from qavach_storage.repository import dispute_from_dict, dispute_to_dict

    d = Dispute(
        attribute="mode",
        claims=(
            AttributeClaim("gcm", "a", ConfidenceTier.AST, FileLocus(path="x", offset=3)),
            AttributeClaim("cbc", "b", ConfidenceTier.PATTERN, FileLocus(path="x", offset=3)),
        ),
        adjudicated_value="gcm",
        adjudicated_by="ops",
        adjudicated_at=NOW,
        adjudication_reason="read it",
    )
    assert dispute_from_dict(dispute_to_dict(d)) == d


# ---- inventory queries ----


def test_the_inventory_pages_and_facets_by_every_dimension(repo: Repository) -> None:
    items, _ = _seed(repo)
    page = repo.list_assets("scan-1", page=1, page_size=4)
    assert page.total == len(items) == 9 and len(page.items) == 4
    f = page.facets
    assert f["finding_class"]["unknown"] == 1  # I8: its own bucket
    assert sum(f["finding_class"].values()) == 9
    assert set(f) == {
        "finding_class",
        "migration_authority",
        "disputed",
        "band",
        "outcome",
        "system",
    }


def test_filters_combine_and_the_facets_follow_the_filtered_set(repo: Repository) -> None:
    _seed(repo)
    weak = repo.list_assets("scan-1", AssetFilter(finding_class="classical-weak"))
    assert weak.total == 2 and {i["family"] for i in weak.items} == {"MD5", "3DES"}
    assert weak.facets["finding_class"] == {"classical-weak": 2}
    both = repo.list_assets(
        "scan-1", AssetFilter(finding_class="quantum-vulnerable", band="overdue")
    )
    assert all(i["finding_class"] == "quantum-vulnerable" for i in both.items)
    assert repo.list_assets("scan-1", AssetFilter(text="rsa")).total == 1
    assert repo.list_assets("scan-1", AssetFilter(finding_class="nope")).total == 0


def test_an_unassigned_asset_is_a_visible_bucket_never_dropped(repo: Repository) -> None:
    repo.create_scan(
        scan_id="u",
        target_ref="t",
        policy=POLICY,
        z_scenario="nominal",
        as_of="2026-09-20",
        now=NOW,
    )
    _, _, items = sc.sample_documents()
    from qavach_core.risk import AssetRiskInput, score_asset

    asset = items[0].asset
    score = score_asset(
        AssetRiskInput(
            identity=asset.identity,
            finding_class=asset.finding_class,
            also_quantum_vulnerable=False,
            function=asset.function,
            authority=asset.migration_authority,
            loci=tuple(o.locus for o in asset.occurrences),
            system=None,
        ),
        policy=POLICY,
        as_of=sc.AS_OF,
    )
    ids = repo.save_assets("u", [asset])
    repo.save_scores(
        "u",
        POLICY.snapshot_id,
        [(ids[asset.identity.key], None, register_entry(RegisterInput(asset=asset, score=score)))],
    )
    page = repo.list_assets("u", AssetFilter(system_id=UNASSIGNED))
    assert page.total == 1 and page.facets["system"] == {"unassigned": 1}
    assert (
        page.items[0]["scores"][0]["system_id"] is None
        and page.items[0]["scores"][0]["band"] == "coverage-gap"
    )


def test_the_detail_carries_occurrences_risk_and_explanations(repo: Repository) -> None:
    items, ids = _seed(repo)
    rsa = next(i for i in items if i.asset.algorithm_family == "RSASSA-PKCS1")
    detail = repo.get_asset_detail(ids[rsa.asset.identity.key])
    assert detail is not None and len(detail["occurrences"]) == 2
    assert detail["risk"][0]["explanations"] and detail["concluded_tier"] == "runtime"
    assert repo.get_asset_detail("nope") is None


def test_capability_only_is_flagged_in_the_listing(repo: Repository) -> None:
    _seed(repo)
    flags = {
        i["family"]: i["capability_only"] for i in repo.list_assets("scan-1", page_size=50).items
    }
    assert flags["RSASSA-PKCS1"] is False


def test_page_size_is_capped(repo: Repository) -> None:
    _seed(repo)
    assert repo.list_assets("scan-1", page_size=10_000).page_size == 500


def test_the_inventory_is_fast_at_fifty_thousand_assets(repo: Repository) -> None:
    """Phase 6 exit criterion: faceted inventory under 500 ms at 50k assets. SQLite
    stands in for Postgres here, so the ceiling is loose; the point is that the
    indexed GROUP BY plan does not degrade quadratically."""
    from sqlalchemy import insert

    repo.create_scan(
        scan_id="big",
        target_ref="t",
        policy=POLICY,
        z_scenario="nominal",
        as_of="2026-09-20",
        now=NOW,
    )
    classes = [c.value for c in FindingClass]
    n = 50_000
    repo.s.execute(
        insert(models.CryptoAssetRow),
        [
            {
                "id": f"a{i}",
                "scan_run_id": "big",
                "identity_kind": "algo",
                "identity_key": f"{i:064x}",
                "asset_type": "algorithm",
                "function": "signature",
                "family": f"F{i % 40}",
                "parameter_set": None,
                "curve": None,
                "mode": None,
                "padding": None,
                "oid": None,
                "finding_class": classes[i % 5],
                "migration_authority": "self",
                "authority_basis": "b",
                "concluded_tier": 50,
                "disputed": False,
                "disputes_json": [],
            }
            for i in range(n)
        ],
    )
    repo.s.execute(
        insert(models.RiskScoreRow),
        [
            {
                "asset_id": f"a{i}",
                "system_id": f"s{i % 20}",
                "scan_run_id": "big",
                "policy_snapshot_id": "p",
                "band": ("overdue", "planned", "imminent")[i % 3],
                "outcome": "migrate",
                "reason": "r",
                "mosca_gap": 1.0,
                "ev": 2.0,
                "z_effective": "2028-12-31",
                "z_source": "x",
                "entry_json": {},
            }
            for i in range(n)
        ],
    )
    repo.s.flush()
    start = time.perf_counter()
    page = repo.list_assets(
        "big", AssetFilter(finding_class="quantum-vulnerable"), page=3, page_size=50
    )
    elapsed = time.perf_counter() - start
    assert page.total == n // 5 and len(page.items) == 50
    assert elapsed < 3.0, f"{elapsed:.2f}s"  # generous on SQLite; Postgres target is < 0.5s
    print(f"\ninventory over {n} assets: {elapsed * 1000:.0f} ms")


# ---- T-076 suppressions, T-077 audit, T-025 adjudications ----


def test_a_suppression_needs_a_reason_and_a_future_expiry_and_is_audited(repo: Repository) -> None:
    with pytest.raises(ValueError, match="reason"):
        repo.suppress("k", reason=" ", author="a", now=NOW, expires_at=NOW + timedelta(days=1))
    with pytest.raises(ValueError, match="expire"):
        repo.suppress("k", reason="r", author="a", now=NOW, expires_at=NOW)
    repo.suppress(
        "k", reason="test fixture", author="ops", now=NOW, expires_at=NOW + timedelta(days=30)
    )
    assert "k" in repo.suppressed_keys(NOW)
    log = repo.s.query(models.AuditLog).all()
    assert [(e.actor, e.action, e.subject) for e in log] == [("ops", "suppress", "k")]


def test_a_suppression_expires_and_a_suppressed_asset_is_flagged_not_hidden(
    repo: Repository,
) -> None:
    items, _ = _seed(repo)
    key = items[0].asset.identity.key
    repo.suppress(
        key,
        reason="accepted risk",
        author="ops",
        now=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    listed = {i["identity_key"]: i for i in repo.list_assets("scan-1", page_size=50).items}
    assert listed[key]["suppressed"] is True and len(listed) == 9  # still listed
    assert key not in repo.suppressed_keys(datetime.now(UTC) + timedelta(days=2))


def test_an_adjudication_is_persisted_audited_and_reapplies_after_a_rescan(
    repo: Repository,
) -> None:
    from qavach_core.model.locus import FileLocus
    from qavach_core.reconcile import OccurrenceClaim, merge_all

    items, _ = _seed(repo)
    identity = items[0].asset.identity
    locus = FileLocus(path="pay.c", offset=42)

    def claims():  # type: ignore[no-untyped-def]
        return [
            OccurrenceClaim(
                identity=identity,
                locus=locus,
                collector=c,
                tool_version="1",
                confidence=t,
                detection_method="x",
                raw_ref="r",
                observed_at=NOW,
                mode=m_,
            )
            for c, t, m_ in (
                ("ast", ConfidenceTier.AST, "gcm"),
                ("pat", ConfidenceTier.PATTERN, "cbc"),
            )
        ]

    ruling = adjudicate(
        merge_all(claims())[0], "mode", "gcm", by="ops", at=NOW, reason="read pay.c"
    )
    repo.save_adjudication(ruling, now=NOW)
    stored = repo.load_adjudications()
    assert stored == [ruling]
    outcome = apply_adjudications(
        merge_all(claims()), stored
    )  # a brand-new merge, as after a re-scan
    assert outcome.applied == (ruling,) and not outcome.results[0].disputed
    assert any(e.action == "adjudicate" for e in repo.s.query(models.AuditLog))


def test_systems_round_trip_with_dependencies_and_bindings(repo: Repository) -> None:
    from qavach_core.context import parse_systems_csv

    text = (ROOT / "tests/fixtures/demo/systems.csv").read_text()
    imported = parse_systems_csv(text, POLICY)
    repo.replace_systems(imported)
    systems, bindings = repo.load_systems()
    assert {s.id for s in systems} == {"payments-core", "settlement"}
    pay = next(s for s in systems if s.id == "payments-core")
    assert pay.depends_on == {"settlement"} and pay.regulatory_regimes == {"cii", "sebi-re"}
    assert bindings["payments-core"]["repos"] == ["github.com/acme/polyglot-payments"]
    repo.replace_systems(imported)  # idempotent
    assert len(repo.load_systems()[0]) == 2
