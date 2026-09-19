"""T-067, T-068 and the Phase 5 exit criteria: byte-identical scoring against
the same snapshot, every score explained, and 50k assets well inside 60s."""

from __future__ import annotations

import copy
import json
import time
from datetime import date

from _policy import load_documents, make_system, real_policy
from qavach_core.model.enums import CryptoFunction, FindingClass, MigrationAuthority
from qavach_core.model.identity import AssetIdentity, IdentityKind
from qavach_core.model.locus import FileLocus, NetworkLocus, SourceLocus
from qavach_core.model.system import DataClass
from qavach_core.policy import PolicySnapshot
from qavach_core.risk import AssetRiskInput, UrgencyBand, score_asset, score_estate

POLICY = real_policy()
AS_OF = date(2026, 9, 20)


def _identity(n: int) -> AssetIdentity:
    return AssetIdentity(kind=IdentityKind.ALGO, key=f"{n:064x}")


def _asset(n: int = 0, **kw):  # type: ignore[no-untyped-def]
    base = {
        "identity": _identity(n),
        "finding_class": FindingClass.QUANTUM_VULNERABLE,
        "also_quantum_vulnerable": False,
        "function": CryptoFunction.KEY_AGREEMENT,
        "authority": MigrationAuthority.SELF,
        "loci": (SourceLocus(repo="r", commit="c", path="a.py", start_line=n, end_line=n),),
        "system": make_system(criticality=4, internet_facing=True, retention_years=10),
    }
    base.update(kw)
    return AssetRiskInput(**base)


def _serialise(scores) -> str:  # type: ignore[no-untyped-def]
    return json.dumps(
        [
            {
                "id": s.identity.key,
                "band": s.band.value,
                "outcome": s.outcome,
                "reason": s.reason,
                "gap": None if s.mosca is None else s.mosca.gap_years,
                "ev": None if s.ev is None else s.ev.ev,
                "y": None if s.y is None else s.y.years,
                "explain": [e.to_dict() for e in s.explanations()],
            }
            for s in scores
        ],
        sort_keys=True,
    )


def _mixed_estate(count: int) -> list[AssetRiskInput]:
    classes = list(FindingClass)
    functions = [*CryptoFunction, None]
    authorities = list(MigrationAuthority)
    classes_dc = list(DataClass)
    systems = [
        make_system(
            id=f"s{i}",
            criticality=1 + i % 5,
            data_class=classes_dc[i % 4],
            internet_facing=bool(i % 2),
            retention_years=float(i % 12),
            regimes=frozenset({"cii"} if i % 3 == 0 else set()),
        )
        for i in range(60)
    ]
    out = []
    for n in range(count):
        out.append(
            _asset(
                n,
                finding_class=classes[n % len(classes)],
                function=functions[n % len(functions)],
                authority=authorities[n % len(authorities)],
                system=None if n % 97 == 0 else systems[n % 60],
                artefact_lifetime_years=(None, 0.25, 5.0, 20.0)[n % 4],
                loci=(
                    SourceLocus(repo="r", commit="c", path="a.py", start_line=n, end_line=n),
                    NetworkLocus(host=f"h{n % 50}", port=443, sni=None, protocol="tls"),
                ),
            )
        )
    return out


def test_scoring_is_byte_identical_across_runs_and_snapshot_reloads() -> None:
    estate = _mixed_estate(500)
    first = _serialise(score_estate(estate, policy=POLICY, as_of=AS_OF))
    again = _serialise(score_estate(estate, policy=POLICY, as_of=AS_OF))
    reloaded = PolicySnapshot.from_json(POLICY.canonical_json())
    third = _serialise(score_estate(estate, policy=reloaded, as_of=AS_OF))
    assert first == again == third


def test_input_order_does_not_change_any_individual_score() -> None:
    estate = _mixed_estate(120)
    forward = {
        s.identity.key: _serialise([s]) for s in score_estate(estate, policy=POLICY, as_of=AS_OF)
    }
    backward = {
        s.identity.key: _serialise([s])
        for s in score_estate(list(reversed(estate)), policy=POLICY, as_of=AS_OF)
    }
    assert forward == backward


def test_scoring_reads_only_the_snapshot_it_was_given() -> None:
    """T-068: change a value in a *different* snapshot and only that snapshot's
    scores move; the original is untouched (it is frozen)."""
    docs = copy.deepcopy(load_documents())
    docs["z_scenarios"]["default"]["value"] = "aggressive"
    other = PolicySnapshot.from_documents(docs)
    a = score_asset(_asset(), policy=POLICY, as_of=AS_OF)
    b = score_asset(_asset(), policy=other, as_of=AS_OF)
    assert a.z is not None and b.z is not None
    assert a.z.bound_by == "scenario:nominal" and b.z.bound_by == "scenario:aggressive"
    assert POLICY.value("z_scenarios.default") == "nominal"


def test_every_scored_result_explains_itself_with_cited_policy() -> None:
    for s in score_estate(_mixed_estate(200), policy=POLICY, as_of=AS_OF):
        if s.system_id is None:
            assert s.explanations() == ()
            continue
        for e in s.explanations():
            d = e.to_dict()
            assert d["formula"] and d["inputs"] is not None
            assert all(p["basis"] for p in d["policy"]), d["name"]
        names = {e.name for e in s.explanations()}
        assert {"shelf_life", "z_effective", "y_estimate", "mosca", "caraf_d4_outcome"} <= names


def test_estimates_and_thresholds_are_flagged_as_heuristics_wherever_they_appear() -> None:
    s = score_asset(_asset(), policy=POLICY, as_of=AS_OF)
    flags = {e.name: e.heuristic for e in s.explanations()}
    assert flags["y_estimate"] and flags["mosca"] and flags["caraf_d3_expected_value"]


def test_an_asset_with_no_system_is_visible_unscored_and_not_given_invented_context() -> None:
    s = score_asset(_asset(system=None), policy=POLICY, as_of=AS_OF)
    assert s.band is UrgencyBand.COVERAGE_GAP and s.outcome is None
    assert s.system_id is None and "unassigned" in s.reason and s.ev is None


def test_I2_at_the_score_level_the_long_lived_signer_outranks_the_ephemeral_one() -> None:
    def gap(lifetime: float) -> float:
        s = score_asset(
            _asset(
                function=CryptoFunction.SIGNATURE,
                artefact_lifetime_years=lifetime,
                system=make_system(retention_years=0, criticality=3),
            ),
            policy=POLICY,
            as_of=AS_OF,
        )
        assert s.mosca is not None and s.mosca.gap_years is not None
        return s.mosca.gap_years

    assert gap(25) > gap(10) > gap(2) > gap(0.25)


def test_I9_external_trust_anchors_are_never_given_an_outcome_at_any_score() -> None:
    for s in score_estate(
        [_asset(n, authority=MigrationAuthority.EXTERNAL_TRUST_ANCHOR) for n in range(50)],
        policy=POLICY,
        as_of=AS_OF,
    ):
        assert s.outcome is None


def test_I8_no_unknown_asset_is_ever_scored_as_a_comfortable_band() -> None:
    for s in score_estate(
        [_asset(n, finding_class=FindingClass.UNKNOWN) for n in range(50)],
        policy=POLICY,
        as_of=AS_OF,
    ):
        assert s.band is UrgencyBand.COVERAGE_GAP and s.outcome is None


def test_fifty_thousand_assets_score_well_inside_the_sixty_second_budget() -> None:
    """NFR-02. Generous ceiling (30s) so CI noise cannot flake it; the point is
    that pure-Python scoring with full explanations is nowhere near 60s."""
    estate = _mixed_estate(50_000)
    start = time.perf_counter()
    scores = score_estate(estate, policy=POLICY, as_of=AS_OF)
    elapsed = time.perf_counter() - start
    assert len(scores) == 50_000
    assert elapsed < 30, f"50k assets took {elapsed:.1f}s"
    print(f"\n50k assets scored in {elapsed:.2f}s")  # noqa: T201


def test_a_file_locus_only_asset_scores() -> None:
    s = score_asset(_asset(loci=(FileLocus(path="/etc/x", offset=0),)), policy=POLICY, as_of=AS_OF)
    assert s.y is not None and s.y.base_locus_kind == "file"
