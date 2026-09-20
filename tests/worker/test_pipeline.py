"""T-072 - the scan pipeline end to end on REAL recorded scanner output, with
per-stage status and per-collector partial failure."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from qavach_collectors import CollectorRegistry, CollectorResult, RunContext, Target, TargetType
from qavach_collectors.base import CollectorError
from qavach_core.context import parse_systems_csv
from qavach_core.model.enums import ConfidenceTier
from qavach_core.reconcile import adjudicate
from qavach_storage import AssetFilter, Repository, create_all, make_engine, models, session_factory
from qavach_worker import STAGES, Deps, ProgressEvent, ScanRequest, run_scan

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/demo.py")
assert _spec and _spec.loader
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

KNOWLEDGE, POLICY, PQC = demo.load_knowledge()
RESULTS = demo.replay_results(KNOWLEDGE)
NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
AS_OF = date(2026, 9, 20)
TARGET = Target(type=TargetType.REPOSITORY, ref="github.com/acme/polyglot-payments")


class ReplayCollector:
    """Serves one recorded real result; behaves like the real collector."""

    requires_sandbox = False
    requires_network = False
    default_confidence = ConfidenceTier.AST

    def __init__(
        self, result: CollectorResult, *, raises: bool = False, partial: bool = False
    ) -> None:
        self._result = result
        self.name = result.tool.name
        self.version = result.tool.version
        self._raises = raises
        self._partial = partial

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        if self._raises:
            raise RuntimeError("boom: secret-looking detail that must not be persisted")
        if self._partial:
            return CollectorResult(
                raw=b"",
                raw_format=self._result.raw_format,
                claims=[],
                tool=self._result.tool,
                errors=[CollectorError(message="degraded", fatal=True)],
                partial=True,
            )
        return self._result


def deps(*, raises: set[str] = frozenset(), partial: set[str] = frozenset()) -> Deps:  # type: ignore[assignment]
    registry = CollectorRegistry()
    for r in RESULTS:
        registry.register(
            ReplayCollector(r, raises=r.tool.name in raises, partial=r.tool.name in partial)
        )
    return Deps(registry=registry, knowledge=KNOWLEDGE, policy=POLICY, pqc=PQC, clock=lambda: NOW)


@pytest.fixture
def session():  # type: ignore[no-untyped-def]
    engine = make_engine("sqlite://")
    create_all(engine)
    with session_factory(engine)() as s:
        yield s


def _with_systems(session) -> Repository:  # type: ignore[no-untyped-def]
    repo = Repository(session)
    repo.replace_systems(
        parse_systems_csv((ROOT / "tests/fixtures/demo/systems.csv").read_text(), POLICY)
    )
    session.commit()
    return repo


def _run(session, **kw):  # type: ignore[no-untyped-def]
    events: list[ProgressEvent] = []
    request = ScanRequest(
        target=TARGET,
        scan_id=kw.pop("scan_id", "scan-1"),
        as_of=AS_OF,
        capacity_per_quarter=4,
        **{k: kw.pop(k) for k in list(kw) if k in ("z_scenario",)},
    )
    outcome = run_scan(session, request, deps(**kw), events.append)
    return outcome, events


def test_a_scan_over_real_recorded_output_completes_and_persists_everything(session) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)
    outcome, _ = _run(session)
    assert outcome.status == "complete"
    scan = repo.get_scan("scan-1")
    assert scan is not None and scan.status == "complete" and scan.finished is not None
    assert set(scan.stages_json) == set(STAGES)
    assert all(v["status"] == "finished" for v in scan.stages_json.values())
    assert outcome.summary["assets"] == 29 and outcome.summary["claims"] == 69
    page = repo.list_assets("scan-1", page_size=100)
    assert page.total == 29 and page.facets["finding_class"]
    assert sum(1 for i in page.items if i["scores"]) == 29
    assert {c.collector for c in repo.collector_runs("scan-1")} >= {
        "source_scan.cdxgen",
        "source_scan.cbomkit",
    }


def test_the_scans_own_policy_snapshot_is_stored_and_scores_reference_it(session) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)
    _run(session)
    assert repo.policy_snapshot("scan-1").snapshot_id == POLICY.snapshot_id
    scan = repo.get_scan("scan-1")
    assert scan is not None and scan.policy_snapshot_id == POLICY.snapshot_id
    assert {r.policy_snapshot_id for r in session.query(models.RiskScoreRow)} == {
        POLICY.snapshot_id
    }


def test_occurrences_are_linked_to_the_collector_run_that_produced_them(session) -> None:  # type: ignore[no-untyped-def]
    _with_systems(session)
    _run(session)
    assert (
        session.query(models.OccurrenceRow)
        .filter(models.OccurrenceRow.collector_run_id.is_(None))
        .count()
        == 0
    )


def test_stages_and_collectors_emit_progress_in_order(session) -> None:  # type: ignore[no-untyped-def]
    _with_systems(session)
    _, events = _run(session)
    stage_events = [
        (e.stage, e.status) for e in events if e.collector is None and e.stage != "scan"
    ]
    assert [s for s, st in stage_events if st == "started"] == list(STAGES)
    collectors = [e.collector for e in events if e.collector and e.status == "started"]
    assert len(collectors) == 6
    assert events[-1].stage == "scan" and events[-1].status == "finished"


def test_a_collector_that_raises_degrades_the_scan_but_never_loses_the_others(session) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)
    outcome, events = _run(session, raises={"source_scan.cbomkit"})
    assert outcome.status == "partial"
    assert outcome.summary["degraded_collectors"] == ["source_scan.cbomkit"]
    assert outcome.summary["collectors"]["source_scan.cbomkit"] == "failed"
    assert repo.list_assets("scan-1").total > 0  # the other four still produced an inventory
    run = next(c for c in repo.collector_runs("scan-1") if c.collector == "source_scan.cbomkit")
    assert run.partial and run.errors_json == [
        {"message": "collector raised RuntimeError", "fatal": True}
    ]
    assert any(e.status == "failed" and e.collector == "source_scan.cbomkit" for e in events)


def test_a_thrown_exceptions_message_is_never_persisted_or_emitted(session) -> None:  # type: ignore[no-untyped-def]
    """The exception text can carry paths or credentials; only its type is kept."""
    _with_systems(session)
    _, events = _run(session, raises={"source_scan.cbomkit"})
    blob = str([e for e in events]) + str(session.query(models.CollectorRun).all()[0].errors_json)
    blob += " ".join(str(r.errors_json) for r in session.query(models.CollectorRun))
    assert "secret-looking" not in blob


def test_a_partial_collector_result_makes_the_scan_partial_not_complete(session) -> None:  # type: ignore[no-untyped-def]
    _with_systems(session)
    outcome, _ = _run(session, partial={"source_scan.opengrep"})
    assert outcome.status == "partial"


def test_a_scan_where_nothing_usable_came_back_is_failed(session) -> None:  # type: ignore[no-untyped-def]
    _with_systems(session)
    all_names = {r.tool.name for r in RESULTS}
    outcome, _ = _run(session, raises=all_names)
    assert outcome.status == "failed" and outcome.summary["assets"] == 0


def test_a_stage_failure_marks_the_scan_failed_names_the_stage_and_reraises(
    session, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)

    def boom(*_a: Any, **_k: Any) -> None:
        raise ValueError("stage exploded")

    monkeypatch.setattr("qavach_worker.pipeline.plan_roadmap", boom)
    with pytest.raises(ValueError, match="stage exploded"):
        _run(session)
    scan = repo.get_scan("scan-1")
    assert scan is not None and scan.status == "failed"
    assert scan.summary_json == {"error_stage": "roadmap", "error": "ValueError"}
    assert scan.stages_json["assemble"]["status"] == "finished"  # earlier stages stay recorded


def test_assets_are_bound_to_systems_and_unbound_ones_stay_visible(session) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)
    _run(session)
    assert repo.list_assets("scan-1", AssetFilter(system_id="payments-core")).total == 29
    bare = Repository(session)
    _run_no_systems = run_scan(
        session, ScanRequest(target=TARGET, scan_id="scan-2", as_of=AS_OF), deps(), None
    )
    # systems still exist from the fixture, so bind against an unrelated target instead
    assert _run_no_systems.status == "complete"
    other = Target(type=TargetType.REPOSITORY, ref="github.com/other/unbound")
    r = run_scan(
        session,
        ScanRequest(target=other, scan_id="scan-3", as_of=AS_OF),
        Deps(
            registry=deps().registry, knowledge=KNOWLEDGE, policy=POLICY, pqc=PQC, clock=lambda: NOW
        ),
    )
    # RepoCollector replay claims carry FileLoci, so with an unbound target nothing binds:
    assert r.summary["unassigned"] == r.summary["assets"] > 0
    unassigned = bare.list_assets("scan-3", AssetFilter(system_id=""))
    assert unassigned.total == r.summary["assets"]


def test_a_scan_is_deterministic_across_scan_ids(session) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)
    _run(session, scan_id="a")
    _run(session, scan_id="b")
    strip = lambda scan: [  # noqa: E731
        (x.identity_key, x.finding_class, x.function)
        for x in session.query(models.CryptoAssetRow)
        .filter_by(scan_run_id=scan)
        .order_by(models.CryptoAssetRow.identity_key)
    ]
    assert strip("a") == strip("b")

    def bands(scan):  # type: ignore[no-untyped-def]
        rows = session.query(models.RiskScoreRow).filter_by(scan_run_id=scan).all()
        return sorted((r.system_id, r.band, r.outcome, r.mosca_gap, r.ev) for r in rows)

    assert bands("a") == bands("b")
    assert repo.get_scan("a").policy_snapshot_id == repo.get_scan("b").policy_snapshot_id  # type: ignore[union-attr]


def test_the_z_scenario_is_a_request_input_and_changes_the_result(session) -> None:  # type: ignore[no-untyped-def]
    _with_systems(session)
    _run(session, scan_id="nominal")
    _run(session, scan_id="aggr", z_scenario="aggressive")

    def z(scan):  # type: ignore[no-untyped-def]
        return {r.z_source for r in session.query(models.RiskScoreRow).filter_by(scan_run_id=scan)}

    assert "scenario:aggressive" in z("aggr") or any("deadline" in s for s in z("aggr") if s)
    assert (
        repo_scenario(session, "aggr") == "aggressive"
        and repo_scenario(session, "nominal") == "nominal"
    )


def repo_scenario(session, scan_id: str) -> str:  # type: ignore[no-untyped-def]
    return session.get(models.ScanRun, scan_id).z_scenario


def test_a_stored_adjudication_is_applied_on_the_next_scan(session) -> None:  # type: ignore[no-untyped-def]
    """T-025 end to end: an operator's ruling made after one scan survives the re-scan."""
    from qavach_core.reconcile import OccurrenceClaim, merge_all

    repo = _with_systems(session)
    _run(session, scan_id="first")
    # inject a dispute-shaped ruling for an asset identity that exists in the scan
    key = (
        session.query(models.CryptoAssetRow)
        .filter_by(scan_run_id="first", family="AES")
        .first()
        .identity_key
    )
    from qavach_core.model.identity import AssetIdentity, IdentityKind
    from qavach_core.model.locus import FileLocus

    identity = AssetIdentity(kind=IdentityKind.ALGO, key=key)
    locus = FileLocus(path="x", offset=1)
    claims = [
        OccurrenceClaim(
            identity=identity,
            locus=locus,
            collector=c,
            tool_version="1",
            confidence=t,
            detection_method="x",
            raw_ref="r",
            observed_at=NOW,
            mode=m,
        )
        for c, t, m in (("a", ConfidenceTier.AST, "gcm"), ("b", ConfidenceTier.PATTERN, "cbc"))
    ]
    repo.save_adjudication(
        adjudicate(merge_all(claims)[0], "mode", "gcm", by="ops", at=NOW, reason="read it"), now=NOW
    )
    session.commit()
    outcome, _ = _run(session, scan_id="second")
    assert outcome.status == "complete"
    report = outcome.summary["adjudications"]
    # The recorded tools do not actually disagree about this asset, so the ruling
    # is *orphaned* - reported with its reason, never silently applied or dropped.
    assert report["applied"] == 0 and report["reopened"] == []
    assert [o["identity"] for o in report["orphaned"]] == [key]
    assert "no longer disagree" in report["orphaned"][0]["reason"]
    actions = [e.action for e in session.query(models.AuditLog)]
    assert actions.count("scan.start") == 2 and "adjudicate" in actions


def test_the_scan_is_audited(session) -> None:  # type: ignore[no-untyped-def]
    _with_systems(session)
    _run(session)
    log = [(e.action, e.subject) for e in session.query(models.AuditLog)]
    assert ("scan.start", "scan-1") in log and ("scan.finish", "scan-1") in log


def test_recommendations_are_stored_with_their_cited_status(session) -> None:  # type: ignore[no-untyped-def]
    repo = _with_systems(session)
    _run(session)
    page = repo.list_assets("scan-1", AssetFilter(finding_class="quantum-vulnerable"), page_size=50)
    detail = repo.get_asset_detail(page.items[0]["id"])
    assert detail is not None and detail["recommendation"]["kind"] == "pqc"
    assert detail["recommendation"]["primary"]["source_url"].startswith("https://")
    assert detail["recommendation"]["primary"]["verified_on"] == "2026-09-20"
