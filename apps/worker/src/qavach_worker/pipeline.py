"""The scan pipeline. T-072: collect -> assemble -> context -> risk -> recommend
-> roadmap -> persist.

`run_scan` is a plain synchronous function (collectors are blocking subprocess
calls, so async buys nothing - CLAUDE.md §4); RQ only wraps it (`jobs.py`).
Everything it needs is passed in, and every score is computed against the
scan's own **policy snapshot** (T-068), never live files.

Failure isolation is the design point:

* a collector that raises, or returns `partial`, is recorded as such and the
  scan continues with what the others found - one broken scanner never loses
  the estate;
* a scan is `complete` only if every collector finished cleanly, `partial` if
  any degraded but something was found, and `failed` only if nothing usable came
  back. A partial scan says so in its status, in `collector_runs` and in its
  summary - it is never presented as complete;
* a stage that raises marks the scan `failed` with the stage named, and the
  stages already finished stay recorded.

Progress is emitted through a callback (the API forwards it to the WebSocket,
T-074): `started`/`finished`/`failed` per stage and per collector.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from qavach_collectors import CollectorRegistry, RunContext, Target, TargetType
from qavach_core.context import (
    BindingKey,
    SystemBindings,
    bind_assets,
    keys_for_locus,
)
from qavach_core.export import RegisterInput, register_entry, roadmap_document
from qavach_core.pipeline import (
    AssembleKnowledge,
    ClaimInput,
    also_quantum_vulnerable_of,
    artefact_lifetime_of,
    assemble,
    plan_roadmap,
)
from qavach_core.policy import PolicySnapshot
from qavach_core.recommend import Constraints, PqcKnowledge, recommend
from qavach_core.risk import AssetRiskInput, score_asset
from qavach_core.roadmap import MigrationUnit, Roadmap
from qavach_storage import Repository
from sqlalchemy.orm import Session

from qavach_worker.workspace import Checkout, CloneError, Workspace, redact_url

STAGES = ("collect", "assemble", "context", "risk", "recommend", "roadmap", "persist")

_TARGET_KEY_KIND = {
    TargetType.REPOSITORY: "repo",
    TargetType.CONTAINER_IMAGE: "image",
    TargetType.NETWORK_ENDPOINT: "endpoint",
    TargetType.CLOUD_ACCOUNT: "cloud_account",
    TargetType.HOST: "host",
}


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    scan_id: str
    stage: str
    status: str
    """`started`, `finished` or `failed`."""
    collector: str | None = None
    detail: str | None = None


ProgressFn = Callable[[ProgressEvent], None]


@dataclass(frozen=True, slots=True)
class ScanRequest:
    target: Target
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    z_scenario: str | None = None
    as_of: date | None = None
    capacity_per_quarter: int | None = None
    actor: str = "system"
    allow_build_resolution: bool = False
    """SECURITY.md §3.1: let cdxgen run the target's build (network on). Off by default."""


@dataclass(frozen=True, slots=True)
class Deps:
    registry: CollectorRegistry
    knowledge: AssembleKnowledge
    policy: PolicySnapshot
    pqc: PqcKnowledge
    clock: Callable[[], datetime]
    workspace: Workspace | None = None


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    scan_id: str
    status: str
    summary: dict[str, Any]


def _error_text(exc: Exception) -> str:
    """What the operator sees. A clone failure carries a useful, already-redacted
    message; anything else is the exception type only (never its text, which could
    hold a path or a secret)."""
    return f"CloneError: {exc}" if isinstance(exc, CloneError) else type(exc).__name__


def binding_key_for(target: Target) -> BindingKey | None:
    kind = _TARGET_KEY_KIND.get(target.type)
    return BindingKey(kind, target.ref) if kind else None


def _bindings(raw: dict[str, Any]) -> SystemBindings:
    return SystemBindings(
        repos=frozenset(raw.get("repos", [])),
        images=frozenset(raw.get("images", [])),
        endpoints=frozenset(raw.get("endpoints", [])),
        cloud_accounts=frozenset(raw.get("cloud_accounts", [])),
        hosts=frozenset(raw.get("hosts", [])),
    )


def _adjudication_report(outcome: Any) -> dict[str, Any]:
    """What happened to each stored operator ruling on this re-merge: an
    operator must be able to see that a ruling stopped applying, and why."""
    if outcome is None:
        return {"applied": 0, "reopened": [], "orphaned": [], "superseded": 0}
    return {
        "applied": len(outcome.applied),
        "reopened": [
            {"identity": u.adjudication.identity.key, "reason": u.reason} for u in outcome.reopened
        ],
        "orphaned": [
            {"identity": u.adjudication.identity.key, "reason": u.reason} for u in outcome.orphaned
        ],
        "superseded": len(outcome.superseded),
    }


def _unit_row(unit: MigrationUnit, roadmap: Roadmap) -> dict[str, Any]:
    scheduled = roadmap.schedule.get(unit.id)
    risk = scheduled.schedule_risk if scheduled else None
    return {
        "id": unit.id,
        "system_id": unit.system_id,
        "function": unit.function.value if unit.function else "unknown",
        "wave": scheduled.wave if scheduled else None,
        "target_quarter": scheduled.target_finish if scheduled else None,
        "feasible": not scheduled.infeasible if scheduled else True,
        "schedule_risk": risk.value if risk else None,
    }


def run_scan(
    session: Session,
    request: ScanRequest,
    deps: Deps,
    progress: ProgressFn | None = None,
) -> ScanOutcome:
    repo = Repository(session)
    emit = progress or (lambda _e: None)
    now = deps.clock()
    as_of = request.as_of or now.date()
    scenario = request.z_scenario or str(deps.policy.value("z_scenarios.default"))
    scan_id = request.scan_id
    if repo.get_scan(scan_id) is None:  # the API pre-creates it so the id is pollable at once
        repo.create_scan(
            scan_id=scan_id,
            target_ref=redact_url(request.target.ref),
            policy=deps.policy,
            z_scenario=scenario,
            as_of=as_of.isoformat(),
            now=now,
        )
    repo.audit(
        request.actor,
        "scan.start",
        scan_id,
        now=now,
        detail={"target": redact_url(request.target.ref)},
    )
    if request.allow_build_resolution:
        repo.audit(
            request.actor,
            "scan.build-resolution-enabled",
            scan_id,
            now=now,
            detail={
                "warning": "the target's own build (pom.xml, package.json postinstall, "
                "build.gradle...) runs inside the sandbox WITH network access; QAVACH does not "
                "yet restrict egress to package registries (SECURITY.md §3.1)"
            },
        )
    stages: dict[str, dict[str, Any]] = {}

    def stage_started(name: str) -> float:
        stages[name] = {"status": "running", "started": deps.clock().isoformat()}
        repo.set_status(scan_id, "running", stages=stages)
        session.commit()
        emit(ProgressEvent(scan_id, name, "started"))
        return time.perf_counter()

    def stage_finished(name: str, t0: float, detail: str | None = None) -> None:
        stages[name] = {
            **stages[name],
            "status": "finished",
            "seconds": round(time.perf_counter() - t0, 4),
        }
        if detail:
            stages[name]["detail"] = detail
        repo.set_status(scan_id, "running", stages=stages)
        session.commit()
        emit(ProgressEvent(scan_id, name, "finished", detail=detail))

    current = "collect"
    checkouts: list[Checkout] = []
    try:
        # ---- collect -----------------------------------------------------------
        t0 = stage_started("collect")
        target = request.target
        if deps.workspace is not None and deps.workspace.wants(target):
            checkout = deps.workspace.clone(target.ref, scan_id)
            checkouts.append(checkout)
            target = Target(type=target.type, ref=str(checkout.path), options=target.options)
        claims: list[ClaimInput] = []
        collector_status: dict[str, str] = {}
        ctx = RunContext(scan_run_id=scan_id, allow_build_resolution=request.allow_build_resolution)
        for collector in deps.registry.for_target(target):
            emit(ProgressEvent(scan_id, "collect", "started", collector=collector.name))
            started = time.perf_counter()
            try:
                result = collector.collect(target, ctx)
            except Exception as exc:  # noqa: BLE001 - a collector must never take the scan down
                repo.add_collector_run(
                    scan_id,
                    collector=collector.name,
                    tool_version=collector.version,
                    exit_code=None,
                    partial=True,
                    errors=[{"message": f"collector raised {type(exc).__name__}", "fatal": True}],
                    duration_seconds=time.perf_counter() - started,
                )
                collector_status[collector.name] = "failed"
                emit(
                    ProgressEvent(
                        scan_id,
                        "collect",
                        "failed",
                        collector=collector.name,
                        detail=f"raised {type(exc).__name__}",
                    )
                )
                continue
            repo.add_collector_run(
                scan_id,
                collector=result.tool.name,
                tool_version=result.tool.version,
                exit_code=result.tool.exit_code,
                partial=result.partial,
                errors=[{"message": e.message, "fatal": e.fatal} for e in result.errors],
                duration_seconds=result.tool.duration_seconds,
            )
            collector_status[result.tool.name] = "partial" if result.partial else "ok"
            for raw in result.claims:
                claims.append(
                    ClaimInput(
                        name=raw.name,
                        oid=raw.oid,
                        primitive=raw.primitive,
                        parameter_set=raw.parameter_set,
                        mode=raw.mode,
                        padding=raw.padding,
                        certificate=raw.certificate,
                        locus=raw.locus,
                        collector=result.tool.name,
                        tool_version=result.tool.version,
                        confidence=raw.confidence,
                        detection_method=raw.detection_method,
                        raw_ref=f"{result.tool.name}:{scan_id}",
                        observed_at=deps.clock(),
                    )
                )
            emit(
                ProgressEvent(
                    scan_id,
                    "collect",
                    "failed" if result.partial else "finished",
                    collector=result.tool.name,
                    detail=f"{len(result.claims)} claims",
                )
            )
        stage_finished(
            "collect", t0, f"{len(claims)} claims from {len(collector_status)} collectors"
        )

        # ---- assemble (normalise + reconcile + adjudicate) ---------------------
        current = "assemble"
        t0 = stage_started("assemble")
        assembled = assemble(claims, deps.knowledge, adjudications=repo.load_adjudications())
        assets = list(assembled.assets)
        stage_finished("assemble", t0, f"{len(claims)} claims -> {len(assets)} assets")

        # ---- context -----------------------------------------------------------
        current = "context"
        t0 = stage_started("context")
        systems, raw_bindings = repo.load_systems()
        system_by_id = {s.id: s for s in systems}
        target_key = binding_key_for(request.target)  # the URL, not the temp checkout
        binding = bind_assets(
            {
                a.identity: [
                    k
                    for o in a.occurrences
                    for k in keys_for_locus(o.locus, scan_target=target_key)
                ]
                for a in assets
            },
            {sid: _bindings(b) for sid, b in raw_bindings.items()},
        )
        stage_finished(
            "context",
            t0,
            f"{len(assets) - len(binding.unassigned)} bound, {len(binding.unassigned)} unassigned",
        )

        # ---- risk + recommend --------------------------------------------------
        current = "risk"
        t0 = stage_started("risk")
        items: list[RegisterInput] = []
        for asset in assets:
            aq = also_quantum_vulnerable_of(asset, deps.knowledge)
            for system_id in binding.systems_for(asset.identity) or (None,):
                system = system_by_id.get(system_id) if system_id else None
                score = score_asset(
                    AssetRiskInput(
                        identity=asset.identity,
                        finding_class=asset.finding_class,
                        also_quantum_vulnerable=aq,
                        function=asset.function,
                        authority=asset.migration_authority,
                        loci=tuple(o.locus for o in asset.occurrences),
                        system=system,
                        artefact_lifetime_years=artefact_lifetime_of(asset, as_of),
                    ),
                    policy=deps.policy,
                    as_of=as_of,
                    scenario=scenario,
                )
                rec = recommend(
                    finding_class=asset.finding_class,
                    also_quantum_vulnerable=aq,
                    function=asset.function,
                    algorithm_family=asset.algorithm_family,
                    knowledge=deps.pqc,
                    constraints=Constraints(
                        regimes=system.regulatory_regimes if system else frozenset()
                    ),
                )
                items.append(RegisterInput(asset=asset, score=score, recommendation=rec))
        stage_finished("risk", t0, f"{len(items)} (asset, system) scores")

        current = "recommend"
        t0 = stage_started("recommend")
        stage_finished("recommend", t0)

        # ---- roadmap -----------------------------------------------------------
        current = "roadmap"
        t0 = stage_started("roadmap")
        roadmap, units, edges = plan_roadmap(
            items, systems, as_of=as_of, capacity_per_quarter=request.capacity_per_quarter
        )
        stage_finished("roadmap", t0, f"{len(roadmap.waves)} waves, {len(roadmap.bridges)} bridges")

        # ---- persist -----------------------------------------------------------
        current = "persist"
        t0 = stage_started("persist")
        ids = repo.save_assets(scan_id, assets)
        repo.link_occurrences_to_runs(scan_id)
        repo.save_scores(
            scan_id,
            deps.policy.snapshot_id,
            [
                (ids[i.asset.identity.key], i.score.system_id, register_entry(i, roadmap))
                for i in items
            ],
        )
        repo.save_bindings(
            [
                (ids[a.identity.key], m.system_id, m.basis)
                for a in assets
                for m in binding.matches.get(a.identity, ())
            ]
        )
        seen: set[str] = set()
        for i in items:
            key = i.asset.identity.key
            if key in seen or i.recommendation is None:
                continue
            seen.add(key)
            rec = i.recommendation
            repo.save_recommendation(
                ids[key],
                kind=rec.kind,
                target=rec.primary.name if rec.primary else None,
                rationale={
                    "reason": rec.reason,
                    "primary": None
                    if rec.primary is None
                    else {
                        "name": rec.primary.name,
                        "status_text": rec.primary.status_text,
                        "source_url": rec.primary.source_url,
                        "verified_on": rec.primary.verified_on,
                    },
                    "watch": [w.name for w in rec.watch],
                    "hybrid": [h.position for h in rec.hybrid],
                    "notes": list(rec.notes),
                    "classical_fix": rec.classical_fix,
                },
            )
        repo.save_roadmap(
            scan_id,
            [_unit_row(u, roadmap) for u in units],
            [
                {
                    "from_unit_id": e.tail,
                    "to_unit_id": e.head,
                    "kind": e.kind.value,
                    "rationale": e.note,
                }
                for e in edges
            ],
        )

        classes = Counter(a.finding_class.value for a in assets)
        degraded = [n for n, s in collector_status.items() if s != "ok"]
        if not claims and degraded:
            status = "failed"
        elif degraded:
            status = "partial"
        else:
            status = "complete"
        summary: dict[str, Any] = {
            "build_resolution": request.allow_build_resolution,
            "assets": len(assets),
            "claims": len(claims),
            "by_finding_class": dict(sorted(classes.items())),
            "collectors": collector_status,
            "degraded_collectors": sorted(degraded),
            "unresolved_names": list(assembled.unresolved),
            "adjudications": _adjudication_report(assembled.adjudications),
            "unassigned": len(binding.unassigned),
            "bridges": len(roadmap.bridges),
            "infeasible": len(roadmap.infeasible),
            "roadmap": roadmap_document(roadmap),
        }
        stage_finished("persist", t0)
        repo.set_status(scan_id, status, now=deps.clock(), stages=stages, summary=summary)
        repo.audit(
            request.actor, "scan.finish", scan_id, now=deps.clock(), detail={"status": status}
        )
        session.commit()
        emit(
            ProgressEvent(
                scan_id, "scan", "finished" if status != "failed" else "failed", detail=status
            )
        )
        return ScanOutcome(scan_id, status, summary)
    except Exception as exc:
        session.rollback()
        stages[current] = {
            **stages.get(current, {}),
            "status": "failed",
            "error": _error_text(exc),
        }
        if repo.get_scan(scan_id) is None:
            repo.create_scan(
                scan_id=scan_id,
                target_ref=redact_url(request.target.ref),
                policy=deps.policy,
                z_scenario=scenario,
                as_of=as_of.isoformat(),
                now=now,
            )
        repo.set_status(
            scan_id,
            "failed",
            now=deps.clock(),
            stages=stages,
            summary={"error_stage": current, "error": _error_text(exc)},
        )
        session.commit()
        emit(ProgressEvent(scan_id, current, "failed", detail=_error_text(exc)))
        raise
    finally:
        for checkout in checkouts:
            if deps.workspace is not None:
                deps.workspace.remove(checkout)


__all__ = [
    "STAGES",
    "Deps",
    "ProgressEvent",
    "ProgressFn",
    "ScanOutcome",
    "ScanRequest",
    "binding_key_for",
    "run_scan",
]
