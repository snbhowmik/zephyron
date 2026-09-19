"""The FastAPI surface (`ARCH.md §12`). T-073, T-074.

**Transport only - zero business logic in route handlers.** Every handler
validates its input, calls the repository, the pipeline or a pure function in
`qavach_core`, and shapes the response. Scoring, reconciliation, classification
and export all live in `packages/core`; this file decides none of it.

Notes on what is and is not here (also in `NOTE.md`):

* Authentication is optional (`QAVACH_API_TOKEN`, `qavach_api.auth`); without it
  the API must be bound to localhost or sit behind an authenticating proxy.
* Scans run through an injected `ScanRunner`. The default runs the pipeline on a
  thread pool (fine for one host); production wraps the same `run_scan` in RQ.
* `GET .../export/report.pdf` and `.../register.xlsx` render the stored register
  (T-094, T-095); they add no analysis of their own.
* Agent enrolment/spec/results endpoints live in `agent_routes` (T-073a).
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from qavach_collectors import Target, TargetType
from qavach_core.context import parse_system_rows, parse_systems_csv
from qavach_core.export import (
    assemble_register,
    bom_ref,
    build_cbom,
    build_sarif_from_entries,
    downgrade_to_1_6,
    evaluate_fail_on_entries,
)
from qavach_core.pipeline import diff_entries
from qavach_core.policy import PolicyError
from qavach_storage import AssetFilter, Repository, models
from qavach_worker import Deps, ProgressEvent, ScanRequest, run_scan, simulate
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from qavach_api.agent_ca import AgentCA
from qavach_api.agent_routes import ReplayGuard, register_agent_routes
from qavach_api.auth import websocket_subprotocol
from qavach_api.reports import build_pdf, build_xlsx

API_PREFIX = "/api/v1"


class ProgressHub:
    """Per-scan progress history with replay, so a client that connects after
    the scan started still sees every event. Thread-safe: workers publish from
    pool threads, WebSocket handlers read on the event loop."""

    def __init__(self) -> None:
        self._events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._done: set[str] = set()
        self._lock = threading.Lock()

    def publish(self, event: ProgressEvent) -> None:
        with self._lock:
            self._events[event.scan_id].append(
                {
                    "stage": event.stage,
                    "status": event.status,
                    "collector": event.collector,
                    "detail": event.detail,
                }
            )
            if event.stage == "scan":
                self._done.add(event.scan_id)

    def snapshot(self, scan_id: str, start: int) -> tuple[list[dict[str, Any]], bool]:
        with self._lock:
            return list(self._events[scan_id][start:]), scan_id in self._done

    def finish(self, scan_id: str) -> None:
        with self._lock:
            self._done.add(scan_id)


ScanRunner = Callable[[Callable[[], None]], None]


def threaded_runner(workers: int = 2) -> ScanRunner:
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="qavach-scan")
    return lambda job: pool.submit(job).add_done_callback(lambda _f: None)


@dataclass(slots=True)
class AppState:
    session_factory: sessionmaker[Session]
    deps: Deps
    hub: ProgressHub = field(default_factory=ProgressHub)
    runner: ScanRunner = field(default_factory=threaded_runner)
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)  # noqa: E731
    agent_ca: Callable[[], AgentCA] | None = None
    """Lazily builds the agent CA (`None`: agent enrolment not configured)."""
    replay_guard: ReplayGuard = field(default_factory=ReplayGuard)


class ScanBody(BaseModel):
    target_type: str = Field(
        description="repository | container-image | network-endpoint | host | ..."
    )
    target_ref: str = Field(min_length=1)
    z_scenario: str | None = None
    as_of: date | None = None
    capacity_per_quarter: int | None = Field(default=None, ge=1)
    options: dict[str, str] = Field(default_factory=dict)


class SuppressBody(BaseModel):
    reason: str = Field(min_length=1)
    author: str = Field(min_length=1)
    days: int = Field(default=30, ge=1, le=365)


class AdjudicateBody(BaseModel):
    attribute: str
    value: str
    by: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class SimulateBody(BaseModel):
    scan_id: str
    overrides: dict[str, Any] = Field(default_factory=dict)
    z_scenario: str | None = None


def get_state(request: Request) -> AppState:
    return request.app.state.qavach  # type: ignore[no-any-return]


StateDep = Annotated[AppState, Depends(get_state)]


def get_repo(st: StateDep) -> Iterator[Repository]:
    with st.session_factory() as session:
        yield Repository(session)


RepoDep = Annotated[Repository, Depends(get_repo)]


def create_app(state: AppState) -> FastAPI:
    app = FastAPI(title="QAVACH", version="0.1.0")
    app.state.qavach = state
    register_agent_routes(app, API_PREFIX)

    def scan_or_404(repo: Repository, scan_id: str) -> models.ScanRun:
        scan = repo.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, f"scan {scan_id!r} not found")
        return scan

    # ---- scans ------------------------------------------------------------

    @app.post(f"{API_PREFIX}/scans", status_code=202)
    def start_scan(body: ScanBody, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        try:
            target_type = TargetType(body.target_type)
        except ValueError as exc:
            raise HTTPException(422, f"unknown target_type {body.target_type!r}") from exc
        scenario = body.z_scenario or str(st.deps.policy.value("z_scenarios.default"))
        try:
            st.deps.policy.node(f"z_scenarios.scenarios.{scenario}")
        except PolicyError as exc:
            raise HTTPException(422, f"unknown Z scenario {scenario!r}") from exc
        scan_id = str(uuid.uuid4())
        now = st.clock()
        as_of = body.as_of or now.date()
        repo.create_scan(
            scan_id=scan_id,
            target_ref=body.target_ref,
            policy=st.deps.policy,
            z_scenario=scenario,
            as_of=as_of.isoformat(),
            now=now,
        )
        repo.s.commit()
        request = ScanRequest(
            target=Target(type=target_type, ref=body.target_ref, options=body.options),
            scan_id=scan_id,
            z_scenario=scenario,
            as_of=as_of,
            capacity_per_quarter=body.capacity_per_quarter,
            actor="api",
        )

        def job() -> None:
            with st.session_factory() as session:
                try:
                    run_scan(session, request, st.deps, st.hub.publish)
                except Exception:  # noqa: BLE001 - recorded on the scan by run_scan
                    st.hub.finish(scan_id)

        st.runner(job)
        return {"scan_id": scan_id, "status": "queued"}

    @app.get(f"{API_PREFIX}/scans")
    def list_scans(
        repo: RepoDep, limit: int = Query(default=50, ge=1, le=200)
    ) -> list[dict[str, Any]]:
        rows = repo.s.scalars(
            select(models.ScanRun).order_by(models.ScanRun.started.desc()).limit(limit)
        )
        return [
            {
                "id": r.id,
                "target_ref": r.target_ref,
                "status": r.status,
                "started": r.started.isoformat(),
                "finished": r.finished.isoformat() if r.finished else None,
                "z_scenario": r.z_scenario,
                "assets": (r.summary_json or {}).get("assets"),
            }
            for r in rows
        ]

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}")
    def get_scan(scan_id: str, repo: RepoDep) -> dict[str, Any]:
        scan = scan_or_404(repo, scan_id)
        return {
            "id": scan.id,
            "target_ref": scan.target_ref,
            "status": scan.status,
            "started": scan.started.isoformat(),
            "finished": scan.finished.isoformat() if scan.finished else None,
            "z_scenario": scan.z_scenario,
            "as_of": scan.as_of,
            "policy_snapshot_id": scan.policy_snapshot_id,
            "stages": scan.stages_json or {},
            "summary": {k: v for k, v in (scan.summary_json or {}).items() if k != "roadmap"},
            "collectors": [
                {
                    "collector": c.collector,
                    "tool_version": c.tool_version,
                    "partial": c.partial,
                    "exit_code": c.exit_code,
                    "errors": c.errors_json or [],
                }
                for c in repo.collector_runs(scan_id)
            ],
        }

    @app.websocket(f"{API_PREFIX}/scans/{{scan_id}}/progress")
    async def progress(ws: WebSocket, scan_id: str) -> None:
        st: AppState = ws.app.state.qavach
        with st.session_factory() as session:
            if Repository(session).get_scan(scan_id) is None:
                await ws.close(code=4404)
                return
        await ws.accept(subprotocol=websocket_subprotocol(ws.scope))
        sent = 0
        try:
            for _ in range(60 * 20):  # bounded: 60 s at 50 ms
                events, done = st.hub.snapshot(scan_id, sent)
                for e in events:
                    await ws.send_json(e)
                sent += len(events)
                if done and not events:
                    break
                with st.session_factory() as session:
                    scan = Repository(session).get_scan(scan_id)
                    if scan and scan.status in {"complete", "partial", "failed"} and not events:
                        st.hub.finish(scan_id)
                await asyncio.sleep(0.05)
            await ws.send_json(
                {"stage": "scan", "status": "closed", "collector": None, "detail": None}
            )
        finally:
            try:
                await ws.close()
            except RuntimeError:
                pass

    # ---- inventory --------------------------------------------------------

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/assets")
    def list_assets(
        scan_id: str,
        repo: RepoDep,
        finding_class: str | None = None,
        migration_authority: str | None = None,
        band: str | None = None,
        outcome: str | None = None,
        system_id: str | None = Query(default=None, description='"" selects unassigned'),
        disputed: bool | None = None,
        family: str | None = None,
        q: str | None = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=500),
    ) -> dict[str, Any]:
        scan_or_404(repo, scan_id)
        result = repo.list_assets(
            scan_id,
            AssetFilter(
                finding_class=finding_class,
                migration_authority=migration_authority,
                band=band,
                outcome=outcome,
                system_id=system_id,
                disputed=disputed,
                family=family,
                text=q,
            ),
            page=page,
            page_size=page_size,
        )
        return {
            "items": result.items,
            "total": result.total,
            "page": result.page,
            "page_size": result.page_size,
            "facets": result.facets,
        }

    @app.get(f"{API_PREFIX}/assets/{{asset_id}}")
    def get_asset(asset_id: str, repo: RepoDep) -> dict[str, Any]:
        detail = repo.get_asset_detail(asset_id)
        if detail is None:
            raise HTTPException(404, f"asset {asset_id!r} not found")
        return detail

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/roadmap")
    def get_roadmap(scan_id: str, repo: RepoDep) -> dict[str, Any]:
        scan = scan_or_404(repo, scan_id)
        units = repo.s.scalars(
            select(models.MigrationUnitRow).where(models.MigrationUnitRow.scan_run_id == scan_id)
        ).all()
        edges = repo.s.scalars(
            select(models.MigrationEdgeRow).where(models.MigrationEdgeRow.scan_run_id == scan_id)
        ).all()
        return {
            "roadmap": (scan.summary_json or {}).get("roadmap"),
            "units": [
                {
                    "id": u.id,
                    "system_id": u.system_id,
                    "function": u.function,
                    "wave": u.wave,
                    "target_quarter": u.target_quarter,
                    "feasible": u.feasible,
                    "schedule_risk": u.schedule_risk,
                }
                for u in sorted(units, key=lambda x: x.id)
            ],
            "edges": [{"from": e.from_unit_id, "to": e.to_unit_id, "kind": e.kind} for e in edges],
        }

    # ---- export -----------------------------------------------------------

    def scoped_assets(repo: Repository, scan_id: str, scope: str, system_id: str | None):  # type: ignore[no-untyped-def]
        assets = repo.load_assets(scan_id)
        if scope == "root":
            return assets, None
        if scope == "system":
            if not system_id:
                raise HTTPException(422, "scope=system needs system_id")
            bound = {
                a.asset_id
                for a in repo.s.scalars(
                    select(models.AssetSystem).where(models.AssetSystem.system_id == system_id)
                )
            }
            from qavach_storage import asset_id_for

            return [a for a in assets if asset_id_for(scan_id, a.identity.key) in bound], system_id
        if scope == "component":
            return assets, None
        raise HTTPException(422, f"unknown scope {scope!r}")

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/export/cbom")
    def export_cbom(
        scan_id: str,
        st: StateDep,
        repo: RepoDep,
        spec: str = Query(default="1.7", pattern="^1\\.[67]$"),
        scope: str = "root",
        system_id: str | None = None,
    ) -> Response:
        scan = scan_or_404(repo, scan_id)
        assets, _ = scoped_assets(repo, scan_id, scope, system_id)
        families = frozenset(st.deps.knowledge.registry.families)
        cbom = build_cbom(
            assets,
            timestamp=scan.started,
            qavach_version="0.1.0",
            scope=scope,
            known_families=families,
        )
        if spec == "1.6":
            cbom, _losses = downgrade_to_1_6(cbom)
        return JSONResponse(cbom, media_type="application/vnd.cyclonedx+json")

    def register_doc(
        st: AppState, repo: Repository, scan_id: str, scope: str, system_id: str | None
    ) -> dict[str, Any]:
        scan = scan_or_404(repo, scan_id)
        assets, sid = scoped_assets(repo, scan_id, scope, system_id)
        families = frozenset(st.deps.knowledge.registry.families)
        cbom = build_cbom(
            assets,
            timestamp=scan.started,
            qavach_version="0.1.0",
            scope=scope,
            known_families=families,
        )
        refs = {c["bom-ref"] for c in cbom["components"]}
        entries = [
            e
            for e in repo.score_entries(scan_id)
            if e["bom_ref"] in refs and (sid is None or e["system_id"] == sid)
        ]
        return assemble_register(
            entries,
            roadmap_doc=(scan.summary_json or {}).get("roadmap"),
            cbom=cbom,
            policy_snapshot_id=scan.policy_snapshot_id,
            z_scenario=scan.z_scenario,
            as_of=date.fromisoformat(scan.as_of),
            generated_at=scan.started,
        )

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/export/risk-register")
    def export_register(
        scan_id: str, st: StateDep, repo: RepoDep, scope: str = "root", system_id: str | None = None
    ) -> dict[str, Any]:
        return register_doc(st, repo, scan_id, scope, system_id)

    def rendered(
        st: AppState, repo: Repository, scan_id: str, scope: str, system_id: str | None
    ) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
        """The register plus what a *rendering* of it needs: readable algorithm
        names and the scan header. No analysis is added here."""
        register = register_doc(st, repo, scan_id, scope, system_id)
        scan = scan_or_404(repo, scan_id)
        labels = {}
        for a in repo.load_assets(scan_id):
            detail = a.curve or a.parameter_set
            labels[bom_ref(a.identity)] = a.algorithm_family + (f"-{detail}" if detail else "")
        return register, labels, {"id": scan.id, "target_ref": scan.target_ref}

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/export/register.xlsx")
    def export_xlsx(
        scan_id: str, st: StateDep, repo: RepoDep, scope: str = "root", system_id: str | None = None
    ) -> Response:
        register, labels, scan = rendered(st, repo, scan_id, scope, system_id)
        return Response(
            build_xlsx(register, labels, scan),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"content-disposition": f'attachment; filename="{scan_id}.register.xlsx"'},
        )

    @app.get(f"{API_PREFIX}/scans/{{before_id}}/diff/{{after_id}}")
    def scan_diff(before_id: str, after_id: str, repo: RepoDep) -> dict[str, Any]:
        """What changed between two scans (T-109). Also says *why the comparison
        may mislead* - a different policy, date, Z scenario or collector set moves
        scores and coverage without the estate changing - rather than presenting a
        raw diff as drift."""
        before, after = scan_or_404(repo, before_id), scan_or_404(repo, after_id)

        def labels(scan_id: str) -> dict[str, str]:
            out = {}
            for a in repo.load_assets(scan_id):
                detail = a.curve or a.parameter_set
                out[bom_ref(a.identity)] = a.algorithm_family + (f"-{detail}" if detail else "")
            return out

        names = labels(before_id) | labels(after_id)

        def ran(scan_id: str) -> dict[str, bool]:
            return {c.collector: not c.partial for c in repo.collector_runs(scan_id)}

        ran_before, ran_after = ran(before_id), ran(after_id)
        drift = diff_entries(repo.score_entries(before_id), repo.score_entries(after_id))

        def row(e: Any) -> dict[str, Any]:
            return {
                "bom_ref": e["bom_ref"],
                "label": names.get(e["bom_ref"], e["bom_ref"]),
                "system_id": e.get("system_id"),
                "finding_class": e["finding_class"],
                "band": e["band"],
            }

        caveats = []
        if before.policy_snapshot_id != after.policy_snapshot_id:
            caveats.append(
                "the policy snapshot differs: score changes may be policy, not the estate"
            )
        if before.z_scenario != after.z_scenario:
            caveats.append("the Z scenario differs")
        if before.as_of != after.as_of:
            caveats.append("the as-of date differs: bands move as deadlines approach")
        if ran_before != ran_after:
            caveats.append(
                "the collector set (or which collectors completed) differs: assets can "
                "appear or vanish because of coverage, not because the estate changed"
            )
        return {
            "before": before_id,
            "after": after_id,
            "summary": drift.summary(),
            "added": [row(e) for e in drift.added],
            "removed": [row(e) for e in drift.removed],
            "changed": [
                {
                    "bom_ref": c.bom_ref,
                    "label": names.get(c.bom_ref, c.bom_ref),
                    "system_id": c.system_id or None,
                    "direction": c.direction,
                    "fields": {k: list(v) for k, v in c.fields.items()},
                }
                for c in drift.changed
            ],
            "caveats": caveats,
        }

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/export/sarif")
    def export_sarif(scan_id: str, repo: RepoDep) -> dict[str, Any]:
        """SARIF 2.1.0 from the stored register entries (T-096); same document the
        in-memory path builds. Informational classes produce no result."""
        scan_or_404(repo, scan_id)
        return build_sarif_from_entries(
            repo.score_entries(scan_id), repo.load_assets(scan_id), qavach_version="0.1.0"
        )

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/gate")
    def gate(scan_id: str, repo: RepoDep, fail_on: str = Query(min_length=1)) -> dict[str, Any]:
        """CI gate: `fail_on` is a comma-separated list of finding classes and/or
        bands. An unknown token is a 422, never a silent pass."""
        scan_or_404(repo, scan_id)
        tokens = [t.strip() for t in fail_on.split(",") if t.strip()]
        try:
            failed, reasons = evaluate_fail_on_entries(repo.score_entries(scan_id), tokens)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"fail": failed, "fail_on": tokens, "reasons": reasons}

    @app.get(f"{API_PREFIX}/scans/{{scan_id}}/export/report.pdf")
    def export_pdf(
        scan_id: str, st: StateDep, repo: RepoDep, scope: str = "root", system_id: str | None = None
    ) -> Response:
        register, labels, scan = rendered(st, repo, scan_id, scope, system_id)
        return Response(
            build_pdf(register, labels, scan),
            media_type="application/pdf",
            headers={"content-disposition": f'attachment; filename="{scan_id}.report.pdf"'},
        )

    # ---- systems & policy -------------------------------------------------

    @app.post(f"{API_PREFIX}/systems/import")
    async def import_systems(
        request: Request,
        st: StateDep,
        repo: RepoDep,
        content: Annotated[str, Body(media_type="text/plain")],
    ) -> dict[str, Any]:
        ctype = request.headers.get("content-type", "")
        if "yaml" in ctype:
            import yaml

            try:
                rows = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                raise HTTPException(422, "invalid YAML") from exc
            if isinstance(rows, dict):
                rows = rows.get("systems", [])
            if not isinstance(rows, list):
                raise HTTPException(422, "YAML must be a list of systems or {systems: [...]}")
            imported = parse_system_rows(rows, st.deps.policy)
        else:
            imported = parse_systems_csv(content, st.deps.policy)
        if imported.systems:
            repo.replace_systems(imported)
            repo.audit("api", "systems.import", f"{len(imported.systems)} systems", now=st.clock())
            repo.s.commit()
        return {
            "imported": len(imported.systems),
            "ok": imported.ok,
            "issues": [
                {"row": i.row, "field": i.field, "message": i.message, "severity": i.severity}
                for i in imported.issues
            ],
        }

    @app.get(f"{API_PREFIX}/systems")
    def list_systems(repo: RepoDep) -> list[dict[str, Any]]:
        systems, bindings = repo.load_systems()
        return [
            {
                "id": s.id,
                "name": s.name,
                "owner": s.owner,
                "criticality": s.criticality,
                "data_classification": s.data_classification.value,
                "retention_years": s.retention_years,
                "retention_inferred": s.retention_inferred,
                "internet_facing": s.internet_facing,
                "regulatory_regimes": sorted(s.regulatory_regimes),
                "depends_on": sorted(s.depends_on),
                "bindings": bindings[s.id],
            }
            for s in systems
        ]

    @app.get(f"{API_PREFIX}/policy")
    def get_policy(st: StateDep) -> dict[str, Any]:
        """Active policy with every value's citation (FR-360)."""
        return {
            "snapshot_id": st.deps.policy.snapshot_id,
            "nodes": [
                {"path": n.path, "fields": dict(n.fields), "basis": n.basis}
                for n in st.deps.policy.iter_nodes()
            ],
        }

    @app.post(f"{API_PREFIX}/policy/simulate")
    def simulate_policy(body: SimulateBody, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        """Re-score a stored scan against a candidate policy: pure recomputation,
        nothing written, no re-scan."""
        scan_or_404(repo, body.scan_id)
        try:
            return simulate(
                repo.s,
                body.scan_id,
                overrides=body.overrides,
                z_scenario=body.z_scenario,
                knowledge=st.deps.knowledge,
            )
        except PolicyError as exc:
            raise HTTPException(422, str(exc)) from exc

    # ---- mutations --------------------------------------------------------

    @app.post(f"{API_PREFIX}/assets/{{asset_id}}/suppress")
    def suppress(asset_id: str, body: SuppressBody, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        row = repo.s.get(models.CryptoAssetRow, asset_id)
        if row is None:
            raise HTTPException(404, f"asset {asset_id!r} not found")
        now = st.clock()
        try:
            sid = repo.suppress(
                row.identity_key,
                reason=body.reason,
                author=body.author,
                now=now,
                expires_at=now + timedelta(days=body.days),
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        repo.s.commit()
        return {
            "suppression_id": sid,
            "asset_id": asset_id,
            "expires_at": (now + timedelta(days=body.days)).isoformat(),
        }

    @app.post(f"{API_PREFIX}/assets/{{asset_id}}/adjudicate")
    def adjudicate_asset(
        asset_id: str, body: AdjudicateBody, st: StateDep, repo: RepoDep
    ) -> dict[str, Any]:
        row = repo.s.get(models.CryptoAssetRow, asset_id)
        if row is None:
            raise HTTPException(404, f"asset {asset_id!r} not found")
        dispute = next(
            (
                d
                for d in row.disputes_json
                if d["attribute"] == body.attribute and not d.get("adjudicated_value")
            ),
            None,
        )
        if dispute is None:
            raise HTTPException(422, f"{body.attribute!r} has no unresolved dispute on this asset")
        from qavach_core.model.identity import AssetIdentity, IdentityKind
        from qavach_core.reconcile import Adjudication

        values = frozenset(c["value"] for c in dispute["claims"] if c["value"] is not None)
        try:
            ruling = Adjudication(
                identity=AssetIdentity(kind=IdentityKind(row.identity_kind), key=row.identity_key),
                attribute=body.attribute,
                value=body.value,
                reviewed_values=values,
                adjudicated_by=body.by,
                adjudicated_at=st.clock(),
                reason=body.reason,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        aid = repo.save_adjudication(ruling, now=st.clock())
        repo.s.commit()
        return {
            "adjudication_id": aid,
            "applies_from": "the next scan (the ruling is keyed by asset identity)",
        }

    @app.exception_handler(KeyError)
    async def key_error(_request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse({"detail": f"not found: {exc.args[0]!r}"}, status_code=404)

    return app
