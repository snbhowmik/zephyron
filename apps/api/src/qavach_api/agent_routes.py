"""Agent registry endpoints (T-073a, ARCH.md §3a and §12).

Two audiences, two kinds of authentication:

* **Operator** endpoints (issue token, list, dispatch, revoke) sit behind the
  operator bearer token like everything else.
* **Agent** endpoints (`enroll`, `spec`, `results`) are exempt from the bearer
  middleware - the agent does not have that token - and authenticate
  themselves: `enroll` by the single-use enrolment token, `spec`/`results` by a
  request signature made with the agent's enrolled key (`qavach_agent.signing`).
  They therefore enforce their own auth *always*, whether or not the operator
  token is configured, and every failure is the same 401 so nothing is an oracle.
"""

from __future__ import annotations

import dataclasses
import hashlib
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from qavach_agent.runtime import deserialize_collector_result
from qavach_agent.signing import (
    MAX_SKEW_SECONDS,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    verify_request,
)
from qavach_agent.spec import AGENT_COLLECTOR_NAMES, InvalidScanSpecError, parse_scan_spec
from qavach_collectors import CollectorRegistry, CollectorResult, RunContext, Target, TargetType
from qavach_core.model.enums import ConfidenceTier
from qavach_storage import AgentRepository, Repository, as_utc, models
from qavach_worker import ScanRequest, run_scan

from qavach_api.agent_ca import AgentCA, CsrRejected

MAX_RESULT_BYTES = 32 * 1024 * 1024
ONLINE_WITHIN_SECONDS = 120
TOKEN_PREFIX = "qat_"
_UNAUTHENTICATED = HTTPException(401, "authentication failed")


class ReplayGuard:
    """Rejects a signature seen within the skew window. In-process only: with
    several API workers a replay could land on a different one, which is why the
    residual is recorded in NOTE.md and mTLS remains the network-level control."""

    def __init__(self) -> None:
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def first_use(self, signature: str, now: float) -> bool:
        with self._lock:
            while self._seen and next(iter(self._seen.values())) < now - MAX_SKEW_SECONDS * 2:
                self._seen.popitem(last=False)
            if signature in self._seen:
                return False
            self._seen[signature] = now
            return True


class TokenBody(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ttl_minutes: int = Field(default=60, ge=1, le=1440)


class EnrollBody(BaseModel):
    enrollment_token: str = Field(min_length=8, max_length=256)
    csr_pem: str = Field(min_length=1, max_length=8192)
    host: str = Field(min_length=1, max_length=255)
    os: str = Field(default="", max_length=64)


class DispatchBody(BaseModel):
    paths: list[str]
    collectors: list[str]


class _HostReplay:
    """A posted `CollectorResult`, presented to the normal pipeline as a collector
    so agent evidence goes through exactly the code path scanner evidence does.
    The registry key is made unique because one collector can return one result per
    path; the result's own `tool.name` is what the pipeline records."""

    requires_sandbox = False
    requires_network = False
    default_confidence = ConfidenceTier.HEURISTIC

    def __init__(self, key: str, result: CollectorResult) -> None:
        self.name = key
        self.version = result.tool.version
        self._result = result

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        return self._result


def _state(request: Request) -> Any:
    return request.app.state.qavach


StateDep = Annotated[Any, Depends(_state)]


def _repo(st: StateDep) -> Iterator[Repository]:
    with st.session_factory() as session:
        yield Repository(session)


RepoDep = Annotated[Repository, Depends(_repo)]


def agents_of(repo: Repository) -> AgentRepository:
    return AgentRepository(repo.s)


async def signed_agent(
    agent_id: str, request: Request, st: StateDep, repo: RepoDep
) -> models.Agent:
    agent = agents_of(repo).get_agent(agent_id)
    timestamp = request.headers.get(TIMESTAMP_HEADER, "")
    signature = request.headers.get(SIGNATURE_HEADER, "")
    raw_path = request.scope.get("raw_path")
    target = (
        raw_path.decode("ascii")
        if raw_path
        else request.url.path + (f"?{request.url.query}" if request.url.query else "")
    )
    body = await request.body()
    valid = (
        agent is not None
        and agent.status == "active"
        and verify_request(
            agent.credential_pem.encode("ascii"),
            method=request.method,
            target=target,
            timestamp=timestamp,
            body=body,
            signature_b64=signature,
            now=st.clock(),
        )
        and st.replay_guard.first_use(signature, time.time())
    )
    if not valid or agent is None:
        raise _UNAUTHENTICATED
    agents_of(repo).touch(agent.id, st.clock())
    return agent


SignedAgent = Annotated[models.Agent, Depends(signed_agent)]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def register_agent_routes(app: FastAPI, prefix: str) -> None:
    def ca_or_503(st: Any) -> AgentCA:
        if st.agent_ca is None:
            raise HTTPException(503, "agent enrolment is not configured on this server")
        return st.agent_ca()  # type: ignore[no-any-return]

    # ---- operator ---------------------------------------------------------

    @app.post(f"{prefix}/agents/tokens", status_code=201)
    def issue_token(body: TokenBody, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        ca_or_503(st)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = st.clock()
        expires = now + timedelta(minutes=body.ttl_minutes)
        token_id = agents_of(repo).issue_token(
            token_sha256=_sha256(token),
            host=body.host.strip(),
            created_by="operator",
            now=now,
            expires_at=expires,
        )
        repo.audit("operator", "agent.token.issue", token_id, now=now, detail={"host": body.host})
        repo.s.commit()
        # The one and only time the plaintext exists outside the operator's hands.
        return {
            "token_id": token_id,
            "token": token,
            "host": body.host.strip(),
            "expires_at": expires.isoformat(),
        }

    @app.get(f"{prefix}/agents/tokens")
    def list_tokens(st: StateDep, repo: RepoDep) -> list[dict[str, Any]]:
        return agents_of(repo).tokens(st.clock())

    def describe(agent: models.Agent, now: datetime, runs: int | None = None) -> dict[str, Any]:
        seen = as_utc(agent.last_seen) if agent.last_seen else None
        online = (
            agent.status == "active"
            and seen is not None
            and (now - seen).total_seconds() <= ONLINE_WITHIN_SECONDS
        )
        return {
            "id": agent.id,
            "host": agent.host,
            "os": agent.os,
            "status": agent.status,
            "online": online,
            "enrolled_at": as_utc(agent.enrolled_at).isoformat(),
            "last_seen": seen.isoformat() if seen else None,
            "credential_fingerprint": agent.credential_fingerprint,
            "credential_expires": as_utc(agent.credential_expires).isoformat(),
            "runs": runs,
        }

    @app.get(f"{prefix}/agents")
    def list_agents(st: StateDep, repo: RepoDep) -> list[dict[str, Any]]:
        a = agents_of(repo)
        counts = a.run_counts()
        now = st.clock()
        return [describe(x, now, counts.get(x.id, 0)) for x in a.list_agents()]

    @app.get(f"{prefix}/agents/{{agent_id}}")
    def agent_detail(agent_id: str, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        a = agents_of(repo)
        agent = a.get_agent(agent_id)
        if agent is None:
            raise HTTPException(404, "agent not found")
        runs = a.runs(agent_id)
        return {
            **describe(agent, st.clock(), len(runs)),
            "run_history": [
                {
                    "id": r.id,
                    "status": r.status,
                    "spec": r.scan_spec_json,
                    "queued_at": as_utc(r.queued_at).isoformat(),
                    "finished": as_utc(r.finished).isoformat() if r.finished else None,
                    "scan_run_id": r.scan_run_id,
                    "partial": r.partial,
                    "detail": r.detail,
                }
                for r in runs
            ],
        }

    @app.post(f"{prefix}/agents/{{agent_id}}/dispatch", status_code=202)
    def dispatch(agent_id: str, body: DispatchBody, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        a = agents_of(repo)
        agent = a.get_agent(agent_id)
        if agent is None:
            raise HTTPException(404, "agent not found")
        if agent.status != "active":
            raise HTTPException(409, "agent is revoked")
        try:
            spec = parse_scan_spec({"paths": body.paths, "collectors": body.collectors})
        except InvalidScanSpecError as exc:
            raise HTTPException(422, str(exc)) from exc
        run_id = a.queue_run(
            agent_id, {"paths": list(spec.paths), "collectors": list(spec.collectors)}, st.clock()
        )
        repo.audit("operator", "agent.dispatch", agent_id, now=st.clock(), detail={"run": run_id})
        repo.s.commit()
        return {"run_id": run_id, "status": "queued"}

    @app.post(f"{prefix}/agents/{{agent_id}}/revoke")
    def revoke(agent_id: str, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        if agents_of(repo).get_agent(agent_id) is None:
            raise HTTPException(404, "agent not found")
        changed = agents_of(repo).revoke(agent_id)
        repo.audit("operator", "agent.revoke", agent_id, now=st.clock())
        repo.s.commit()
        return {"revoked": changed}

    # ---- agent: enrolment ---------------------------------------------------

    @app.post(f"{prefix}/agents/enroll")
    def enroll(body: EnrollBody, st: StateDep, repo: RepoDep) -> dict[str, Any]:
        ca = ca_or_503(st)
        now = st.clock()
        agent_id = str(uuid.uuid4())
        a = agents_of(repo)
        # Validate the CSR *before* consuming the token, so a malformed request
        # cannot burn an operator's token. Consuming is the single atomic step.
        try:
            issued = ca.issue(body.csr_pem.encode("ascii", "ignore"), agent_id, now)
        except CsrRejected as exc:
            raise HTTPException(422, str(exc)) from exc
        if not a.consume_token(
            token_sha256=_sha256(body.enrollment_token),
            host=body.host.strip(),
            now=now,
            agent_id=agent_id,
        ):
            raise _UNAUTHENTICATED
        a.add_agent(
            agent_id=agent_id,
            host=body.host.strip(),
            os_name=body.os,
            now=now,
            credential_fingerprint=issued.fingerprint_sha256,
            credential_pem=issued.certificate_pem.decode("ascii"),
            credential_expires=issued.not_after,
        )
        repo.audit(
            f"agent:{agent_id}", "agent.enroll", agent_id, now=now, detail={"host": body.host}
        )
        repo.s.commit()
        return {
            "agent_id": agent_id,
            "client_cert_pem": issued.certificate_pem.decode("ascii"),
            "ca_bundle_pem": ca.bundle_pem.decode("ascii"),
        }

    # ---- agent: authenticated by request signature --------------------------

    @app.get(f"{prefix}/agents/{{agent_id}}/spec")
    def poll_spec(agent: SignedAgent, st: StateDep, repo: RepoDep) -> Response:
        run = agents_of(repo).dispatch_next(agent.id, st.clock())
        repo.s.commit()
        if run is None:
            return Response(status_code=204)
        # exactly the typed spec: {paths, collectors}. No other field, ever.
        return Response(
            content=_json(
                {
                    "paths": run.scan_spec_json["paths"],
                    "collectors": run.scan_spec_json["collectors"],
                }
            ),
            media_type="application/json",
        )

    @app.post(f"{prefix}/agents/{{agent_id}}/results")
    async def post_results(
        agent: SignedAgent, request: Request, st: StateDep, repo: RepoDep
    ) -> dict[str, Any]:
        a = agents_of(repo)
        run = a.dispatched_run(agent.id)
        if run is None:
            raise HTTPException(409, "no dispatched run is awaiting results")
        raw_body = await request.body()
        if len(raw_body) > MAX_RESULT_BYTES:
            a.finish_run(
                run.id,
                now=st.clock(),
                status="failed",
                scan_run_id=None,
                partial=True,
                detail="result exceeded the size cap",
            )
            repo.s.commit()
            raise HTTPException(413, "result payload too large")

        expected = set(run.scan_spec_json["collectors"])
        try:
            payload = await request.json()
            posted = payload["results"]
            if not isinstance(posted, dict) or not set(posted) <= expected:
                raise ValueError("results name a collector that was not in the dispatched spec")
            results: list[CollectorResult] = []
            for name in sorted(posted):
                if name not in AGENT_COLLECTOR_NAMES:
                    raise ValueError(f"unknown collector {name!r}")
                results.extend(deserialize_collector_result(item) for item in posted[name])
        except (ValueError, KeyError, TypeError) as exc:
            a.finish_run(
                run.id,
                now=st.clock(),
                status="failed",
                scan_run_id=None,
                partial=True,
                detail=f"malformed result: {type(exc).__name__}",
            )
            repo.s.commit()
            raise HTTPException(422, f"malformed result: {exc}") from exc

        registry = CollectorRegistry()
        for i, result in enumerate(results):
            registry.register(_HostReplay(f"{result.tool.name}#{i}", result))
        scan_id = str(uuid.uuid4())
        request_obj = ScanRequest(
            target=Target(type=TargetType.HOST, ref=agent.host),
            scan_id=scan_id,
            actor=f"agent:{agent.id}",
        )
        try:
            outcome = run_scan(repo.s, request_obj, dataclasses.replace(st.deps, registry=registry))
        except Exception as exc:  # noqa: BLE001 - recorded on the run, never lost
            a.finish_run(
                run.id,
                now=st.clock(),
                status="failed",
                scan_run_id=scan_id,
                partial=True,
                detail=f"ingestion raised {type(exc).__name__}",
            )
            repo.s.commit()
            raise HTTPException(500, "ingestion failed") from exc
        partial = any(r.partial for r in results) or outcome.status == "partial"
        a.finish_run(
            run.id, now=st.clock(), status="complete", scan_run_id=scan_id, partial=partial
        )
        repo.s.commit()
        return {"run_id": run.id, "scan_id": scan_id, "status": outcome.status, "partial": partial}


def _json(value: Any) -> bytes:
    import json

    return json.dumps(value, separators=(",", ":")).encode()
