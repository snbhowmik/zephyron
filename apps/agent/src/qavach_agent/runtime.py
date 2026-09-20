"""ARCH.md §3a — the poll loop. T-031a.

'It opens a connection to the backend, asks "do you have work for me," runs
it, posts results, and closes.' `poll_once` is exactly one such cycle;
`run_forever` repeats it on an interval. Neither ever talks to more than the
one backend URL the caller's `httpx.Client` (from `transport.AgentTransport`)
is bound to — there is no second endpoint this module knows how to reach.

AGENT-01 (resolved, T-073a): `serialize_collector_result` below and its inverse
`deserialize_collector_result` are the wire contract for `POST .../results`; the
backend (`qavach_api.agent_routes`) uses the inverse, and a round-trip test pins
the pair. The body is `{"results": {<collector>: [<serialized result>, ...]}}`.
"""

from __future__ import annotations

import base64
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from qavach_collectors import CollectorRegistry, CollectorResult, RunContext, Target, TargetType
from qavach_collectors.base import (
    CollectorError,
    RawClaim,
    RawFormat,
    ToolIdentity,
)
from qavach_core.model import CertificateFacts, locus_from_dict, locus_to_dict
from qavach_core.model.enums import ConfidenceTier

from qavach_agent.spec import InvalidScanSpecError, ScanSpec, parse_scan_spec

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PollOutcome:
    """What one poll-run-post cycle did. Never raised as an exception for a
    routine "no work this tick" or "backend unreachable" result — those are
    ordinary outcomes of an outbound poll, not failures of the loop itself
    (mirrors `SECURITY.md §3`'s "failure is isolated" principle, applied to
    the agent's own network calls rather than a sandboxed collector)."""

    had_work: bool
    spec: ScanSpec | None = None
    collectors_run: tuple[str, ...] = ()
    collectors_skipped_unregistered: tuple[str, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def serialize_collector_result(result: CollectorResult) -> dict[str, object]:
    return {
        "raw_base64": base64.b64encode(result.raw).decode("ascii"),
        "raw_format": result.raw_format.value,
        "claims": [
            {
                "locus": locus_to_dict(claim.locus),
                "name": claim.name,
                "oid": claim.oid,
                "primitive": claim.primitive,
                "parameter_set": claim.parameter_set,
                "mode": claim.mode,
                "padding": claim.padding,
                "detection_method": claim.detection_method,
                "confidence": int(claim.confidence),
                "certificate": claim.certificate.to_dict() if claim.certificate else None,
            }
            for claim in result.claims
        ],
        "tool": {
            "name": result.tool.name,
            "version": result.tool.version,
            "invocation": list(result.tool.invocation),
            "exit_code": result.tool.exit_code,
            "duration_seconds": result.tool.duration_seconds,
        },
        "errors": [{"message": e.message, "fatal": e.fatal} for e in result.errors],
        "partial": result.partial,
    }


def deserialize_collector_result(data: dict[str, Any]) -> CollectorResult:
    """Inverse of `serialize_collector_result` - used by the backend to turn a
    posted result back into a `CollectorResult` for the normal pipeline. Raises
    `ValueError`/`KeyError` on any malformed field: the backend must never
    half-ingest a result it did not fully understand."""
    return CollectorResult(
        raw=base64.b64decode(data["raw_base64"], validate=True),
        raw_format=RawFormat(data["raw_format"]),
        claims=[
            RawClaim(
                locus=locus_from_dict(c["locus"]),
                name=c.get("name"),
                oid=c.get("oid"),
                primitive=c.get("primitive"),
                parameter_set=c.get("parameter_set"),
                mode=c.get("mode"),
                padding=c.get("padding"),
                detection_method=c["detection_method"],
                confidence=ConfidenceTier(int(c["confidence"])),
                certificate=(
                    CertificateFacts.from_dict(c["certificate"]) if c.get("certificate") else None
                ),
            )
            for c in data["claims"]
        ],
        tool=ToolIdentity(
            name=data["tool"]["name"],
            version=data["tool"]["version"],
            invocation=tuple(data["tool"]["invocation"]),
            exit_code=data["tool"]["exit_code"],
            duration_seconds=float(data["tool"]["duration_seconds"]),
        ),
        errors=[
            CollectorError(message=e["message"], fatal=bool(e["fatal"])) for e in data["errors"]
        ],
        partial=bool(data["partial"]),
    )


def poll_once(
    *,
    client: httpx.Client,
    agent_id: str,
    registry: CollectorRegistry,
    scan_run_id: str,
) -> PollOutcome:
    """One outbound-poll cycle against `GET/POST /api/v1/agents/{agent_id}/
    ...` (`ARCH.md §12`). A spec collector name that is not registered in
    this build is skipped and reported in `collectors_skipped_unregistered`
    — never an error the whole cycle fails on, since the agent's own fixed
    vocabulary (`spec.AGENT_COLLECTOR_NAMES`) is deliberately broader than
    what any one build necessarily has wired up yet."""
    try:
        spec_response = client.get(f"/api/v1/agents/{agent_id}/spec")
    except httpx.HTTPError as exc:
        return PollOutcome(had_work=False, error=f"spec poll unreachable: {exc}")

    if spec_response.status_code == 204:
        return PollOutcome(had_work=False)
    if spec_response.status_code != 200:
        return PollOutcome(
            had_work=False, error=f"spec poll failed: HTTP {spec_response.status_code}"
        )

    try:
        spec = parse_scan_spec(spec_response.json())
    except (InvalidScanSpecError, ValueError) as exc:
        return PollOutcome(had_work=False, error=f"invalid scan spec: {exc}")

    results: dict[str, list[dict[str, object]]] = {}
    ran: list[str] = []
    skipped: list[str] = []
    ctx = RunContext(scan_run_id=scan_run_id)

    for collector_name in spec.collectors:
        try:
            collector = registry.get(collector_name)
        except KeyError:
            skipped.append(collector_name)
            continue

        per_path_results: list[dict[str, object]] = []
        for path in spec.paths:
            target = Target(type=TargetType.HOST, ref=path)
            if not collector.supports(target):
                continue
            result = collector.collect(target, ctx)
            per_path_results.append(serialize_collector_result(result))
        results[collector_name] = per_path_results
        ran.append(collector_name)

    try:
        post_response = client.post(f"/api/v1/agents/{agent_id}/results", json={"results": results})
    except httpx.HTTPError as exc:
        return PollOutcome(
            had_work=True,
            spec=spec,
            collectors_run=tuple(ran),
            collectors_skipped_unregistered=tuple(skipped),
            error=f"result post unreachable: {exc}",
        )

    if post_response.status_code != 200:
        return PollOutcome(
            had_work=True,
            spec=spec,
            collectors_run=tuple(ran),
            collectors_skipped_unregistered=tuple(skipped),
            error=f"result post failed: HTTP {post_response.status_code}",
        )

    return PollOutcome(
        had_work=True,
        spec=spec,
        collectors_run=tuple(ran),
        collectors_skipped_unregistered=tuple(skipped),
    )


@dataclass(frozen=True, slots=True)
class RunForeverConfig:
    poll_interval_seconds: float = 30.0
    max_iterations: int | None = None
    """`None` runs indefinitely; set for tests and bounded runs."""


def run_forever(
    *,
    client: httpx.Client,
    agent_id: str,
    registry: CollectorRegistry,
    sleep: Callable[[float], None] = time.sleep,
    config: RunForeverConfig | None = None,
) -> list[PollOutcome]:
    """Repeats `poll_once` on `config.poll_interval_seconds`. Returns the
    outcomes it collected — bounded by `config.max_iterations` in tests so
    this is actually exercisable without blocking forever; a real deployment
    passes `max_iterations=None` (the default) and runs until the process is
    stopped, which is the agent's whole outbound-poll-only lifecycle
    (`ARCH.md §3a`: it never listens, it only ever asks). `sleep` is
    injectable so a test can run many iterations without real wall-clock
    delay between them."""
    config = config or RunForeverConfig()
    outcomes: list[PollOutcome] = []
    iteration = 0
    while config.max_iterations is None or iteration < config.max_iterations:
        scan_run_id = f"agent-run-{uuid.uuid4().hex[:12]}"
        outcomes.append(
            poll_once(client=client, agent_id=agent_id, registry=registry, scan_run_id=scan_run_id)
        )
        iteration += 1
        if config.max_iterations is None or iteration < config.max_iterations:
            sleep(config.poll_interval_seconds)
    return outcomes
