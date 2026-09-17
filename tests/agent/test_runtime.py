"""T-031a — the poll loop (`runtime.py`), end to end against the real mock
backend: GET a real spec over real mTLS, run a real (fake) collector against
it, POST a real serialized result back, and confirm the backend actually
received it. No real agent-side collector exists yet (`tls.store` etc. are
still-blocked Phase 3 tasks), so these tests register a `_FakeHostCollector`
standing in for one — proving the loop's own mechanics, which is exactly
T-031a's scope."""

from __future__ import annotations

from pathlib import Path

from _mock_backend import run_mock_backend
from _pki import make_test_ca
from qavach_agent import (
    AgentTransport,
    PollOutcome,
    RunForeverConfig,
    enroll,
    poll_once,
    run_forever,
)
from qavach_collectors import (
    CollectorRegistry,
    CollectorResult,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)
from qavach_core.model import ConfidenceTier, FileLocus


class _FakeHostCollector:
    name = "tls.store"
    version = "0.1.0"
    default_confidence = ConfidenceTier.PATTERN
    requires_sandbox = False
    requires_network = False

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        return CollectorResult(
            raw=b'{"found":1}',
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=[
                RawClaim(
                    locus=FileLocus(path=f"{target.ref}/server.jks", offset=0),
                    name="RSA",
                    confidence=self.default_confidence,
                )
            ],
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=("fake",),
                exit_code=0,
                duration_seconds=0.05,
            ),
            errors=[],
            partial=False,
        )


def _enrolled(tmp_path: Path) -> tuple[str, object, object]:
    """Returns `(backend_url, credential, ca)` from a full real enrollment,
    for tests that then talk to a *second* mock backend instance bound to
    the same CA (mirroring "enroll once, poll repeatedly against the same
    backend" without reusing one server across enroll + poll in a single
    `with` block, since enrollment intentionally happens before mTLS is
    available)."""
    ca = make_test_ca()
    with run_mock_backend(tmp_path=tmp_path / "enroll", ca=ca, expected_enrollment_token="tok") as (
        backend_url,
        _state,
    ):
        ca_path = tmp_path / "pinned-ca.crt"
        ca_path.write_bytes(ca.cert_pem)
        credential = enroll(
            backend_url=backend_url, enrollment_token="tok", ca_bundle_path=str(ca_path)
        )
    return backend_url, credential, ca


def test_poll_once_with_no_work_queued(tmp_path: Path) -> None:
    _backend_url, credential, ca = _enrolled(tmp_path)
    with run_mock_backend(
        tmp_path=tmp_path / "poll", ca=ca, expected_enrollment_token="unused"
    ) as (
        backend_url,
        _state,
    ):
        registry = CollectorRegistry()
        with AgentTransport(backend_url=backend_url, credential=credential) as client:
            outcome = poll_once(
                client=client, agent_id=credential.agent_id, registry=registry, scan_run_id="run-1"
            )
        assert outcome == PollOutcome(had_work=False)
        assert outcome.ok


def test_poll_once_runs_a_registered_collector_and_posts_results(tmp_path: Path) -> None:
    _backend_url, credential, ca = _enrolled(tmp_path)
    with run_mock_backend(
        tmp_path=tmp_path / "poll", ca=ca, expected_enrollment_token="unused"
    ) as (
        backend_url,
        state,
    ):
        state.spec_queue.append({"paths": ["/opt/tomcat"], "collectors": ["tls.store"]})
        registry = CollectorRegistry()
        registry.register(_FakeHostCollector())

        with AgentTransport(backend_url=backend_url, credential=credential) as client:
            outcome = poll_once(
                client=client, agent_id=credential.agent_id, registry=registry, scan_run_id="run-1"
            )

        assert outcome.ok
        assert outcome.had_work
        assert outcome.collectors_run == ("tls.store",)
        assert outcome.collectors_skipped_unregistered == ()

        # The backend actually received a real, decodable claim.
        assert len(state.posted_results) == 1
        posted = state.posted_results[0]["results"]["tls.store"]
        assert len(posted) == 1
        assert posted[0]["claims"][0]["name"] == "RSA"
        assert posted[0]["claims"][0]["locus"]["path"] == "/opt/tomcat/server.jks"


def test_poll_once_skips_an_unregistered_collector_without_failing(tmp_path: Path) -> None:
    """None of ARCH.md §3a's four agent-only collectors are built yet
    (T-036, T-036a, T-041, T-042 are still open) — a real deployment today
    would receive specs naming modules this build has not registered.
    That must degrade gracefully, not blow up the whole poll cycle."""
    _backend_url, credential, ca = _enrolled(tmp_path)
    with run_mock_backend(
        tmp_path=tmp_path / "poll", ca=ca, expected_enrollment_token="unused"
    ) as (
        backend_url,
        state,
    ):
        state.spec_queue.append({"paths": ["/etc/ssl"], "collectors": ["hsm.evidence"]})
        registry = CollectorRegistry()  # nothing registered

        with AgentTransport(backend_url=backend_url, credential=credential) as client:
            outcome = poll_once(
                client=client, agent_id=credential.agent_id, registry=registry, scan_run_id="run-1"
            )

        assert outcome.ok
        assert outcome.collectors_run == ()
        assert outcome.collectors_skipped_unregistered == ("hsm.evidence",)
        assert state.posted_results[0]["results"] == {}


def test_poll_once_reports_an_invalid_spec_without_raising(tmp_path: Path) -> None:
    _backend_url, credential, ca = _enrolled(tmp_path)
    with run_mock_backend(
        tmp_path=tmp_path / "poll", ca=ca, expected_enrollment_token="unused"
    ) as (
        backend_url,
        state,
    ):
        state.spec_queue.append({"paths": ["/etc/ssl"], "collectors": ["not.a.real.module"]})
        registry = CollectorRegistry()

        with AgentTransport(backend_url=backend_url, credential=credential) as client:
            outcome = poll_once(
                client=client, agent_id=credential.agent_id, registry=registry, scan_run_id="run-1"
            )

        assert not outcome.ok
        assert outcome.error is not None
        assert "invalid scan spec" in outcome.error
        assert state.posted_results == []  # never reaches the results POST


def test_run_forever_is_bounded_by_max_iterations_and_does_not_sleep_in_tests(
    tmp_path: Path,
) -> None:
    _backend_url, credential, ca = _enrolled(tmp_path)
    with run_mock_backend(
        tmp_path=tmp_path / "poll", ca=ca, expected_enrollment_token="unused"
    ) as (
        backend_url,
        state,
    ):
        state.spec_queue.append({"paths": ["/etc/ssl"], "collectors": ["tls.store"]})
        registry = CollectorRegistry()
        registry.register(_FakeHostCollector())

        slept_for: list[float] = []
        with AgentTransport(backend_url=backend_url, credential=credential) as client:
            outcomes = run_forever(
                client=client,
                agent_id=credential.agent_id,
                registry=registry,
                sleep=slept_for.append,
                config=RunForeverConfig(poll_interval_seconds=5.0, max_iterations=3),
            )

        assert len(outcomes) == 3
        assert outcomes[0].had_work  # the one queued spec
        assert not outcomes[1].had_work  # queue now empty -> 204
        assert not outcomes[2].had_work
        assert slept_for == [5.0, 5.0]  # never sleeps after the last iteration
