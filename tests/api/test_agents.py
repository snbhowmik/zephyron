"""T-073a - the agent registry over the real API: token issue, enrolment (real
CSR, real CA), signed polling, dispatch, and result ingestion through the normal
pipeline. The agent side is the real `poll_once` and the real request signing;
only the network is the in-process TestClient."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qavach_agent import poll_once
from qavach_agent.enrollment import _generate_csr
from qavach_agent.signing import SignedRequestAuth
from qavach_api import AppState, create_app
from qavach_api.agent_ca import AgentCA
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
from qavach_storage import create_all, make_engine, session_factory
from qavach_worker import Deps
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).parent))
from test_api import KNOWLEDGE, POLICY, PQC  # noqa: E402

# the agent signs with the real wall clock, so the server clock must start there
NOW = datetime.now(UTC).replace(microsecond=0)


class FakeStore:
    name = "tls.store"
    version = "0.1.0"
    default_confidence = ConfidenceTier.PATTERN
    requires_sandbox = False
    requires_network = False

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        return CollectorResult(
            raw=b"{}",
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=[
                RawClaim(
                    locus=FileLocus(path=f"{target.ref}/server.jks", offset=0),
                    name="RSA-2048",
                    primitive="signature",
                    detection_method="keystore",
                    confidence=ConfidenceTier.PATTERN,
                ),
                RawClaim(
                    locus=FileLocus(path=f"{target.ref}/legacy.jks", offset=0),
                    name="MD5",
                    detection_method="keystore",
                    confidence=ConfidenceTier.PATTERN,
                ),
            ],
            tool=ToolIdentity("tls.store", "0.1.0", ("fake",), 0, 0.01),
            errors=[],
            partial=False,
        )


@pytest.fixture
def clock() -> list[datetime]:
    return [NOW]


@pytest.fixture
def client(tmp_path: Path, clock: list[datetime]) -> TestClient:
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    create_all(engine)
    _ = make_engine
    state = AppState(
        session_factory=session_factory(engine),
        deps=Deps(
            registry=CollectorRegistry(),
            knowledge=KNOWLEDGE,
            policy=POLICY,
            pqc=PQC,
            clock=lambda: clock[0],
        ),
        runner=lambda job: job(),
        clock=lambda: clock[0],
        agent_ca=lambda: AgentCA.load_or_create(tmp_path / "ca", clock[0]),
    )
    return TestClient(create_app(state))


def enrol(client: TestClient, host: str = "web-01") -> tuple[str, bytes]:
    token = client.post("/api/v1/agents/tokens", json={"host": host}).json()["token"]
    key_pem, csr_pem = _generate_csr(host)
    r = client.post(
        "/api/v1/agents/enroll",
        json={"enrollment_token": token, "csr_pem": csr_pem.decode(), "host": host, "os": "Linux"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "BEGIN CERTIFICATE" in body["client_cert_pem"] and body["ca_bundle_pem"]
    return body["agent_id"], key_pem


def as_agent(client: TestClient, key_pem: bytes) -> None:
    client.auth = SignedRequestAuth(key_pem)


def test_the_token_is_shown_once_is_single_use_and_scoped_to_its_host(client: TestClient) -> None:
    issued = client.post("/api/v1/agents/tokens", json={"host": "web-01"}).json()
    assert issued["token"].startswith("qat_")
    assert issued["token"] not in str(client.get("/api/v1/agents/tokens").json())
    _, csr = _generate_csr("web-01")

    def attempt(host: str) -> int:
        return client.post(
            "/api/v1/agents/enroll",
            json={
                "enrollment_token": issued["token"],
                "csr_pem": csr.decode(),
                "host": host,
                "os": "Linux",
            },
        ).status_code

    assert attempt("db-09") == 401  # wrong host: refused, and must not burn the token
    assert attempt("web-01") == 200
    assert attempt("web-01") == 401  # consumed
    assert client.get("/api/v1/agents/tokens").json()[0]["state"] == "consumed"


def test_an_expired_token_and_a_bad_csr_are_refused_without_burning_the_token(
    client: TestClient, clock: list[datetime]
) -> None:
    token = client.post("/api/v1/agents/tokens", json={"host": "h", "ttl_minutes": 5}).json()[
        "token"
    ]
    bad = client.post(
        "/api/v1/agents/enroll",
        json={"enrollment_token": token, "csr_pem": "garbage", "host": "h", "os": ""},
    )
    assert bad.status_code == 422
    assert client.get("/api/v1/agents/tokens").json()[0]["state"] == "pending"
    clock[0] = NOW + timedelta(minutes=6)
    _, csr = _generate_csr("h")
    late = client.post(
        "/api/v1/agents/enroll",
        json={"enrollment_token": token, "csr_pem": csr.decode(), "host": "h", "os": ""},
    )
    assert late.status_code == 401


def test_the_issued_identity_is_ours_not_whatever_the_agent_asked_to_be_called(
    client: TestClient,
) -> None:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    token = client.post("/api/v1/agents/tokens", json={"host": "web-01"}).json()["token"]
    _, csr = _generate_csr("i-am-the-domain-controller")
    body = client.post(
        "/api/v1/agents/enroll",
        json={"enrollment_token": token, "csr_pem": csr.decode(), "host": "web-01", "os": "x"},
    ).json()
    cert = x509.load_pem_x509_certificate(body["client_cert_pem"].encode())
    [cn] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn.value == body["agent_id"]


def test_agent_endpoints_refuse_unsigned_forged_and_replayed_requests(client: TestClient) -> None:
    agent_id, key = enrol(client)
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 401  # unsigned
    assert (
        client.post(f"/api/v1/agents/{agent_id}/results", json={"results": {}}).status_code == 401
    )
    other_key = _generate_csr("x")[0]
    as_agent(client, other_key)  # right agent id, someone else's key
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 401
    as_agent(client, key)
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 204
    # replay: same signed request twice
    request = client.build_request("GET", f"/api/v1/agents/{agent_id}/spec")
    signed = next(SignedRequestAuth(key).auth_flow(request))
    client.auth = None
    assert client.send(signed).status_code == 204
    assert client.send(signed).status_code == 401


def test_a_stale_signature_is_refused(client: TestClient, clock: list[datetime]) -> None:
    agent_id, key = enrol(client)
    as_agent(client, key)
    clock[0] = NOW + timedelta(minutes=10)  # the agent's timestamp is 10 minutes behind us
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 401


def test_a_revoked_agent_is_locked_out(client: TestClient) -> None:
    agent_id, key = enrol(client)
    client.post(f"/api/v1/agents/{agent_id}/revoke")
    as_agent(client, key)
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 401


def test_dispatch_accepts_only_the_closed_vocabulary(client: TestClient) -> None:
    agent_id, _ = enrol(client)
    ok = client.post(
        f"/api/v1/agents/{agent_id}/dispatch",
        json={"paths": ["/etc/ssl"], "collectors": ["tls.store"]},
    )
    assert ok.status_code == 202
    for bad in (
        {"paths": ["/etc"], "collectors": ["sh -c 'curl evil'"]},
        {"paths": [], "collectors": ["tls.store"]},
    ):
        assert client.post(f"/api/v1/agents/{agent_id}/dispatch", json=bad).status_code == 422


def test_dispatch_poll_run_post_ingests_evidence_through_the_real_pipeline(
    client: TestClient,
) -> None:
    agent_id, key = enrol(client)
    client.post(
        f"/api/v1/agents/{agent_id}/dispatch",
        json={"paths": ["/opt/tomcat/conf"], "collectors": ["tls.store"]},
    )
    as_agent(client, key)
    registry = CollectorRegistry()
    registry.register(FakeStore())
    outcome = poll_once(client=client, agent_id=agent_id, registry=registry, scan_run_id="r1")
    assert outcome.ok and outcome.had_work and outcome.collectors_run == ("tls.store",)

    client.auth = None
    detail = client.get(f"/api/v1/agents/{agent_id}").json()
    [run] = detail["run_history"]
    assert run["status"] == "complete" and run["scan_run_id"] and not run["partial"]
    assert detail["online"] is True and detail["runs"] == 1

    scan = client.get(f"/api/v1/scans/{run['scan_run_id']}").json()
    assert scan["status"] == "complete" and scan["target_ref"] == "web-01"
    assets = client.get(f"/api/v1/scans/{run['scan_run_id']}/assets").json()
    families = {a["family"] for a in assets["items"]}
    assert "MD5" in families and any("RSA" in f for f in families)
    # the polled spec was consumed: nothing left to hand out
    as_agent(client, key)
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 204


def test_results_for_a_collector_that_was_not_dispatched_are_rejected_and_the_run_fails(
    client: TestClient,
) -> None:
    agent_id, key = enrol(client)
    client.post(
        f"/api/v1/agents/{agent_id}/dispatch", json={"paths": ["/x"], "collectors": ["tls.store"]}
    )
    as_agent(client, key)
    assert client.get(f"/api/v1/agents/{agent_id}/spec").status_code == 200
    r = client.post(f"/api/v1/agents/{agent_id}/results", json={"results": {"hsm.evidence": []}})
    assert r.status_code == 422
    client.auth = None
    assert client.get(f"/api/v1/agents/{agent_id}").json()["run_history"][0]["status"] == "failed"


def test_results_with_no_dispatched_run_are_a_409(client: TestClient) -> None:
    agent_id, key = enrol(client)
    as_agent(client, key)
    assert (
        client.post(f"/api/v1/agents/{agent_id}/results", json={"results": {}}).status_code == 409
    )


def test_an_agent_is_offline_until_it_polls_and_again_after_it_goes_quiet(
    client: TestClient, clock: list[datetime]
) -> None:
    agent_id, key = enrol(client)
    assert client.get("/api/v1/agents").json()[0]["online"] is False
    as_agent(client, key)
    client.get(f"/api/v1/agents/{agent_id}/spec")
    client.auth = None
    assert client.get("/api/v1/agents").json()[0]["online"] is True
    clock[0] = NOW + timedelta(minutes=10)
    assert client.get("/api/v1/agents").json()[0]["online"] is False


def test_agent_routes_stay_reachable_but_still_self_authenticating_behind_the_operator_token(
    client: TestClient,
) -> None:
    from qavach_api.auth import AGENT_SELF_AUTH

    assert AGENT_SELF_AUTH.match("/api/v1/agents/enroll")
    assert AGENT_SELF_AUTH.match("/api/v1/agents/abc/spec")
    assert AGENT_SELF_AUTH.match("/api/v1/agents/abc/results")
    # operator routes must NOT be exempt from the bearer token
    for path in (
        "/api/v1/agents",
        "/api/v1/agents/tokens",
        "/api/v1/agents/abc",
        "/api/v1/agents/abc/dispatch",
        "/api/v1/agents/abc/revoke",
    ):
        assert not AGENT_SELF_AUTH.match(path), path
