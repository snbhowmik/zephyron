"""T-031a — `AgentTransport`, against the real local mTLS mock backend.
Proves the client certificate materialised by `AgentTransport` is actually
what gets presented on the wire and actually satisfies the backend's own
peer-certificate check (`_mock_backend`'s `_client_cert_present`), not just
that the right constructor arguments were passed."""

from __future__ import annotations

import stat
from pathlib import Path

import httpx
import pytest
from _mock_backend import run_mock_backend
from _pki import issue_server_cert, make_test_ca
from qavach_agent import AgentCredential, AgentTransport, enroll


def _real_credential(tmp_path: Path, *, token: str = "tok-abc") -> tuple[AgentCredential, object]:
    ca = make_test_ca()
    with run_mock_backend(tmp_path=tmp_path, ca=ca, expected_enrollment_token=token) as (
        backend_url,
        _state,
    ):
        ca_path = tmp_path / "pinned-ca.crt"
        ca_path.write_bytes(ca.cert_pem)
        credential = enroll(
            backend_url=backend_url, enrollment_token=token, ca_bundle_path=str(ca_path)
        )
    return credential, ca


def test_transport_authenticates_with_the_enrolled_client_certificate(tmp_path: Path) -> None:
    credential, ca = _real_credential(tmp_path / "enroll")
    with run_mock_backend(
        tmp_path=tmp_path / "backend", ca=ca, expected_enrollment_token="unused"
    ) as (
        backend_url,
        state,
    ):
        state.spec_queue.append({"paths": ["/etc/ssl"], "collectors": ["tls.store"]})
        with AgentTransport(backend_url=backend_url, credential=credential) as client:
            response = client.get(f"/api/v1/agents/{credential.agent_id}/spec")
        assert response.status_code == 200
        assert response.json() == {"paths": ["/etc/ssl"], "collectors": ["tls.store"]}


def test_transport_rejects_the_backend_if_not_signed_by_the_pinned_ca(tmp_path: Path) -> None:
    """A different CA presenting itself as the backend must be refused —
    ARCH.md §3a: 'verifies the backend's certificate against a pinned CA
    rather than trusting whatever is offered.' The credential's own client
    certificate is signed by `wrong_ca` too, so it is one the mock server
    (which also trusts `wrong_ca`) would happily accept — isolating the
    failure to the client's verification of the *server*, not a client-cert
    mismatch muddying the result."""
    real_ca = make_test_ca()  # what the agent is pinned to trust
    wrong_ca = make_test_ca(common_name="Rogue CA")  # what the backend actually presents
    with run_mock_backend(tmp_path=tmp_path, ca=wrong_ca, expected_enrollment_token="tok") as (
        backend_url,
        _state,
    ):
        client_cert_pem, client_key_pem = issue_server_cert(wrong_ca, hostname="agent-client")
        credential = AgentCredential(
            agent_id="agent-x",
            private_key_pem=client_key_pem,
            client_cert_pem=client_cert_pem,
            ca_bundle_pem=real_ca.cert_pem,  # pinned to the WRONG ca for this backend, on purpose
        )
        with (
            pytest.raises(httpx.ConnectError),
            AgentTransport(backend_url=backend_url, credential=credential) as client,
        ):
            client.get("/api/v1/agents/agent-x/spec")


def test_transport_writes_the_private_key_with_owner_only_permissions(tmp_path: Path) -> None:
    credential, ca = _real_credential(tmp_path)
    with run_mock_backend(tmp_path=tmp_path / "b2", ca=ca, expected_enrollment_token="unused") as (
        backend_url,
        _state,
    ):
        transport = AgentTransport(backend_url=backend_url, credential=credential)
        with transport:
            assert transport._tmpdir is not None
            key_path = Path(transport._tmpdir.name) / "client.key"
            mode = stat.S_IMODE(key_path.stat().st_mode)
            assert mode == 0o600


def test_transport_removes_credential_material_on_exit(tmp_path: Path) -> None:
    credential, ca = _real_credential(tmp_path)
    with run_mock_backend(tmp_path=tmp_path / "b3", ca=ca, expected_enrollment_token="unused") as (
        backend_url,
        _state,
    ):
        transport = AgentTransport(backend_url=backend_url, credential=credential)
        with transport:
            tmp_dir_path = Path(transport._tmpdir.name)  # type: ignore[union-attr]
            assert tmp_dir_path.exists()
        assert not tmp_dir_path.exists()
