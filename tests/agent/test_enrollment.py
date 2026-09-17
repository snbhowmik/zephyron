"""T-031a — enrollment (ARCH.md §3a step 3), against a real local mock
backend that actually signs the agent's CSR (tests/agent/_mock_backend.py),
not a mocked HTTP call. `T-073a` (the real backend) is Phase 6 and does not
exist yet; this is the client-side half, genuinely exercisable without it."""

from __future__ import annotations

from pathlib import Path

import pytest
from _mock_backend import run_mock_backend
from _pki import make_test_ca
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from qavach_agent import EnrollmentError, enroll


def test_enrollment_succeeds_with_a_valid_token(tmp_path: Path) -> None:
    ca = make_test_ca()
    with run_mock_backend(tmp_path=tmp_path, ca=ca, expected_enrollment_token="tok-123") as (
        backend_url,
        state,
    ):
        ca_path = tmp_path / "pinned-ca.crt"
        ca_path.write_bytes(ca.cert_pem)

        credential = enroll(
            backend_url=backend_url,
            enrollment_token="tok-123",
            ca_bundle_path=str(ca_path),
            hostname="test-host-1",
        )

        assert credential.agent_id == "agent-1"
        assert state.enroll_call_count == 1

        # The private key never left the agent: it exists locally...
        private_key = serialization.load_pem_private_key(credential.private_key_pem, password=None)
        # ...and the returned certificate is signed by the test CA, for the
        # public key matching that same private key.
        client_cert = x509.load_pem_x509_certificate(credential.client_cert_pem)
        assert client_cert.issuer == ca.certificate.subject
        assert (
            client_cert.public_key().public_numbers()  # type: ignore[union-attr]
            == private_key.public_key().public_numbers()  # type: ignore[union-attr]
        )
        assert (
            client_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            == "test-host-1"
        )


def test_enrollment_rejects_a_wrong_token(tmp_path: Path) -> None:
    ca = make_test_ca()
    with run_mock_backend(tmp_path=tmp_path, ca=ca, expected_enrollment_token="tok-123") as (
        backend_url,
        _state,
    ):
        ca_path = tmp_path / "pinned-ca.crt"
        ca_path.write_bytes(ca.cert_pem)

        with pytest.raises(EnrollmentError, match="HTTP 403"):
            enroll(
                backend_url=backend_url,
                enrollment_token="wrong-token",
                ca_bundle_path=str(ca_path),
            )


def test_enrollment_rejects_an_untrusted_backend_certificate(tmp_path: Path) -> None:
    """The agent verifies the backend's certificate against the *pinned*
    CA (ARCH.md §3a Transport) — a CA the operator did not provision must
    be refused, not silently trusted."""
    real_ca = make_test_ca()
    wrong_ca = make_test_ca(common_name="Attacker CA")
    with run_mock_backend(tmp_path=tmp_path, ca=real_ca, expected_enrollment_token="tok-123") as (
        backend_url,
        _state,
    ):
        wrong_ca_path = tmp_path / "wrong-ca.crt"
        wrong_ca_path.write_bytes(wrong_ca.cert_pem)

        with pytest.raises(Exception):  # noqa: B017 — httpx raises an ssl.SSLCertVerificationError wrapper
            enroll(
                backend_url=backend_url,
                enrollment_token="tok-123",
                ca_bundle_path=str(wrong_ca_path),
            )
