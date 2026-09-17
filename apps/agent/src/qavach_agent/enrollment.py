"""ARCH.md §3a Enrollment (FR-133). T-031a.

Step 3: 'Agent exchanges the token for a rotatable long-lived client
credential... and registers itself: identity, host, OS/platform.' The agent
generates its own keypair locally and sends only a certificate signing
request — the private key never crosses the wire, standard PKI practice and
consistent with this repo's own X.509 tooling choice (`cryptography`,
`CLAUDE.md §4`).

Enrollment itself happens over server-authenticated TLS only, verified
against the pinned CA the operator provisioned alongside the token — the
agent has no client certificate yet at this point, so full mTLS (`transport.
py`) only begins on the request *after* enrollment succeeds.
"""

from __future__ import annotations

import platform
import socket
import ssl
from dataclasses import dataclass

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class EnrollmentError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AgentCredential:
    """What a successful enrollment produces — enough to authenticate every
    subsequent request without holding onto the (single-use, now-consumed)
    enrollment token. `agent_id` is the identity the backend itself issued;
    ARCH.md §3a is explicit that this, not any operator-typed hostname, is
    what evidence gets attributed to (see `HostLocus`, §6.2)."""

    agent_id: str
    private_key_pem: bytes
    client_cert_pem: bytes
    ca_bundle_pem: bytes

    def to_json_dict(self) -> dict[str, str]:
        """All four fields are ASCII-safe (an id string, three PEM blocks),
        so plain text round-trips without base64. Written to disk by the
        CLI with owner-only permissions — this dict is the at-rest shape of
        the private key, so the caller must treat the destination file the
        same way `transport.py` treats its temp copy."""
        return {
            "agent_id": self.agent_id,
            "private_key_pem": self.private_key_pem.decode("ascii"),
            "client_cert_pem": self.client_cert_pem.decode("ascii"),
            "ca_bundle_pem": self.ca_bundle_pem.decode("ascii"),
        }

    @classmethod
    def from_json_dict(cls, data: dict[str, str]) -> AgentCredential:
        return cls(
            agent_id=data["agent_id"],
            private_key_pem=data["private_key_pem"].encode("ascii"),
            client_cert_pem=data["client_cert_pem"].encode("ascii"),
            ca_bundle_pem=data["ca_bundle_pem"].encode("ascii"),
        )


def _generate_csr(common_name: str) -> tuple[bytes, bytes]:
    """Returns `(private_key_pem, csr_pem)`. P-256 — small, fast, the curve
    this repo already treats as the modern default elsewhere. Nothing about
    a short-lived, operator-rotatable mTLS client credential invokes the
    HNDL reasoning that motivates PQC elsewhere in QAVACH (`IDEATION.md`):
    that applies to data confidentiality with a long shelf life, not to an
    agent credential the operator can re-enroll in minutes."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return private_key_pem, csr_pem


def enroll(
    *,
    backend_url: str,
    enrollment_token: str,
    ca_bundle_path: str,
    hostname: str | None = None,
    timeout_seconds: float = 30.0,
) -> AgentCredential:
    """`POST /api/v1/agents/enroll` (`ARCH.md §12`). Raises `EnrollmentError`
    on any non-200 response or a malformed response body — enrollment
    failure must be loud, never a silently-empty credential the poll loop
    goes on to use."""
    host = hostname or socket.gethostname()
    private_key_pem, csr_pem = _generate_csr(host)

    ssl_context = ssl.create_default_context(cafile=ca_bundle_path)
    with httpx.Client(base_url=backend_url, verify=ssl_context, timeout=timeout_seconds) as client:
        response = client.post(
            "/api/v1/agents/enroll",
            json={
                "enrollment_token": enrollment_token,
                "csr_pem": csr_pem.decode("ascii"),
                "host": host,
                "os": platform.system(),
            },
        )

    if response.status_code != 200:
        raise EnrollmentError(
            f"enrollment failed: HTTP {response.status_code} — {response.text[:500]}"
        )

    try:
        body = response.json()
        return AgentCredential(
            agent_id=body["agent_id"],
            private_key_pem=private_key_pem,
            client_cert_pem=body["client_cert_pem"].encode("ascii"),
            ca_bundle_pem=body["ca_bundle_pem"].encode("ascii"),
        )
    except (KeyError, ValueError) as exc:
        raise EnrollmentError(f"enrollment response malformed: {exc}") from exc
