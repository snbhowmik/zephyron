"""Request signing: binds each agent request to the agent's enrolled key.

Why this exists on top of mTLS (ARCH.md §3a): the ASGI server does not hand the
client certificate to the application, so a backend behind uvicorn cannot tell
*which* enrolled agent is on a mutually-authenticated connection. Every request
therefore carries a signature, made with the private key whose certificate the
backend issued at enrolment, over the method, path+query, a timestamp and the
SHA-256 of the body. The backend checks it against the certificate it stored.
mTLS at the transport stays a deployment requirement; this is the application's
own proof that the request came from the holder of that key, and it means a
leaked `agent_id` alone is worthless.

Replay: the timestamp must be within `MAX_SKEW_SECONDS` of the backend's clock,
so a captured request is replayable only inside that window. That residual is
bounded, and mTLS (which a network attacker cannot read or replay into) is the
control for it; it is recorded in NOTE.md rather than hidden.

The same functions are used by both sides, so they cannot disagree about the
canonical string.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Generator
from datetime import UTC, datetime

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

TIMESTAMP_HEADER = "x-qavach-timestamp"
SIGNATURE_HEADER = "x-qavach-signature"
MAX_SKEW_SECONDS = 120


def canonical_string(method: str, target: str, timestamp: str, body: bytes) -> bytes:
    return "\n".join([method.upper(), target, timestamp, hashlib.sha256(body).hexdigest()]).encode()


def sign_request(
    private_key: ec.EllipticCurvePrivateKey, method: str, target: str, timestamp: str, body: bytes
) -> str:
    signature = private_key.sign(
        canonical_string(method, target, timestamp, body), ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("ascii")


def verify_request(
    certificate_pem: bytes,
    *,
    method: str,
    target: str,
    timestamp: str,
    body: bytes,
    signature_b64: str,
    now: datetime,
) -> bool:
    """False for *every* failure - malformed input, stale timestamp, bad
    signature, expired certificate - so no failure mode is distinguishable."""
    try:
        sent = datetime.fromtimestamp(int(timestamp), tz=UTC)
        if abs((now - sent).total_seconds()) > MAX_SKEW_SECONDS:
            return False
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            return False
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(
            base64.b64decode(signature_b64, validate=True),
            canonical_string(method, target, timestamp, body),
            ec.ECDSA(hashes.SHA256()),
        )
    except (ValueError, InvalidSignature, TypeError):
        return False
    return True


class SignedRequestAuth(httpx.Auth):
    """httpx auth flow that signs every request with the agent's key."""

    requires_request_body = True

    def __init__(self, private_key_pem: bytes) -> None:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("agent credentials use an EC key")
        self._key = key

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        timestamp = str(int(datetime.now(UTC).timestamp()))
        target = request.url.raw_path.decode("ascii")
        request.headers[TIMESTAMP_HEADER] = timestamp
        request.headers[SIGNATURE_HEADER] = sign_request(
            self._key, request.method, target, timestamp, request.content
        )
        yield request
