"""Signed exports - the protocol. T-097.

A **detached** signature over the exact bytes of an export, leaving the export
untouched. Detached because CycloneDX embeds signatures in JSF 0.82, whose
algorithm list (RS/PS/ES/Ed25519/Ed448/HS) has **no post-quantum algorithm**:
embedding would force a quantum-vulnerable signature into an inventory whose
whole purpose is finding those. A detached ML-DSA-65 (FIPS 204) signature keeps
the CBOM schema-valid (I5) and the signature post-quantum.

`packages/core` may import nothing but the stdlib (`tests/test_architecture.py`),
so this module defines only the *protocol*: the envelope, the signed message and
the tamper checks. The actual cryptography is injected - a `Signer` to sign, a
verify callable to verify - and lives in `apps/api` (`qavach_api.export_signing`),
which owns key custody. A signer whose algorithm is not post-quantum must say so
in `limitation`, and the envelope carries it: never a silent downgrade.

The signed message is a SHA-256 of the bytes plus their length, and the verifier
recomputes both from the file it is given, so neither truncation nor substitution
verifies.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from typing import Any, Protocol

FORMAT = "qavach-detached-signature/1"

Verify = Callable[[str, bytes, bytes, bytes], bool]
"""`(algorithm, public_key, signature, message) -> valid`."""


class Signer(Protocol):
    algorithm: str
    standard: str
    limitation: str | None

    def public_key(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def signed_message(digest_hex: str, length: int) -> bytes:
    return f"{FORMAT}\nsha256:{digest_hex}\nbytes:{length}".encode("ascii")


def sign_export(data: bytes, signer: Signer, *, key_id: str | None = None) -> dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    return {
        "format": FORMAT,
        "algorithm": signer.algorithm,
        "standard": signer.standard,
        "signed_sha256": digest,
        "signed_bytes": len(data),
        "key_id": key_id,
        "public_key": _b64(signer.public_key()),
        "signature": _b64(signer.sign(signed_message(digest, len(data)))),
        "limitation": signer.limitation,
    }


def verify_export(data: bytes, envelope: dict[str, Any], verify: Verify) -> bool:
    """Recomputes the digest and length from `data`; False on any mismatch or
    malformed envelope - never raises on a hostile one."""
    try:
        if envelope.get("format") != FORMAT:
            return False
        digest = hashlib.sha256(data).hexdigest()
        if digest != envelope["signed_sha256"] or len(data) != envelope["signed_bytes"]:
            return False
        public_key = base64.b64decode(envelope["public_key"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        return bool(
            verify(
                str(envelope["algorithm"]), public_key, signature, signed_message(digest, len(data))
            )
        )
    except Exception:  # noqa: BLE001 - any failure on a hostile envelope means "not verified"
        return False
