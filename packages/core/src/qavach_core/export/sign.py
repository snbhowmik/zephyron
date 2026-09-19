"""Signed exports. T-097.

A **detached** signature over the exact bytes of an export, leaving the export
itself untouched. Detached because CycloneDX embeds signatures in JSF 0.82, whose
algorithm list (RS/PS/ES/Ed25519/Ed448/HS) has **no post-quantum algorithm**:
embedding would force a quantum-vulnerable signature into an inventory whose
whole purpose is finding those. A detached ML-DSA-65 (FIPS 204) signature keeps
the CBOM schema-valid (I5) and the signature post-quantum.

`cryptography` 50 provides ML-DSA-65; if a build lacks it the signer falls back
to Ed25519 and the output *says so* in `limitation` - never a silent downgrade.
The signature covers a SHA-256 of the bytes plus the byte length, and the
verifier recomputes both from the file it is given, so neither truncation nor
substitution verifies.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

FORMAT = "qavach-detached-signature/1"
_ED25519_LIMITATION = (
    "Signed with Ed25519, which is quantum-vulnerable: ML-DSA-65 was not available in "
    "this build. Treat this signature as authenticating today, not against a future "
    "cryptographically relevant quantum computer."
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _message(digest_hex: str, length: int) -> bytes:
    return f"{FORMAT}\nsha256:{digest_hex}\nbytes:{length}".encode("ascii")


def generate_signer(prefer: str = "ML-DSA-65") -> Any:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if prefer == "ML-DSA-65":
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa

            return mldsa.MLDSA65PrivateKey.generate()
        except (ImportError, AttributeError, UnsupportedAlgorithm):
            pass
    return ed25519.Ed25519PrivateKey.generate()


def _algorithm_of(private_key: Any) -> tuple[str, str, str | None]:
    name = type(private_key).__name__
    if name == "MLDSA65PrivateKey":
        return "ML-DSA-65", "FIPS 204", None
    if name == "Ed25519PrivateKey":
        return "Ed25519", "RFC 8032", _ED25519_LIMITATION
    raise ValueError(f"unsupported signing key type {name}")


def _public_bytes(private_key: Any) -> bytes:
    public = private_key.public_key()
    if hasattr(public, "public_bytes_raw"):
        return bytes(public.public_bytes_raw())
    from cryptography.hazmat.primitives import serialization

    raw: bytes = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw


def sign_export(data: bytes, private_key: Any, *, key_id: str | None = None) -> dict[str, Any]:
    algorithm, standard, limitation = _algorithm_of(private_key)
    digest = hashlib.sha256(data).hexdigest()
    signature = private_key.sign(_message(digest, len(data)))
    return {
        "format": FORMAT,
        "algorithm": algorithm,
        "standard": standard,
        "signed_sha256": digest,
        "signed_bytes": len(data),
        "key_id": key_id,
        "public_key": _b64(_public_bytes(private_key)),
        "signature": _b64(signature),
        "limitation": limitation,
    }


def verify_export(data: bytes, envelope: dict[str, Any]) -> bool:
    """Recomputes the digest and length from `data`; False on any mismatch or
    malformed envelope - never raises on hostile input."""
    try:
        if envelope.get("format") != FORMAT:
            return False
        digest = hashlib.sha256(data).hexdigest()
        if digest != envelope["signed_sha256"] or len(data) != envelope["signed_bytes"]:
            return False
        public_raw = base64.b64decode(envelope["public_key"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        message = _message(digest, len(data))
        algorithm = envelope["algorithm"]
        if algorithm == "ML-DSA-65":
            from cryptography.hazmat.primitives.asymmetric import mldsa

            mldsa.MLDSA65PublicKey.from_public_bytes(public_raw).verify(signature, message)
        elif algorithm == "Ed25519":
            from cryptography.hazmat.primitives.asymmetric import ed25519

            ed25519.Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        else:
            return False
        return True
    except Exception:  # noqa: BLE001 - any failure on a hostile envelope means "not verified"
        return False
