"""Concrete export signers. T-097.

Key custody lives at the API layer, not in `packages/core` (which may import only
the stdlib). ML-DSA-65 (FIPS 204) is preferred - `cryptography` 50 provides it -
because a signature on an inventory of quantum-vulnerable cryptography should not
itself be quantum-vulnerable. If a build lacks it, `generate_signer` falls back to
Ed25519 and the signer's `limitation` says so; the envelope carries that text.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ED25519_LIMITATION = (
    "Signed with Ed25519, which is quantum-vulnerable: ML-DSA-65 was not available in "
    "this build. Treat this signature as authenticating today, not against a future "
    "cryptographically relevant quantum computer."
)


class MlDsa65Signer:
    algorithm = "ML-DSA-65"
    standard = "FIPS 204"
    limitation: str | None = None

    def __init__(self, private_key: Any) -> None:
        self._key = private_key

    def public_key(self) -> bytes:
        return bytes(self._key.public_key().public_bytes_raw())

    def sign(self, message: bytes) -> bytes:
        return bytes(self._key.sign(message))


class Ed25519Signer:
    algorithm = "Ed25519"
    standard = "RFC 8032"
    limitation: str | None = ED25519_LIMITATION

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        self._key = private_key

    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def generate_signer(prefer: str = "ML-DSA-65") -> MlDsa65Signer | Ed25519Signer:
    if prefer == "ML-DSA-65":
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa

            return MlDsa65Signer(mldsa.MLDSA65PrivateKey.generate())
        except (ImportError, AttributeError, UnsupportedAlgorithm):
            pass
    return Ed25519Signer(ed25519.Ed25519PrivateKey.generate())


def verify(algorithm: str, public_key: bytes, signature: bytes, message: bytes) -> bool:
    """The `Verify` callable for `qavach_core.export.verify_export`."""
    try:
        if algorithm == "ML-DSA-65":
            from cryptography.hazmat.primitives.asymmetric import mldsa

            mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        elif algorithm == "Ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        return False
