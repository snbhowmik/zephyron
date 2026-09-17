"""ARCH.md §4/§7.2 — map a CDX-vocabulary `primitive` (from
`resolve_algorithm`'s output, T-012) to QAVACH's `CryptoFunction`, which
drives Mosca (invariant I2). T-016.

CDX's primitive vocabulary (`cryptography-defs.schema.json`) and
`CryptoFunction` are not the same taxonomy — ARCH.md never gives an
explicit cross-reference, so this mapping is QAVACH's own engineering
judgement, not lifted from a published table:

  - `key-wrap` -> ENCRYPTION: wrapping is a symmetric-encryption operation
    performed on key material, not a distinct primitive class of its own.
  - `xof` -> HASH: an extendable-output function (e.g. SHAKE) is a
    hash-family primitive for QAVACH's purposes.
  - `other` has no mapping and never will by default — a primitive CDX
    itself couldn't classify is not something QAVACH should guess at
    silently either.
"""

from __future__ import annotations

from qavach_core.model.enums import CryptoFunction

_PRIMITIVE_TO_FUNCTION: dict[str, CryptoFunction] = {
    "kem": CryptoFunction.KEY_ENCAPSULATION,
    "key-agree": CryptoFunction.KEY_AGREEMENT,
    "pke": CryptoFunction.ENCRYPTION,
    "block-cipher": CryptoFunction.ENCRYPTION,
    "ae": CryptoFunction.ENCRYPTION,
    "stream-cipher": CryptoFunction.ENCRYPTION,
    "key-wrap": CryptoFunction.ENCRYPTION,
    "signature": CryptoFunction.SIGNATURE,
    "mac": CryptoFunction.MAC,
    "hash": CryptoFunction.HASH,
    "xof": CryptoFunction.HASH,
    "kdf": CryptoFunction.KDF,
    "drbg": CryptoFunction.DRBG,
}


def classify_function(primitive: str | None) -> CryptoFunction | None:
    """None in, None out — an unresolved or unmapped primitive (e.g. CDX's
    own "other") is never silently forced into a CryptoFunction bucket."""
    if primitive is None:
        return None
    return _PRIMITIVE_TO_FUNCTION.get(primitive)
