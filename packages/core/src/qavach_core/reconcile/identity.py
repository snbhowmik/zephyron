"""ARCH.md §6.1 — asset_identity(): the merge key. T-020.

Certificates and keys are instances (identity is the artefact itself, or
the CA's SPKI hash per A-7); algorithms and protocols are classes
(identity is a hash of the canonical core attributes).

`IdentityClaim` is deliberately NOT the same type as `normalize.cbom.
NormalisedClaim` (T-014): computing `is_ca`/`spki_sha256`/
`sha256_fingerprint` for a real certificate needs actual X.509 parsing
(the `cryptography` library, real I/O) — checked directly against the
vendored 1.7 schema while building this: `certificateProperties` has no
first-class SPKI/is-CA field at all, only a generic `fingerprint` (hash
object) and an optional `certificateExtensions` array that may or may not
carry `basicConstraints`. Extracting these reliably is collector-layer
work (`ARCH.md §2.2`'s `tls.store`, which has real `cryptography` access),
not something this zero-I/O function can derive from a bare CDX document.
Whatever produces an `IdentityClaim` is responsible for having already
parsed the certificate/key; this function only computes the merge key
from already-extracted facts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from qavach_core.model.enums import AssetType
from qavach_core.model.identity import AssetIdentity, IdentityKind


@dataclass(frozen=True, slots=True)
class IdentityClaim:
    asset_type: AssetType
    is_ca: bool = False
    spki_sha256: str | None = None
    sha256_fingerprint: str | None = None
    material_ref: str | None = None
    algorithm_family: str | None = None
    parameter_set: str | None = None
    curve: str | None = None
    primitive: str | None = None
    oid: str | None = None


def _canonical_json(data: Mapping[str, object]) -> str:
    """Deterministic serialisation for the identity hash (NFR-09 —
    scoring, and therefore identity, must be reproducible across runs and
    machines): sorted keys, no whitespace ambiguity."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def asset_identity(claim: IdentityClaim) -> AssetIdentity:
    if claim.asset_type is AssetType.CERTIFICATE:
        # A-7: a CA's identity is its SPKI hash (a reissued CA with the
        # same key is the same risk asset); an end-entity cert's identity
        # is its own fingerprint (an instance, not a class).
        if claim.is_ca and claim.spki_sha256:
            return AssetIdentity(kind=IdentityKind.CA_KEY, key=claim.spki_sha256)
        if claim.sha256_fingerprint is None:
            raise ValueError(
                "certificate IdentityClaim needs sha256_fingerprint "
                "(or is_ca=True with spki_sha256 for a CA)"
            )
        return AssetIdentity(kind=IdentityKind.CERT, key=claim.sha256_fingerprint)

    if claim.asset_type is AssetType.RELATED_MATERIAL:
        key = claim.spki_sha256 or claim.material_ref
        if key is None:
            raise ValueError(
                "related-crypto-material IdentityClaim needs spki_sha256 or material_ref"
            )
        return AssetIdentity(kind=IdentityKind.KEY, key=key)

    # ALGORITHM and PROTOCOL are classes, not instances (ARCH.md §6.1): the
    # same algorithm in ten files is one asset with ten occurrences.
    canonical = {
        "family": claim.algorithm_family,
        "params": claim.parameter_set,
        "curve": claim.curve,  # canonicalised upstream — resolve_curve (T-012/T-015c)
        "primitive": claim.primitive,
        "oid": claim.oid,
    }
    digest = hashlib.sha256(_canonical_json(canonical).encode()).hexdigest()
    return AssetIdentity(kind=IdentityKind.ALGO, key=digest)
