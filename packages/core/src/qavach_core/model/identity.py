"""ARCH.md §6.1 — the merge key. Certificates and keys are instances
(identity is the artefact itself, or the CA's SPKI hash per A-7); algorithms
and protocols are classes (identity is a hash of the canonical core
attributes). Computing an AssetIdentity from a claim is asset_identity()'s
job (T-020) — this module only defines the value's shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class IdentityKind(StrEnum):
    """ARCH.md §6.1."""

    ALGO = "algo"
    CERT = "cert"
    CA_KEY = "ca-key"
    KEY = "key"


@dataclass(frozen=True, slots=True)
class AssetIdentity:
    kind: IdentityKind
    key: str
