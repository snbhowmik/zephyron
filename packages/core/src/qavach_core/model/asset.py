"""ARCH.md §4 — CryptoAsset and Occurrence, the core of the whole model.

Asset vs. occurrence is the load-bearing distinction: assets are what
scanners find (after reconciliation, exactly one per identity); occurrences
are every individual claim about that asset, retained forever (invariant
I4 — confidence is never averaged, conflicts are never silently resolved).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from qavach_core.model.certificate import CertificateFacts
from qavach_core.model.dispute import Dispute
from qavach_core.model.enums import (
    AssetType,
    ConfidenceTier,
    CryptoFunction,
    FindingClass,
    MigrationAuthority,
)
from qavach_core.model.identity import AssetIdentity
from qavach_core.model.locus import Locus


@dataclass(frozen=True, slots=True)
class Occurrence:
    locus: Locus
    collector: str
    tool_version: str
    confidence: ConfidenceTier
    detection_method: str  # CycloneDX evidence.identity method vocabulary
    raw_ref: str  # pointer into the archived raw output — ARCH.md §2.1
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class CryptoAsset:
    identity: AssetIdentity
    asset_type: AssetType
    function: CryptoFunction | None
    """`None` when the function could not be determined. Never guessed: an asset
    with no function is scored at its worst plausible reading (I8)."""
    algorithm_family: str  # canonical, from the CDX 1.7 Cryptography Registry
    parameter_set: str | None  # "2048", "P-256", "ML-KEM-768"
    curve: str | None  # canonical, from the CDX 1.7 curve registry
    mode: str | None  # "CBC", "GCM"
    padding: str | None  # "OAEP", "PKCS1v15"
    oid: str | None
    finding_class: FindingClass
    migration_authority: MigrationAuthority
    authority_basis: str  # the derivation rule that fired — ARCH.md §4.1
    occurrences: tuple[Occurrence, ...]
    concluded_from: ConfidenceTier
    disputed: bool
    disputes: tuple[Dispute, ...]
    certificate: CertificateFacts | None = None
    """Set for `AssetType.CERTIFICATE` only (OQ-20): role and validity, the inputs
    that make a root CA and an ephemeral leaf with the same key score differently."""

    # NOTE: there is deliberately no scalar `key_size: int` field.
    # ARCH.md §4.2 — Ed25519 has no bit-length in the RSA sense, ML-DSA-65
    # has a parameter set, not a key size. Do not add one back.

    def __post_init__(self) -> None:
        if not self.occurrences:
            raise ValueError("CryptoAsset must have at least one occurrence")
        if self.disputed and not self.disputes:
            raise ValueError("CryptoAsset.disputed=True requires at least one Dispute")
