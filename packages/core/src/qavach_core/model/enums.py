"""ARCH.md §4 — the enums the rest of the domain model is built from."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class AssetType(StrEnum):
    """CycloneDX cryptoProperties.assetType — ARCH.md §4."""

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-crypto-material"


class CryptoFunction(StrEnum):
    """Drives Mosca's per-function-class shelf life — ARCH.md §7.2, invariant I2."""

    KEY_ENCAPSULATION = "key-encapsulation"
    KEY_AGREEMENT = "key-agreement"
    ENCRYPTION = "encryption"
    SIGNATURE = "signature"
    MAC = "mac"
    HASH = "hash"
    KDF = "kdf"
    DRBG = "drbg"


class FindingClass(StrEnum):
    """Invariant I1 (CLAUDE.md §2) — every finding is exactly one of these.

    GROVER_AFFECTED is informational and must never be rendered with the
    same severity as QUANTUM_VULNERABLE. UNKNOWN is a coverage failure, not
    a risk verdict (invariant I8) — it must never contribute to a "safe"
    count anywhere this enum is aggregated.
    """

    QUANTUM_VULNERABLE = "quantum-vulnerable"
    CLASSICAL_WEAK = "classical-weak"
    GROVER_AFFECTED = "grover-affected"
    QUANTUM_SAFE = "quantum-safe"
    UNKNOWN = "unknown"


class MigrationAuthority(StrEnum):
    """Who can actually change this asset — ARCH.md §4.1, invariant I9.

    Only SELF units may ever enter the migration roadmap DAG.
    EXTERNAL_TRUST_ANCHOR is never ranked, never alerted on, never
    scheduled — inventoried for completeness only.
    """

    SELF = "self"
    VENDOR = "vendor"
    EXTERNAL_TRUST_ANCHOR = "external-trust-anchor"
    REGULATOR_GATED = "regulator-gated"
    UNKNOWN = "unknown"


class ConfidenceTier(IntEnum):
    """Higher wins — ARCH.md §4, §6.4.

    Precedence is applied per attribute class, not per whole claim (A-5):
    a source that does not observe an attribute contributes nothing to it
    and cannot outrank a source that does ("silence is not a claim").
    """

    RUNTIME = 100
    ARTEFACT = 90
    ATTESTED = 80
    DEPENDENCY = 60
    AST = 50
    PATTERN = 30
    HEURISTIC = 10
