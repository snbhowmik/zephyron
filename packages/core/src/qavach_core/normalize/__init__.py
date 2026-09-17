"""CycloneDX canonicalisation and Cryptography Registry lookup — ARCH.md
§5. T-012 (algorithm resolution) is implemented; CycloneDX 1.4-1.7 → 1.7
version normalisation (T-014) is not yet built.
"""

from __future__ import annotations

from qavach_core.normalize.aliases import AliasTable, AliasTarget
from qavach_core.normalize.registry import AlgorithmFamilyDef, CryptographyRegistry, CurveDef
from qavach_core.normalize.resolve import (
    RawAlgorithmClaim,
    ResolvedAlgorithm,
    ResolvedCurve,
    UnresolvedAlgorithm,
    UnresolvedCurve,
    resolve_algorithm,
    resolve_curve,
)

__all__ = [
    "AlgorithmFamilyDef",
    "AliasTable",
    "AliasTarget",
    "CryptographyRegistry",
    "CurveDef",
    "RawAlgorithmClaim",
    "ResolvedAlgorithm",
    "ResolvedCurve",
    "UnresolvedAlgorithm",
    "UnresolvedCurve",
    "resolve_algorithm",
    "resolve_curve",
]
