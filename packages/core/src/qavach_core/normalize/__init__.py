"""CycloneDX canonicalisation and Cryptography Registry lookup — ARCH.md
§5. T-012 (algorithm resolution) is implemented; CycloneDX 1.4-1.7 → 1.7
version normalisation (T-014) is not yet built.
"""

from __future__ import annotations

from qavach_core.normalize.aliases import AliasTable, AliasTarget
from qavach_core.normalize.cbom import SUPPORTED_SPEC_VERSIONS, NormalisedClaim, normalise_bom
from qavach_core.normalize.quality import (
    PLAUSIBLE_MODULUS_BITS,
    DataQualityIssue,
    check_filename_shaped_name,
    check_modulus_plausibility,
)
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
    "PLAUSIBLE_MODULUS_BITS",
    "SUPPORTED_SPEC_VERSIONS",
    "AlgorithmFamilyDef",
    "AliasTable",
    "AliasTarget",
    "CryptographyRegistry",
    "CurveDef",
    "DataQualityIssue",
    "NormalisedClaim",
    "RawAlgorithmClaim",
    "ResolvedAlgorithm",
    "ResolvedCurve",
    "UnresolvedAlgorithm",
    "UnresolvedCurve",
    "check_filename_shaped_name",
    "check_modulus_plausibility",
    "normalise_bom",
    "resolve_algorithm",
    "resolve_curve",
]
