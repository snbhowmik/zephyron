"""Layer 6 - recommendation (`ARCH.md §8`)."""

from __future__ import annotations

from qavach_core.recommend.engine import (
    AlternativeRef,
    Constraints,
    HybridAdvice,
    Recommendation,
    SizeCost,
    recommend,
)
from qavach_core.recommend.knowledge import (
    MAX_AGE_DAYS,
    Alternative,
    ClassicalFix,
    HybridGuidance,
    KnowledgeError,
    PerformanceRow,
    PqcKnowledge,
)

__all__ = [
    "MAX_AGE_DAYS",
    "Alternative",
    "AlternativeRef",
    "ClassicalFix",
    "Constraints",
    "HybridAdvice",
    "HybridGuidance",
    "KnowledgeError",
    "PerformanceRow",
    "PqcKnowledge",
    "Recommendation",
    "SizeCost",
    "recommend",
]
