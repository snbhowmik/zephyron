"""Collector protocol implementations — ARCH.md §2. One module per source."""

from __future__ import annotations

from qavach_collectors.base import (
    Collector,
    CollectorError,
    CollectorRegistry,
    CollectorResult,
    DuplicateCollectorError,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)

__all__ = [
    "Collector",
    "CollectorError",
    "CollectorRegistry",
    "CollectorResult",
    "DuplicateCollectorError",
    "RawClaim",
    "RawFormat",
    "RunContext",
    "Target",
    "TargetType",
    "ToolIdentity",
]
