"""QAVACH domain model — ARCH.md §4. Pure dataclasses, zero I/O.

T-010 scope note: CLAUDE.md §3's repo-layout comment names this package's
contents as "CryptoAsset, Occurrence, Finding, Evidence, MigrationUnit" —
shorthand for the module's purpose, not a literal class list. `Finding` is
FindingClass (an attribute of CryptoAsset, not a separate type); `Evidence`
is Occurrence; `MigrationUnit` belongs to the roadmap layer (ARCH.md §9.1)
and is built in Phase 7 (T-084), not here.
"""

from __future__ import annotations

from qavach_core.model.asset import CryptoAsset, Occurrence
from qavach_core.model.dispute import AttributeClaim, Dispute
from qavach_core.model.enums import (
    AssetType,
    ConfidenceTier,
    CryptoFunction,
    FindingClass,
    MigrationAuthority,
)
from qavach_core.model.identity import AssetIdentity, IdentityKind
from qavach_core.model.locus import (
    CloudLocus,
    ContainerLocus,
    DependencyLocus,
    FileLocus,
    HostLocus,
    HsmLocus,
    Locus,
    NetworkLocus,
    RuntimeLocus,
    SourceLocus,
    locus_from_dict,
    locus_to_dict,
    locus_type_name,
)
from qavach_core.model.system import DataClass, System

__all__ = [
    "AssetIdentity",
    "AssetType",
    "AttributeClaim",
    "CloudLocus",
    "ConfidenceTier",
    "ContainerLocus",
    "CryptoAsset",
    "CryptoFunction",
    "DataClass",
    "DependencyLocus",
    "Dispute",
    "FileLocus",
    "FindingClass",
    "HostLocus",
    "HsmLocus",
    "IdentityKind",
    "Locus",
    "MigrationAuthority",
    "NetworkLocus",
    "Occurrence",
    "RuntimeLocus",
    "SourceLocus",
    "System",
    "locus_from_dict",
    "locus_to_dict",
    "locus_type_name",
]
