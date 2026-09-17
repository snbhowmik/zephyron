"""ARCH.md §4 — System, the business unit of migration. Assets are what
scanners find; Systems are what humans migrate, budget for and own."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DataClass(StrEnum):
    """# QAVACH-OPEN: MODEL-02 (NOTE.md §6)

    ARCH.md §4 and PRD.md FR-251 both name `data_classification` as a
    required System field but neither enumerates its levels. This is the
    smallest defensible taxonomy — the four tiers common to most
    enterprise data-classification schemes — not a citation-backed
    QAVACH decision. Revisit once a real customer's own taxonomy (or a
    regulatory one, e.g. an RBI/SEBI data-classification circular) is
    known; FR-252's retention-inference table (System.retention_inferred)
    will need to key off whatever this becomes.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass(frozen=True, slots=True)
class System:
    id: str
    name: str
    owner: str
    criticality: int  # 1..5 — ARCH.md §4
    data_classification: DataClass
    retention_years: float
    retention_inferred: bool
    internet_facing: bool
    regulatory_regimes: frozenset[str]
    depends_on: frozenset[str]

    def __post_init__(self) -> None:
        if not 1 <= self.criticality <= 5:
            raise ValueError(f"System.criticality must be 1..5, got {self.criticality}")
        if self.retention_years < 0:
            raise ValueError(f"System.retention_years must be >= 0, got {self.retention_years}")
