"""ARCH.md §6.4 — per-attribute dispute records.

# QAVACH-OPEN: MODEL-01 (NOTE.md §6)
ARCH.md §6.4 describes dispute *behaviour* in prose ("disputes are recorded
per attribute: an asset can be settled on key size and disputed on
padding") but never gives an exact `Dispute` dataclass shape the way it
does for CryptoAsset/Occurrence. The shape below is the smallest
defensible design satisfying the stated constraints:

  - invariant I4: both records are retained, never averaged — so a
    Dispute holds every conflicting AttributeClaim, not just two.
  - "silence is not a claim" (A-5, ARCH.md §6.4): AttributeClaim always
    names its source and confidence, so precedence can be computed without
    a source that never observed the attribute being able to win by
    omission.
  - T-025 ("persist an operator's resolution of a dispute; it survives
    re-scan"): a Dispute can carry an adjudication, defaulting to
    unresolved.

Revisit this shape when T-023 (dispute detection) is implemented — it may
turn out a different structure is more natural once real merge code needs
to build one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from qavach_core.model.enums import ConfidenceTier
from qavach_core.model.locus import Locus


@dataclass(frozen=True, slots=True)
class AttributeClaim:
    """One source's claim about a single attribute value at one occurrence."""

    value: str | None
    source_collector: str
    confidence: ConfidenceTier
    locus: Locus


@dataclass(frozen=True, slots=True)
class Dispute:
    """Fires only when two sources disagree about the same occurrence
    (A-5) — multi-usage across different occurrences is not a dispute."""

    attribute: str
    claims: tuple[AttributeClaim, ...]
    adjudicated_value: str | None = None
    adjudicated_by: str | None = None
    adjudicated_at: datetime | None = None
    adjudication_reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.adjudicated_value is not None
