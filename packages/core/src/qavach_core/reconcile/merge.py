"""ARCH.md §6.3, §6.4 — the merge engine. T-022, T-023.

Groups already-identity-computed claims (T-020) into one record per
identity, retaining every occurrence (invariant I4 — confidence is never
averaged, conflicts are never silently resolved). For ALGO/PROTOCOL-kind
identities, the core attributes (family/parameter_set/curve/primitive/oid)
are already fixed by the identity hash itself — every claim in a group
necessarily agrees on them by construction (that is what made them group
together). The only attributes that can genuinely disagree within a group
are the usage qualifiers `mode`/`padding` (A-5), which is what this
module's precedence and dispute logic resolves.

Full `CryptoAsset` assembly (`finding_class` via `risk.classify`,
`migration_authority` via `reconcile.authority`) needs inputs this pure
merge function doesn't have (policy rules, business context) — that is a
downstream pipeline-orchestration step (Phase 6), not built here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from qavach_core.model.dispute import AttributeClaim, Dispute
from qavach_core.model.enums import ConfidenceTier
from qavach_core.model.identity import AssetIdentity
from qavach_core.model.locus import Locus


@dataclass(frozen=True, slots=True)
class OccurrenceClaim:
    """One collector's claim about one occurrence of an already-identified
    asset. Only usage qualifiers (`mode`, `padding`) are carried here for
    merging (A-5) — core/identity-bearing attributes are already fixed by
    `identity` itself and are not this module's concern."""

    identity: AssetIdentity
    locus: Locus
    collector: str
    tool_version: str
    confidence: ConfidenceTier
    detection_method: str
    raw_ref: str
    observed_at: datetime
    mode: str | None = None
    padding: str | None = None


@dataclass(frozen=True, slots=True)
class ConcludedAttribute:
    value: str | None
    confidence: ConfidenceTier
    source_collector: str


@dataclass(frozen=True, slots=True)
class MergeResult:
    identity: AssetIdentity
    occurrences: tuple[OccurrenceClaim, ...]
    concluded_mode: ConcludedAttribute | None
    concluded_padding: ConcludedAttribute | None
    concluded_from: ConfidenceTier
    """Highest ConfidenceTier among all occurrences — the asset's overall
    provenance tier. Distinct from per-attribute precedence (see
    `_usage_attribute_rank`), which governs `concluded_mode`/`padding`."""
    disputed: bool
    """True while at least one dispute is unresolved. Resolved (adjudicated)
    disputes stay in `disputes` — both records are retained (I4)."""
    disputes: tuple[Dispute, ...]

    @property
    def unresolved_disputes(self) -> tuple[Dispute, ...]:
        """What `ARCH.md §6.4`'s "scored at its worst plausible claim until
        adjudicated" applies to."""
        return tuple(d for d in self.disputes if not d.resolved)


_USAGE_OBSERVING_TIERS = frozenset({ConfidenceTier.RUNTIME, ConfidenceTier.AST})


def _usage_attribute_rank(tier: ConfidenceTier) -> tuple[int, int]:
    """ARCH.md §6.4: for usage qualifiers (mode, padding), usage-observing
    tiers (AST, RUNTIME) outrank ATTESTED, which outranks everything else
    ("declared" — DEPENDENCY/PATTERN/HEURISTIC). This is deliberately NOT
    ConfidenceTier's own "higher wins" ordering: an ATTESTED cloud KMS API
    (tier 80) does not outrank an AST claim (tier 50) for a field it never
    observed ("silence is not a claim", A-5) — a KMS API describes the key
    it holds, not the padding an application chose at call time.

    ARTEFACT is not named in ARCH.md §6.4's mode/padding row at all;
    treated conservatively as "declared" (rank 0) here since we cannot
    assume an artefact parse observed a usage qualifier ARCH.md doesn't
    document it as covering — flagged in NOTE.md §7, not silently guessed.
    """
    if tier in _USAGE_OBSERVING_TIERS:
        return (2, tier.value)
    if tier is ConfidenceTier.ATTESTED:
        return (1, tier.value)
    return (0, tier.value)


def _conclude_attribute(
    occurrences: Iterable[OccurrenceClaim], attr: str
) -> ConcludedAttribute | None:
    candidates = [o for o in occurrences if getattr(o, attr) is not None]
    if not candidates:
        return None
    best = max(candidates, key=lambda o: _usage_attribute_rank(o.confidence))
    return ConcludedAttribute(
        value=getattr(best, attr),
        confidence=best.confidence,
        source_collector=best.collector,
    )


def _detect_attribute_dispute(
    occurrences: tuple[OccurrenceClaim, ...], attr: str
) -> Dispute | None:
    """Dispute fires only when two sources disagree about the SAME
    occurrence, i.e. the same locus (ARCH.md §6.3) — a different locus
    reporting a different value is multi-usage, a true fact, not a
    dispute. Silence is not a claim (A-5): an occurrence that didn't
    report this attribute at all never participates."""
    by_locus: dict[Locus, list[OccurrenceClaim]] = defaultdict(list)
    for occ in occurrences:
        if getattr(occ, attr) is not None:
            by_locus[occ.locus].append(occ)

    conflicting: list[AttributeClaim] = []
    for locus_occurrences in by_locus.values():
        values = {getattr(o, attr) for o in locus_occurrences}
        if len(values) > 1:
            conflicting.extend(
                AttributeClaim(
                    value=getattr(o, attr),
                    source_collector=o.collector,
                    confidence=o.confidence,
                    locus=o.locus,
                )
                for o in locus_occurrences
            )

    if not conflicting:
        return None
    return Dispute(attribute=attr, claims=tuple(conflicting))


def merge(identity: AssetIdentity, occurrences: Iterable[OccurrenceClaim]) -> MergeResult:
    """Merges every claim already grouped under ONE identity — callers
    group the full claim list by identity first (`group_by_identity`) and
    call this once per group, or use `merge_all` directly."""
    occs = tuple(occurrences)
    if not occs:
        raise ValueError("merge() requires at least one occurrence")
    if any(o.identity != identity for o in occs):
        raise ValueError("all occurrences passed to merge() must share the given identity")

    disputes = tuple(
        d
        for d in (
            _detect_attribute_dispute(occs, "mode"),
            _detect_attribute_dispute(occs, "padding"),
        )
        if d is not None
    )

    return MergeResult(
        identity=identity,
        occurrences=occs,
        concluded_mode=_conclude_attribute(occs, "mode"),
        concluded_padding=_conclude_attribute(occs, "padding"),
        concluded_from=max(o.confidence for o in occs),
        disputed=bool(disputes),
        disputes=disputes,
    )


def group_by_identity(
    claims: Iterable[OccurrenceClaim],
) -> dict[AssetIdentity, list[OccurrenceClaim]]:
    groups: dict[AssetIdentity, list[OccurrenceClaim]] = defaultdict(list)
    for claim in claims:
        groups[claim.identity].append(claim)
    return dict(groups)


def merge_all(claims: Iterable[OccurrenceClaim]) -> list[MergeResult]:
    return [merge(identity, occs) for identity, occs in group_by_identity(claims).items()]
