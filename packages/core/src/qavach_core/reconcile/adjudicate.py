"""ARCH.md §6.4 — an operator's resolution of a dispute, applied on re-merge.
T-025.

**Pure.** No I/O: this defines the record, its (de)serialisation and the
function that applies a set of records to fresh merge results. Persisting the
records is the storage layer's job (`packages/storage`, not yet built); what
this module fixes is *what must be true when they come back*.

**What "survives re-scan" means.** A dispute's identity is `(asset identity,
attribute)`, and the asset identity is a content hash, so it is stable across
scans. An adjudication is a ruling on one specific disagreement: it records
which values were in dispute when the operator ruled (`reviewed_values`).
On the next merge it is applied only if it still answers the question:

* the same (or a narrower) set of values is still in conflict, and the value
  the operator chose is still among them -> **applied**: the dispute is marked
  resolved, the concluded attribute becomes the operator's choice, and *both
  claim records are kept* (I4 — the disagreement is not deleted, it is ruled on);
* a value the operator never reviewed has appeared -> **reopened**: new
  evidence, so the ruling no longer covers the disagreement;
* the chosen value is no longer reported by any tool -> **reopened**: the
  code changed under the ruling;
* the dispute or the asset is gone -> **orphaned**: kept for the caller, never
  silently dropped and never applied.

Nothing here ever discards an adjudication. Every input record ends up in
exactly one of `applied`, `reopened` or `orphaned` (or `superseded` by a later
ruling on the same dispute), so a caller can tell an operator *why* a ruling
stopped applying.

The chosen value must be one a tool actually reported. An operator asserting a
value no tool observed would make the concluded attribute unsupported by any
evidence; that is a different feature (a manual override) and is not built.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from qavach_core.model.dispute import Dispute
from qavach_core.model.enums import ConfidenceTier
from qavach_core.model.identity import AssetIdentity, IdentityKind
from qavach_core.reconcile.merge import ConcludedAttribute, MergeResult

ADJUDICABLE_ATTRIBUTES = frozenset({"mode", "padding"})
ADJUDICATION_SOURCE = "adjudication"


@dataclass(frozen=True, slots=True)
class Adjudication:
    identity: AssetIdentity
    attribute: str
    value: str
    reviewed_values: frozenset[str]
    adjudicated_by: str
    adjudicated_at: datetime
    reason: str

    def __post_init__(self) -> None:
        if self.attribute not in ADJUDICABLE_ATTRIBUTES:
            raise ValueError(f"attribute {self.attribute!r} cannot be adjudicated")
        if not self.value.strip():
            raise ValueError("an adjudication needs a non-empty value")
        if self.value not in self.reviewed_values:
            raise ValueError("the adjudicated value must be one of the reviewed values")
        if not self.adjudicated_by.strip():
            raise ValueError("an adjudication must record who made it")
        if not self.reason.strip():
            raise ValueError("an adjudication must record a reason")
        if self.adjudicated_at.tzinfo is None:
            raise ValueError("adjudicated_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class Unapplied:
    adjudication: Adjudication
    reason: str


@dataclass(frozen=True, slots=True)
class AdjudicationOutcome:
    results: tuple[MergeResult, ...]
    applied: tuple[Adjudication, ...]
    reopened: tuple[Unapplied, ...]
    orphaned: tuple[Unapplied, ...]
    superseded: tuple[Adjudication, ...]


def _conflicting_values(dispute: Dispute) -> frozenset[str]:
    return frozenset(c.value for c in dispute.claims if c.value is not None)


def adjudicate(
    result: MergeResult,
    attribute: str,
    value: str,
    *,
    by: str,
    at: datetime,
    reason: str,
) -> Adjudication:
    """Builds the record for an operator's ruling on `result`'s open dispute
    over `attribute`. Refuses a ruling on a dispute that does not exist, is
    already resolved, or whose claims never included `value`."""
    dispute = next((d for d in result.unresolved_disputes if d.attribute == attribute), None)
    if dispute is None:
        raise ValueError(f"{attribute!r} has no unresolved dispute on this asset")
    values = _conflicting_values(dispute)
    if value not in values:
        raise ValueError(
            f"{value!r} was not reported by any tool; disputed values are {sorted(values)}"
        )
    return Adjudication(
        identity=result.identity,
        attribute=attribute,
        value=value,
        reviewed_values=values,
        adjudicated_by=by,
        adjudicated_at=at,
        reason=reason,
    )


def _latest_per_dispute(
    adjudications: Iterable[Adjudication],
) -> tuple[dict[tuple[AssetIdentity, str], Adjudication], list[Adjudication]]:
    latest: dict[tuple[AssetIdentity, str], Adjudication] = {}
    superseded: list[Adjudication] = []
    for adj in adjudications:
        key = (adj.identity, adj.attribute)
        current = latest.get(key)
        if current is None:
            latest[key] = adj
        elif adj.adjudicated_at == current.adjudicated_at and adj.value != current.value:
            raise ValueError(
                f"two different rulings for {key} carry the same timestamp; cannot order them"
            )
        elif adj.adjudicated_at > current.adjudicated_at:
            superseded.append(current)
            latest[key] = adj
        else:
            superseded.append(adj)
    return latest, superseded


def _best_confidence(dispute: Dispute, value: str) -> ConfidenceTier:
    return max(c.confidence for c in dispute.claims if c.value == value)


def _apply_one(result: MergeResult, adj: Adjudication) -> MergeResult:
    disputes: list[Dispute] = []
    concluded: ConcludedAttribute | None = None
    for dispute in result.disputes:
        if dispute.attribute == adj.attribute and not dispute.resolved:
            concluded = ConcludedAttribute(
                value=adj.value,
                confidence=_best_confidence(dispute, adj.value),
                source_collector=ADJUDICATION_SOURCE,
            )
            dispute = replace(
                dispute,
                adjudicated_value=adj.value,
                adjudicated_by=adj.adjudicated_by,
                adjudicated_at=adj.adjudicated_at,
                adjudication_reason=adj.reason,
            )
        disputes.append(dispute)
    updated = replace(result, disputes=tuple(disputes))
    updated = replace(updated, disputed=bool(updated.unresolved_disputes))
    if concluded is not None and adj.attribute == "mode":
        updated = replace(updated, concluded_mode=concluded)
    elif concluded is not None:
        updated = replace(updated, concluded_padding=concluded)
    return updated


def apply_adjudications(
    results: Iterable[MergeResult], adjudications: Iterable[Adjudication]
) -> AdjudicationOutcome:
    latest, superseded = _latest_per_dispute(adjudications)
    by_identity = {r.identity: r for r in results}
    order = list(by_identity)
    applied: list[Adjudication] = []
    reopened: list[Unapplied] = []
    orphaned: list[Unapplied] = []

    for (identity, attribute), adj in latest.items():
        result = by_identity.get(identity)
        if result is None:
            orphaned.append(Unapplied(adj, "the asset is no longer present"))
            continue
        dispute = next((d for d in result.unresolved_disputes if d.attribute == attribute), None)
        if dispute is None:
            orphaned.append(Unapplied(adj, "the tools no longer disagree about this attribute"))
            continue
        current = _conflicting_values(dispute)
        unreviewed = current - adj.reviewed_values
        if unreviewed:
            reopened.append(
                Unapplied(
                    adj,
                    f"new conflicting value(s) appeared after the ruling: {sorted(unreviewed)}",
                )
            )
            continue
        if adj.value not in current:
            reopened.append(
                Unapplied(adj, f"the chosen value {adj.value!r} is no longer reported by any tool")
            )
            continue
        by_identity[identity] = _apply_one(result, adj)
        applied.append(adj)

    return AdjudicationOutcome(
        results=tuple(by_identity[i] for i in order),
        applied=tuple(applied),
        reopened=tuple(reopened),
        orphaned=tuple(orphaned),
        superseded=tuple(superseded),
    )


def adjudication_to_dict(adj: Adjudication) -> dict[str, Any]:
    return {
        "identity": {"kind": adj.identity.kind.value, "key": adj.identity.key},
        "attribute": adj.attribute,
        "value": adj.value,
        "reviewed_values": sorted(adj.reviewed_values),
        "adjudicated_by": adj.adjudicated_by,
        "adjudicated_at": adj.adjudicated_at.isoformat(),
        "reason": adj.reason,
    }


def adjudication_from_dict(data: Mapping[str, Any]) -> Adjudication:
    identity = data["identity"]
    return Adjudication(
        identity=AssetIdentity(kind=IdentityKind(identity["kind"]), key=str(identity["key"])),
        attribute=str(data["attribute"]),
        value=str(data["value"]),
        reviewed_values=frozenset(str(v) for v in data["reviewed_values"]),
        adjudicated_by=str(data["adjudicated_by"]),
        adjudicated_at=datetime.fromisoformat(str(data["adjudicated_at"])),
        reason=str(data["reason"]),
    )
