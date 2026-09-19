"""Scan-to-scan drift (T-109). Pure: two lists of register entries in, a diff out.

An entry is one (asset, system); its key is `(bom_ref, system_id)`. Because an
asset's `bom_ref` is derived from its resolved identity (OQ-18), the same
algorithm in two scans has the same key, so this is a set difference plus a field
comparison - no fuzzy matching.

The direction of a change is judged by the finding classes and bands, never by a
score, and **I8 holds here too**: movement into or out of `unknown` /
`coverage-gap` is reported as a *coverage* change, never as an improvement. An
asset that vanished because a collector did not run is not a fix; callers pass
`comparable=False` context and the summary says so instead of celebrating.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

Direction = Literal["worsened", "improved", "coverage", "changed"]

_BAND_RANK = {"not-applicable": 0, "planned": 1, "imminent": 2, "overdue": 3}
_RISKY_CLASSES = frozenset({"quantum-vulnerable", "classical-weak"})
_COVERAGE = frozenset({"unknown", "coverage-gap"})
_TRACKED = ("finding_class", "band", "outcome", "migration_authority", "disputed")


def _key(entry: Mapping[str, Any]) -> tuple[str, str]:
    return entry["bom_ref"], entry.get("system_id") or ""


def _is_risky(entry: Mapping[str, Any]) -> bool:
    return entry["finding_class"] in _RISKY_CLASSES or entry["band"] in ("overdue", "imminent")


def _direction(before: Mapping[str, Any], after: Mapping[str, Any]) -> Direction:
    if (
        before["finding_class"] in _COVERAGE
        or after["finding_class"] in _COVERAGE
        or before["band"] == "coverage-gap"
        or after["band"] == "coverage-gap"
    ):
        return "coverage"
    b_rank, a_rank = _BAND_RANK.get(before["band"], 0), _BAND_RANK.get(after["band"], 0)
    b_risky = before["finding_class"] in _RISKY_CLASSES
    a_risky = after["finding_class"] in _RISKY_CLASSES
    if a_rank > b_rank or (a_risky and not b_risky):
        return "worsened"
    if a_rank < b_rank or (b_risky and not a_risky):
        return "improved"
    return "changed"


@dataclass(frozen=True, slots=True)
class EntryChange:
    bom_ref: str
    system_id: str
    direction: Direction
    fields: Mapping[str, tuple[Any, Any]]


@dataclass(frozen=True, slots=True)
class Drift:
    added: tuple[Mapping[str, Any], ...]
    removed: tuple[Mapping[str, Any], ...]
    changed: tuple[EntryChange, ...]
    unchanged: int

    def summary(self) -> dict[str, int]:
        directions = [c.direction for c in self.changed]
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "unchanged": self.unchanged,
            "added_risky": sum(1 for e in self.added if _is_risky(e)),
            "added_coverage_failures": sum(
                1 for e in self.added if e["finding_class"] in _COVERAGE
            ),
            "removed_risky": sum(1 for e in self.removed if _is_risky(e)),
            "worsened": directions.count("worsened"),
            "improved": directions.count("improved"),
            "coverage_changes": directions.count("coverage"),
        }


def diff_entries(before: Iterable[Mapping[str, Any]], after: Iterable[Mapping[str, Any]]) -> Drift:
    old = {_key(e): e for e in before}
    new = {_key(e): e for e in after}
    changed: list[EntryChange] = []
    unchanged = 0
    for key in sorted(old.keys() & new.keys()):
        b, a = old[key], new[key]
        fields = {f: (b.get(f), a.get(f)) for f in _TRACKED if b.get(f) != a.get(f)}
        if fields:
            changed.append(EntryChange(key[0], key[1], _direction(b, a), fields))
        else:
            unchanged += 1
    return Drift(
        added=tuple(new[k] for k in sorted(new.keys() - old.keys())),
        removed=tuple(old[k] for k in sorted(old.keys() - new.keys())),
        changed=tuple(changed),
        unchanged=unchanged,
    )
