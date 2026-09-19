"""The PQC knowledge base: alternatives, their standardisation status, hybrid
guidance and size/performance figures. T-080, T-081, T-083.

Validation happens at load, so a bad edit to the YAML cannot reach a user:

* **FR-410 guard.** An alternative whose `status` is not `final` can never have
  `usable_as_recommendation: true`. HQC (selected, not published) and FN-DSA
  (in development) therefore cannot be presented as available standards - the
  error a domain reviewer catches instantly - no matter what the file says.
* **No invented figures.** Every performance row needs a `source_url` and a
  `basis` (`spec`, `measured`, `derived`); a timing may be non-null only if the
  row names where it was measured. Unavailable figures stay `None`.
* **Verification is explicit.** `verified_on` is a date or `None`; `None`
  demands an `unverified_reason`, so "not checked" can never be mistaken for
  "checked and fine". `stale()` and `unverified()` back the CI freshness check
  (`scripts/check_knowledge_freshness.py`), which fails the build when an entry
  was last verified more than 180 days ago.

Pure: takes parsed dicts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

STATUSES = frozenset({"final", "selected-not-published", "in-development"})
BASES = frozenset({"spec", "measured", "derived"})
MAX_AGE_DAYS = 180


class KnowledgeError(ValueError):
    pass


def _as_date(value: Any, where: str) -> date | None:
    if value is None:
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise KnowledgeError(f"{where}: {value!r} is not an ISO date") from exc


def _verification(entry: Mapping[str, Any], where: str) -> tuple[date | None, str | None]:
    verified = _as_date(entry.get("verified_on"), f"{where}.verified_on")
    reason = entry.get("unverified_reason")
    if not entry.get("source_url"):
        raise KnowledgeError(f"{where}: `source_url` is required")
    if verified is None and not (isinstance(reason, str) and reason.strip()):
        raise KnowledgeError(f"{where}: `verified_on` is null, so `unverified_reason` is required")
    return verified, (str(reason) if reason else None)


@dataclass(frozen=True, slots=True)
class Alternative:
    key: str
    name: str
    family: str
    functions: frozenset[str]
    standard: str | None
    status: str
    status_date: date | None
    usable_as_recommendation: bool
    replaces: frozenset[str]
    verified_on: date | None
    unverified_reason: str | None
    source_url: str
    note: str | None

    @property
    def is_final(self) -> bool:
        return self.status == "final"


@dataclass(frozen=True, slots=True)
class ClassicalFix:
    key: str
    name: str
    replaces: frozenset[str]
    standard: str
    verified_on: date | None
    unverified_reason: str | None
    source_url: str
    note: str | None


@dataclass(frozen=True, slots=True)
class HybridGuidance:
    key: str
    position: str
    context: str
    reason: str
    recommend: str | None
    verified_on: date | None
    unverified_reason: str | None
    source_url: str


@dataclass(frozen=True, slots=True)
class PerformanceRow:
    group: str
    name: str
    source_url: str
    basis: str
    figures: Mapping[str, int | None]
    note: str | None


@dataclass(frozen=True, slots=True)
class PqcKnowledge:
    alternatives: Mapping[str, Alternative]
    classical_fixes: Mapping[str, ClassicalFix]
    hybrid: Mapping[str, HybridGuidance]
    performance: Mapping[str, PerformanceRow]
    measured_on: str | None

    @staticmethod
    def from_documents(
        alternatives_doc: Mapping[str, Any], performance_doc: Mapping[str, Any]
    ) -> PqcKnowledge:
        alternatives: dict[str, Alternative] = {}
        for key, e in alternatives_doc["alternatives"].items():
            where = f"alternatives.{key}"
            if e["status"] not in STATUSES:
                raise KnowledgeError(f"{where}: unknown status {e['status']!r}")
            usable = bool(e["usable_as_recommendation"])
            if usable and e["status"] != "final":
                raise KnowledgeError(
                    f"{where}: status {e['status']!r} cannot be usable_as_recommendation "
                    "(FR-410: a non-final algorithm is never presented as an available standard)"
                )
            verified, reason = _verification(e, where)
            alternatives[key] = Alternative(
                key=key,
                name=str(e["name"]),
                family=str(e["family"]),
                functions=frozenset(e["functions"]),
                standard=e.get("standard"),
                status=e["status"],
                status_date=_as_date(e.get("status_date"), f"{where}.status_date"),
                usable_as_recommendation=usable,
                replaces=frozenset(e.get("replaces", [])),
                verified_on=verified,
                unverified_reason=reason,
                source_url=str(e["source_url"]),
                note=e.get("note"),
            )

        fixes: dict[str, ClassicalFix] = {}
        for key, e in alternatives_doc.get("classical_fixes", {}).items():
            verified, reason = _verification(e, f"classical_fixes.{key}")
            fixes[key] = ClassicalFix(
                key=key,
                name=str(e["name"]),
                replaces=frozenset(e["replaces"]),
                standard=str(e["standard"]),
                verified_on=verified,
                unverified_reason=reason,
                source_url=str(e["source_url"]),
                note=e.get("note"),
            )

        hybrid: dict[str, HybridGuidance] = {}
        for key, e in alternatives_doc.get("hybrid_guidance", {}).items():
            verified, reason = _verification(e, f"hybrid_guidance.{key}")
            hybrid[key] = HybridGuidance(
                key=key,
                position=str(e["position"]),
                context=str(e["context"]),
                reason=str(e["reason"]),
                recommend=e.get("recommend"),
                verified_on=verified,
                unverified_reason=reason,
                source_url=str(e["source_url"]),
            )

        performance: dict[str, PerformanceRow] = {}
        for group in ("kem", "signature", "tls_hybrid_key_share"):
            for name, row in performance_doc.get(group, {}).items():
                where = f"performance.{group}.{name}"
                if not row.get("source_url"):
                    raise KnowledgeError(f"{where}: every figure needs a `source_url`")
                if row.get("basis") not in BASES:
                    raise KnowledgeError(f"{where}: `basis` must be one of {sorted(BASES)}")
                figures: dict[str, int | None] = {}
                for field, value in row.items():
                    if field.endswith(("_bytes", "_us")):
                        if value is not None and (not isinstance(value, int) or value < 0):
                            raise KnowledgeError(
                                f"{where}.{field}: must be a non-negative integer or null"
                            )
                        figures[field] = value
                if any(
                    v is not None for k, v in figures.items() if k.endswith("_us")
                ) and not row.get("measured_on"):
                    raise KnowledgeError(
                        f"{where}: a timing is present but the row does not say where it was "
                        "measured"
                    )
                performance[f"{group}.{name}"] = PerformanceRow(
                    group=group,
                    name=name,
                    source_url=str(row["source_url"]),
                    basis=str(row["basis"]),
                    figures=figures,
                    note=row.get("note"),
                )
        return PqcKnowledge(
            alternatives=alternatives,
            classical_fixes=fixes,
            hybrid=hybrid,
            performance=performance,
            measured_on=performance_doc.get("measured_on"),
        )

    def _dated(self) -> list[tuple[str, date | None]]:
        entries: list[tuple[str, date | None]] = []
        entries += [(f"alternatives.{k}", v.verified_on) for k, v in self.alternatives.items()]
        entries += [
            (f"classical_fixes.{k}", v.verified_on) for k, v in self.classical_fixes.items()
        ]
        entries += [(f"hybrid_guidance.{k}", v.verified_on) for k, v in self.hybrid.items()]
        return entries

    def stale(self, today: date, max_age_days: int = MAX_AGE_DAYS) -> list[tuple[str, int]]:
        """`(entry, age_in_days)` for every verified entry older than the limit,
        and for any verified in the future (a typo that would hide staleness)."""
        out = []
        for name, verified in self._dated():
            if verified is None:
                continue
            age = (today - verified).days
            if age > max_age_days or age < 0:
                out.append((name, age))
        return sorted(out)

    def unverified(self) -> list[str]:
        return sorted(name for name, verified in self._dated() if verified is None)
