"""ARCH.md §7.1 — the four finding classes (invariant I1, CLAUDE.md §2).
Table-driven from `config/knowledge/classification_rules.yaml` (T-015) —
never hardcoded branches, so the rule set stays auditable against ARCH.md
§7.1's prose by inspection, not by trusting this file blindly.

`packages/core` has zero I/O: `ClassificationRules.from_dict()` takes an
already-parsed dict, never opens the YAML file itself.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from qavach_core.model.enums import FindingClass


@dataclass(frozen=True, slots=True)
class ClassificationRules:
    classical_weak_unconditional: frozenset[str]
    quantum_vulnerable_families: frozenset[str]
    classical_weak_key_size_threshold: Mapping[str, int]
    grover_affected: frozenset[tuple[str, str]]  # (family, parameter_set)
    quantum_safe_families: frozenset[str]
    quantum_safe_symmetric_threshold: Mapping[str, int]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> ClassificationRules:
        return ClassificationRules(
            classical_weak_unconditional=frozenset(
                data.get("classical_weak_unconditional_families", [])
            ),
            quantum_vulnerable_families=frozenset(data.get("quantum_vulnerable_families", [])),
            classical_weak_key_size_threshold=dict(
                data.get("classical_weak_key_size_threshold", {})
            ),
            grover_affected=frozenset(
                (e["family"], e["parameter_set"]) for e in data.get("grover_affected", [])
            ),
            quantum_safe_families=frozenset(data.get("quantum_safe_families", [])),
            quantum_safe_symmetric_threshold=dict(data.get("quantum_safe_symmetric_threshold", {})),
        )


@dataclass(frozen=True, slots=True)
class Classification:
    finding_class: FindingClass
    also_quantum_vulnerable: bool = False
    """ARCH.md §7.1: an asset may be simultaneously CLASSICAL_WEAK and
    quantum-vulnerable (RSA-1024 is both). The more urgent class
    (classical — the attack works today) is `finding_class`; this flag is
    what keeps it in the PQC programme's scope too."""


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def classify(
    family: str, parameter_set: str | None, *, rules: ClassificationRules
) -> Classification:
    """Never call this on an unresolved algorithm — an asset whose family
    couldn't even be resolved (`resolve_algorithm` returned
    `UnresolvedAlgorithm`) is `FindingClass.UNKNOWN` by construction of
    that failure, not by reaching this function at all (invariant I8)."""
    is_quantum_vulnerable = family in rules.quantum_vulnerable_families

    if family in rules.classical_weak_unconditional:
        return Classification(
            FindingClass.CLASSICAL_WEAK, also_quantum_vulnerable=is_quantum_vulnerable
        )

    threshold = rules.classical_weak_key_size_threshold.get(family)
    size = _as_int(parameter_set)
    if threshold is not None and size is not None and size < threshold:
        return Classification(
            FindingClass.CLASSICAL_WEAK, also_quantum_vulnerable=is_quantum_vulnerable
        )

    if is_quantum_vulnerable:
        return Classification(FindingClass.QUANTUM_VULNERABLE)

    if (family, parameter_set) in rules.grover_affected:
        return Classification(FindingClass.GROVER_AFFECTED)

    if family in rules.quantum_safe_families:
        return Classification(FindingClass.QUANTUM_SAFE)

    safe_threshold = rules.quantum_safe_symmetric_threshold.get(family)
    if safe_threshold is not None and size is not None and size >= safe_threshold:
        return Classification(FindingClass.QUANTUM_SAFE)

    return Classification(FindingClass.UNKNOWN)


# --- Invariant I8 (CLAUDE.md §2), T-015a ---
#
# "An unclassified asset must never contribute to a 'safe' count." There is
# no aggregation/UI layer yet to enforce this against (that's Phase 9), so
# this is the foundational contract those layers must build on: a semantic
# token per FindingClass (never a literal colour — that is the frontend's
# job) and an aggregation helper that keeps every class in its own bucket
# by construction, so folding UNKNOWN into a safe count would require
# actively rewriting this function, not accidentally reusing it.

# Semantic tokens, not literal colours (CLAUDE.md §7's finding-class visual
# language requirement is a frontend concern, T-107) — but the contract
# that UNKNOWN's token is never the same as QUANTUM_SAFE's, and never
# reads as safe, is a domain invariant that belongs here.
FINDING_CLASS_TOKEN: Mapping[FindingClass, str] = {
    FindingClass.QUANTUM_VULNERABLE: "critical",
    FindingClass.CLASSICAL_WEAK: "critical",
    FindingClass.GROVER_AFFECTED: "informational",
    FindingClass.QUANTUM_SAFE: "safe",
    FindingClass.UNKNOWN: "coverage-gap",
}


def is_safe_finding_class(finding_class: FindingClass) -> bool:
    """Only QUANTUM_SAFE is "safe". GROVER_AFFECTED is informational, not
    safe; UNKNOWN is a coverage failure, never safe (invariant I8)."""
    return finding_class == FindingClass.QUANTUM_SAFE


def aggregate_by_finding_class(
    finding_classes: Iterable[FindingClass],
) -> dict[FindingClass, int]:
    """Every FindingClass gets its own bucket, always — including one with
    a zero count — so UNKNOWN is never silently absent from an aggregate
    the way a competitor's dashboard renders it as a green bar instead of
    reporting it as a coverage failure (IDEATION.md §2.2c)."""
    counts: dict[FindingClass, int] = dict.fromkeys(FindingClass, 0)
    for fc in finding_classes:
        counts[fc] += 1
    return counts
