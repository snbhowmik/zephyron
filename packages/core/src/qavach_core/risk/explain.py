"""Explanation objects. T-067 / FR-360.

Every score carries the record of how it was reached: the inputs it saw, the
formula, and each policy value it used *with that value's citation*. The
explanation is data, not prose generated after the fact, so the same result
always serialises to the same bytes (no LLM anywhere - CLAUDE.md 7) and the UI
drill-down and the exports read one structure.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from qavach_core.policy import Cited


@dataclass(frozen=True, slots=True)
class PolicyRef:
    path: str
    value: Any
    basis: str

    @staticmethod
    def of(cited: Cited) -> PolicyRef:
        fields = dict(cited.fields)
        value = fields["value"] if set(fields) == {"value"} or "value" in fields else fields
        return PolicyRef(path=cited.path, value=value, basis=cited.basis)


@dataclass(frozen=True, slots=True)
class Explanation:
    name: str
    formula: str
    inputs: Mapping[str, Any]
    policy: tuple[PolicyRef, ...]
    steps: tuple[str, ...] = ()
    heuristic: bool = False
    """True when the score rests on planning heuristics (Y, EV thresholds).
    Surfaces must label it so (ARCH.md 7.4)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "formula": self.formula,
            "inputs": dict(self.inputs),
            "policy": [{"path": p.path, "value": p.value, "basis": p.basis} for p in self.policy],
            "steps": list(self.steps),
            "heuristic": self.heuristic,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def refs(cited: Iterable[Cited]) -> tuple[PolicyRef, ...]:
    """De-duplicated by path and sorted, so the order in which a function
    happened to consult policy never changes the bytes."""
    unique = {c.path: PolicyRef.of(c) for c in cited}
    return tuple(unique[path] for path in sorted(unique))
