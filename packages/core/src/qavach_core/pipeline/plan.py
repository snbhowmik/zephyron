"""Scored assets -> a migration roadmap. Pure.

A migration unit is a `(System, CryptoFunction)` pair (`ARCH.md §9.1`): a system
migrates its key establishment and its signing separately. Only `SELF`
assets with an issued outcome become units (I9); a unit takes the *worst*
member: the largest `Y`, the most overdue Mosca gap, and the earliest binding
deadline. System dependencies become `protocol-peer` edges between the units of
the same function, tail = the dependency. A cycle between systems therefore
becomes a hybrid-bridge finding, never an error.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import date

from qavach_core.export.register import RegisterInput, unit_id
from qavach_core.model.enums import CryptoFunction, MigrationAuthority
from qavach_core.model.system import System
from qavach_core.roadmap import Edge, EdgeKind, MigrationUnit, Roadmap, build_roadmap


def plan_roadmap(
    items: Sequence[RegisterInput],
    systems: Iterable[System],
    *,
    as_of: date,
    capacity_per_quarter: int | None = None,
) -> tuple[Roadmap, list[MigrationUnit], list[Edge]]:
    by_system = {s.id: s for s in systems}
    accum: dict[str, dict[str, object]] = {}
    for item in items:
        score, asset = item.score, item.asset
        if (
            score.system_id is None
            or score.outcome is None
            or score.y is None
            or score.z is None
            or asset.migration_authority is not MigrationAuthority.SELF
        ):
            continue
        uid = unit_id(score.system_id, asset.function)
        current = accum.setdefault(
            uid,
            {
                "system": score.system_id,
                "function": asset.function,
                "y": 0.0,
                "deadline": score.z.z_date,
                "bound": score.z.bound_by,
                "gap": None,
            },
        )
        current["y"] = max(float(current["y"]), score.y.years)  # type: ignore[arg-type]
        if score.z.z_date < current["deadline"]:  # type: ignore[operator]
            current["deadline"], current["bound"] = score.z.z_date, score.z.bound_by
        gap = score.mosca.gap_years if score.mosca else None
        if gap is not None:
            previous = current["gap"]
            current["gap"] = gap if previous is None else max(float(previous), gap)  # type: ignore[arg-type]

    units = [
        MigrationUnit(
            id=uid,
            system_id=str(u["system"]),
            function=u["function"],  # type: ignore[arg-type]
            authority=MigrationAuthority.SELF,
            y_years=float(u["y"]),  # type: ignore[arg-type]
            deadline=u["deadline"],  # type: ignore[arg-type]
            deadline_bound_by=str(u["bound"]),
            urgency_gap_years=u["gap"],  # type: ignore[arg-type]
        )
        for uid, u in sorted(accum.items())
    ]

    edges: list[Edge] = []
    functions_by_system: dict[str, set[CryptoFunction | None]] = {}
    for u in accum.values():
        functions_by_system.setdefault(str(u["system"]), set()).add(u["function"])  # type: ignore[arg-type]
    for system in by_system.values():
        for dependency in sorted(system.depends_on):
            for function in functions_by_system.get(system.id, set()):
                tail = unit_id(dependency, function)
                if tail in accum:
                    edges.append(Edge(tail, unit_id(system.id, function), EdgeKind.PROTOCOL_PEER))

    roadmap = build_roadmap(units, edges, as_of=as_of, capacity_per_quarter=capacity_per_quarter)
    return roadmap, units, edges
