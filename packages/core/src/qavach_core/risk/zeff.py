"""ARCH.md §7.3 - `Z_effective = min(Z_scenario, applicable regulatory deadlines)`.
T-062.

`Z` is unknowable, so it is a policy input (I3): the scenario is chosen from
`z_scenarios.yaml` and every result says which one, and which date *bound*.
For an Indian CII operator the binding constraint is usually a deadline, years
before any plausible CRQC - "the binding constraint is compliance, not physics".

What counts as applicable (`ARCH.md §7.3` is explicit on some of this, silent on
the rest; each decision is recorded in NOTE.md):

* Only `kind: migration` deadlines bind. An *inventory* deadline (DST
  Milestone 1, SEBI CSCRF) is reported in `considered` but says nothing about
  when keys become breakable, so it never becomes `Z`.
* The DST/NQM **track** (`cii` or `enterprise`) is read from the system's
  regimes and is never inferred. A system that states neither gets no DST
  deadline, and the result says so.
* The DST **milestone** follows priority: criticality at or above
  `dst.high_priority_min_criticality` -> Milestone 2, otherwise Milestone 3.
* A scenario year is taken as 1 January of that year - the conservative end.
* Ties go to the deadline: it is the one a regulator can hold you to.

Dates in, dates out; `as_of` is a parameter, never the wall clock, so the
result is reproducible (NFR-09).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from qavach_core.policy import Cited, PolicySnapshot
from qavach_core.risk.explain import Explanation, refs

_TRACKS = ("cii", "enterprise")


@dataclass(frozen=True, slots=True)
class DeadlineConsidered:
    id: str
    when: date
    kind: str
    binding: bool
    applies: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ZEffective:
    z_date: date
    bound_by: str
    """`scenario:<name>` or `deadline:<id>`."""
    binding: bool
    """True only when a *binding* (regulator-enforced) deadline is what bound."""
    scenario: str
    considered: tuple[DeadlineConsidered, ...]
    explanation: Explanation

    def years_from(self, as_of: date) -> float:
        return (self.z_date - as_of).days / 365.25


def _track(regimes: Iterable[str]) -> str | None:
    regime_set = set(regimes)
    for track in _TRACKS:
        if track in regime_set:
            return track
    return None


def z_effective(
    *,
    regulatory_regimes: Iterable[str],
    criticality: int,
    policy: PolicySnapshot,
    scenario: str | None = None,
) -> ZEffective:
    regimes = frozenset(regulatory_regimes)
    default_node = policy.node("z_scenarios.default")
    chosen = scenario or str(default_node.value)
    scenario_node = policy.node(f"z_scenarios.scenarios.{chosen}")
    scenario_date = date(int(scenario_node.fields["crqc_year"]), 1, 1)

    track = _track(regimes)
    min_crit_node = policy.node("scoring.dst.high_priority_min_criticality")
    wanted_milestone = "high_priority" if criticality >= int(min_crit_node.value) else "full"

    used: list[Cited] = [default_node, scenario_node, min_crit_node]
    considered: list[DeadlineConsidered] = []
    candidates: list[tuple[date, str, bool]] = [(scenario_date, f"scenario:{chosen}", False)]

    for deadline_id, node in sorted(policy.nodes("regulatory_deadlines.deadlines").items()):
        f = node.fields
        when = date.fromisoformat(str(f["date"]))
        scope = set(f.get("scope", []))
        kind = str(f["kind"])
        binding = bool(f.get("binding", False))
        milestone = f.get("milestone")

        if kind != "migration":
            applies, reason = False, "inventory deadline: reported, does not bind Z"
        elif milestone is not None:
            if track is None or track not in scope:
                applies, reason = False, f"DST track not stated as {sorted(scope)}"
            elif milestone != wanted_milestone:
                applies, reason = (
                    False,
                    f"milestone {milestone!r} is not this system's ({wanted_milestone!r})",
                )
            else:
                applies, reason = True, f"DST {track} track, {milestone} milestone"
        elif scope & regimes:
            applies, reason = True, f"system is in scope {sorted(scope & regimes)}"
        else:
            applies, reason = False, f"system is not in scope {sorted(scope)}"

        considered.append(DeadlineConsidered(deadline_id, when, kind, binding, applies, reason))
        if applies:
            used.append(node)
            candidates.append((when, f"deadline:{deadline_id}", binding))

    # earliest date wins; on a tie a deadline beats the scenario
    best = min(candidates, key=lambda c: (c[0], not c[1].startswith("deadline:"), c[1]))
    steps = [
        f"scenario {chosen!r} gives {scenario_date.isoformat()}",
        *(
            f"{d.id} ({d.when.isoformat()}): {'applies' if d.applies else 'skipped'} - {d.reason}"
            for d in considered
        ),
        f"earliest applicable date is {best[0].isoformat()} ({best[1]})",
    ]
    if track is None:
        steps.append(
            "no DST track (cii/enterprise) is stated for this system, so no DST deadline applies"
        )
    return ZEffective(
        z_date=best[0],
        bound_by=best[1],
        binding=best[2],
        scenario=chosen,
        considered=tuple(considered),
        explanation=Explanation(
            name="z_effective",
            formula="Z_effective = min(Z_scenario, applicable migration deadlines)",
            inputs={
                "regimes": sorted(regimes),
                "criticality": criticality,
                "scenario": chosen,
                "track": track,
                "milestone": wanted_milestone,
            },
            policy=refs(used),
            steps=tuple(steps),
        ),
    )
