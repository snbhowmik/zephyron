"""Layer 7 - the migration roadmap. T-084, T-085, T-086, T-087 / ARCH.md 9.

Pure and deterministic. Steps follow `ARCH.md §9.2`:

0. **Authority filter (I9).** Only `SELF` units enter the DAG. `VENDOR` units
   become *dependency leaves* with an ETA and a contact action; `REGULATOR_GATED`
   units become *named blockers*; `EXTERNAL_TRUST_ANCHOR` units never enter
   the roadmap (they are only counted); `UNKNOWN` goes to a triage list and is
   never defaulted to `SELF`. Without this step the DAG fills with public CAs
   and OEM firmware nobody here can change.
1. **Waves.** Topological layering. Each unit is really two nodes,
   `start` and `complete`; ordinary edges run `tail.complete -> head.start`,
   while a `regulatory-gate` edge lands on `head.complete`: a unit behind a gate
   can *start* on schedule and still be unable to *complete*. A gate with no ETA
   makes the unit `schedule_risk: unbounded` and **no date is rendered** -
   inventing one is worse than admitting the gap.
2. **Order inside a wave** by Mosca urgency, most overdue first; an unscored
   unit sorts last and visibly so.
3. **Quarters, scheduled backwards** from each unit's binding deadline, with an
   operator capacity limit, then a forward pass for the earliest feasible date.
4. **Shared resources aggregate with `min()` downward:** a unit's latest finish
   is capped by every dependent's latest *start*, so a root CA or HSM inherits
   the earliest deadline of everything beneath it.
5. **`SCHEDULE_INFEASIBLE`** when the earliest feasible completion is after the
   binding deadline, with the specific blocking chain named. Capacity
   contention is *detected and named*, not solved: that is a
   resource-constrained scheduling problem, not a DAG problem (ARCH.md 9.2).

**A cycle is a finding, not an error** (ARCH.md 9.3). Each strongly connected
component becomes a `HybridBridgeRequirement` naming every member and is
scheduled as its own wave; where an edge in the cycle is certificate pinning,
the variant is pin-superset -> rotate -> prune, gated on adoption telemetry
rather than a date.

The `data-format` helper encodes **reader before writer**: consumers must be able
to *verify* a new format before any producer *emits* it.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum

from qavach_core.model.enums import CryptoFunction, MigrationAuthority


class EdgeKind(StrEnum):
    TRUST_ANCHOR = "trust-anchor"
    PROTOCOL_PEER = "protocol-peer"
    LIBRARY_AVAILABILITY = "library-availability"
    HARDWARE_GATE = "hardware-gate"
    DATA_FORMAT = "data-format"
    BUILD_AND_SIGN = "build-and-sign"
    REGULATORY_GATE = "regulatory-gate"


class ScheduleRisk(StrEnum):
    UNBOUNDED = "unbounded"


@dataclass(frozen=True, slots=True)
class MigrationUnit:
    id: str
    system_id: str
    function: CryptoFunction | None
    authority: MigrationAuthority
    y_years: float
    deadline: date
    deadline_bound_by: str
    urgency_gap_years: float | None = None
    """Mosca gap; `None` (unscored) sorts last within a wave."""
    eta: date | None = None
    """For a `VENDOR` unit: when the vendor is expected to deliver. `None` is
    unbounded and stays unbounded - never invented."""
    contact_action: str | None = None
    shared_resource: str | None = None


@dataclass(frozen=True, slots=True)
class RegulatoryGate:
    id: str
    body: str
    eta: date | None = None


@dataclass(frozen=True, slots=True)
class Edge:
    tail: str
    head: str
    kind: EdgeKind
    pinning: bool = False
    """Certificate pinning: a static pin-set cannot run dual-stack, so a cycle
    through such an edge needs the pin-superset variant."""
    note: str | None = None


def data_format_edges(writer: str, readers: Iterable[str]) -> list[Edge]:
    """Reader before writer: every consumer must be able to *verify* the new
    format before the producer starts *emitting* it. Getting this backwards
    breaks production on cutover day."""
    return [
        Edge(tail=reader, head=writer, kind=EdgeKind.DATA_FORMAT, note="reader before writer")
        for reader in sorted(readers)
    ]


@dataclass(frozen=True, slots=True)
class VendorDependency:
    unit_id: str
    system_id: str
    eta: date | None
    action: str
    blocks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NamedBlocker:
    unit_id: str
    system_id: str
    blocks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HybridBridgeRequirement:
    members: tuple[str, ...]
    variant: str
    """`dual-stack` or `pin-superset`."""
    phases: tuple[str, ...]
    gate: str


@dataclass(frozen=True, slots=True)
class Infeasibility:
    unit_id: str
    deadline_quarter: str
    earliest_finish_quarter: str
    deadline_source: str
    blocking_chain: tuple[str, ...]
    contended_resource: str | None


@dataclass(frozen=True, slots=True)
class UnitSchedule:
    unit_id: str
    wave: int
    earliest_start: str | None
    earliest_finish: str | None
    target_finish: str | None
    """Backward-scheduled from the binding deadline; `None` when unbounded."""
    schedule_risk: ScheduleRisk | None
    infeasible: bool


@dataclass(frozen=True, slots=True)
class Wave:
    index: int
    kind: str
    """`migration` or `bridge`."""
    units: tuple[str, ...]
    schedule_risk: ScheduleRisk | None


@dataclass(frozen=True, slots=True)
class Roadmap:
    waves: tuple[Wave, ...]
    schedule: Mapping[str, UnitSchedule]
    bridges: tuple[HybridBridgeRequirement, ...]
    vendor_dependencies: tuple[VendorDependency, ...]
    named_blockers: tuple[NamedBlocker, ...]
    infeasible: tuple[Infeasibility, ...]
    excluded_trust_anchors: int
    triage: tuple[str, ...]
    notes: tuple[str, ...] = field(default=())


class RoadmapError(ValueError):
    pass


def quarter_index(d: date) -> int:
    return d.year * 4 + (d.month - 1) // 3


def quarter_label(index: int) -> str:
    return f"{index // 4}-Q{index % 4 + 1}"


def _sccs(nodes: Sequence[str], succ: Mapping[str, Sequence[str]]) -> list[list[str]]:
    """Iterative Tarjan (no recursion limit on deep chains), deterministic order."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, child_i = work.pop()
            if child_i == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            children = succ.get(node, ())
            advanced = False
            for i in range(child_i, len(children)):
                child = children[i]
                if child not in index:
                    work.append((node, i + 1))
                    work.append((child, 0))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            if low[node] == index[node]:
                comp = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    comp.append(member)
                    if member == node:
                        break
                result.append(sorted(comp))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return result


def build_roadmap(
    units: Sequence[MigrationUnit],
    edges: Sequence[Edge],
    *,
    as_of: date,
    gates: Mapping[str, RegulatoryGate] | None = None,
    capacity_per_quarter: int | None = None,
    bridge_window_quarters: int = 2,
) -> Roadmap:
    gates = gates or {}
    by_id = {u.id: u for u in units}
    if len(by_id) != len(units):
        raise RoadmapError("migration unit ids must be unique")
    notes: list[str] = []

    for e in edges:
        if e.kind is EdgeKind.REGULATORY_GATE:
            if e.tail not in gates or e.head not in by_id:
                raise RoadmapError(
                    f"regulatory-gate edge {e.tail}->{e.head} names an unknown gate or unit"
                )
        elif e.tail not in by_id or e.head not in by_id:
            raise RoadmapError(f"edge {e.tail}->{e.head} names an unknown unit")

    # ---- step 0: authority filter -------------------------------------------------
    selves = sorted(u.id for u in units if u.authority is MigrationAuthority.SELF)
    self_set = set(selves)
    excluded = sum(1 for u in units if u.authority is MigrationAuthority.EXTERNAL_TRUST_ANCHOR)
    triage = tuple(sorted(u.id for u in units if u.authority is MigrationAuthority.UNKNOWN))

    ordinary: dict[str, list[str]] = defaultdict(list)
    pinned_edges: set[tuple[str, str]] = set()
    vendor_blocks: dict[str, set[str]] = defaultdict(set)
    blocker_blocks: dict[str, set[str]] = defaultdict(set)
    gate_edges: dict[str, list[str]] = defaultdict(list)
    for e in sorted(edges, key=lambda x: (x.tail, x.head, x.kind.value)):
        if e.kind is EdgeKind.REGULATORY_GATE:
            if e.head in self_set:
                gate_edges[e.head].append(e.tail)
            continue
        tail_unit, head_unit = by_id[e.tail], by_id[e.head]
        if head_unit.authority is not MigrationAuthority.SELF:
            notes.append(f"edge {e.tail}->{e.head} ignored: {e.head} is not a SELF unit")
            continue
        if tail_unit.authority is MigrationAuthority.SELF:
            ordinary[e.tail].append(e.head)
            if e.pinning:
                pinned_edges.add((e.tail, e.head))
        elif tail_unit.authority is MigrationAuthority.VENDOR:
            vendor_blocks[e.tail].add(e.head)
        elif tail_unit.authority is MigrationAuthority.REGULATOR_GATED:
            blocker_blocks[e.tail].add(e.head)
        else:
            notes.append(f"edge {e.tail}->{e.head} ignored: {e.tail} is external or unknown")

    succ = {n: sorted(set(ordinary.get(n, ()))) for n in selves}
    pred: dict[str, list[str]] = defaultdict(list)
    for tail, heads in succ.items():
        for head in heads:
            pred[head].append(tail)

    # ---- step 1: SCCs -> bridges, condensation, levels ----------------------------
    comps = _sccs(selves, succ)
    comp_of = {m: i for i, c in enumerate(comps) for m in c}
    is_bridge = [len(c) > 1 or (c[0] in succ.get(c[0], ())) for c in comps]
    csucc: dict[int, set[int]] = defaultdict(set)
    cpred: dict[int, set[int]] = defaultdict(set)
    for tail, heads in succ.items():
        for head in heads:
            if comp_of[tail] != comp_of[head]:
                csucc[comp_of[tail]].add(comp_of[head])
                cpred[comp_of[head]].add(comp_of[tail])

    order: list[int] = []
    indeg = {i: len(cpred.get(i, ())) for i in range(len(comps))}
    ready = sorted(i for i, d in indeg.items() if d == 0)
    level: dict[int, int] = {}
    while ready:
        i = ready.pop(0)
        order.append(i)
        level[i] = 1 + max((level[p] for p in cpred.get(i, ())), default=-1)
        for j in sorted(csucc.get(i, ())):
            indeg[j] -= 1
            if indeg[j] == 0:
                ready.append(j)
                ready.sort()

    bridges: list[HybridBridgeRequirement] = []
    for i, comp in enumerate(comps):
        if not is_bridge[i]:
            continue
        pinning = any((a, b) in pinned_edges for a in comp for b in succ.get(a, ()) if b in comp)
        if pinning:
            bridges.append(
                HybridBridgeRequirement(
                    members=tuple(comp),
                    variant="pin-superset",
                    phases=(
                        "A: publish a pin SUPERSET containing both classical and PQC SPKI",
                        "B: soak - gate on adoption telemetry, not a calendar date",
                        "C: rotate the server key to the PQC SPKI",
                        "D: soak again",
                        "E: prune the classical pin",
                    ),
                    gate="adoption telemetry (client-version floor and a backup pin required "
                    "before phase C); a time-based gate bricks the long tail",
                )
            )
        else:
            bridges.append(
                HybridBridgeRequirement(
                    members=tuple(comp),
                    variant="dual-stack",
                    phases=(
                        "run classical and PQC simultaneously on every member",
                        "verify every member interoperates in PQC mode",
                        "retire the classical half",
                    ),
                    gate="all members verified in PQC mode",
                )
            )

    # ---- per-component effort, unbounded propagation ------------------------------
    def effort_q(i: int) -> int:
        base = max(max(1, math.ceil(by_id[m].y_years * 4)) for m in comps[i])
        return base + (bridge_window_quarters if is_bridge[i] else 0)

    as_of_q = quarter_index(as_of)
    unbounded: set[int] = set()
    vendor_eta_q: dict[int, int] = defaultdict(int)
    for vendor_id, blocked in vendor_blocks.items():
        eta = by_id[vendor_id].eta
        for head in blocked:
            c = comp_of[head]
            if eta is None:
                unbounded.add(c)
            else:
                vendor_eta_q[c] = max(vendor_eta_q[c], quarter_index(eta))
    for blocked in blocker_blocks.values():
        unbounded.update(comp_of[h] for h in blocked)
    gate_eta_q: dict[int, int] = defaultdict(int)
    for head, gate_ids in gate_edges.items():
        for gate_id in gate_ids:
            eta = gates[gate_id].eta
            if eta is None:
                unbounded.add(comp_of[head])
            else:
                gate_eta_q[comp_of[head]] = max(gate_eta_q[comp_of[head]], quarter_index(eta))
    for i in order:
        if any(p in unbounded for p in cpred.get(i, ())):
            unbounded.add(i)

    # ---- forward pass: earliest start/finish with capacity, binding predecessor ---
    start_load: dict[int, int] = defaultdict(int)
    e_start: dict[int, int] = {}
    e_finish: dict[int, int] = {}
    binding: dict[int, str] = {}
    binding_pred: dict[int, int] = {}
    waited: dict[int, int] = {}
    for i in sorted(order, key=lambda c: (level[c], comps[c])):
        if i in unbounded:
            continue
        ready_q, why, why_pred = as_of_q, "start of planning window", None
        for p in sorted(cpred.get(i, ())):
            if e_finish.get(p, as_of_q) > ready_q:
                ready_q, why, why_pred = e_finish[p], f"predecessor {comps[p][0]}", p
        if vendor_eta_q.get(i, 0) > ready_q:
            ready_q, why, why_pred = vendor_eta_q[i], "vendor ETA", None
        if why_pred is not None:
            binding_pred[i] = why_pred
        s = ready_q
        if capacity_per_quarter is not None:
            while start_load[s] >= capacity_per_quarter:
                s += 1
        waited[i] = s - ready_q
        start_load[s] += 1
        f = max(s + effort_q(i), gate_eta_q.get(i, 0))
        e_start[i], e_finish[i] = s, f
        binding[i] = why

    # ---- backward pass: latest finish from binding deadlines (min downward) -------
    deadline_q = {
        i: min(quarter_index(by_id[m].deadline) for m in comps[i]) for i in range(len(comps))
    }
    deadline_src = {
        i: min((by_id[m] for m in comps[i]), key=lambda u: (u.deadline, u.id))
        for i in range(len(comps))
    }
    latest_finish: dict[int, int] = {}
    latest_src: dict[int, str] = {}
    for i in reversed(order):
        lf = deadline_q[i]
        src = f"{deadline_src[i].id} ({deadline_src[i].deadline_bound_by})"
        for s_ in csucc.get(i, ()):
            latest_start = latest_finish[s_] - effort_q(s_)
            if latest_start < lf:
                lf = latest_start
                src = f"dependent {comps[s_][0]} ({latest_src[s_]})"
        latest_finish[i], latest_src[i] = lf, src

    # ---- target quarters: backward, respecting capacity ---------------------------
    finish_load: dict[int, int] = defaultdict(int)
    target_finish: dict[int, int] = {}
    for i in reversed(order):
        if i in unbounded:
            continue
        q = latest_finish[i]
        for s_ in csucc.get(i, ()):
            if s_ in target_finish:
                q = min(q, target_finish[s_] - effort_q(s_))
        if capacity_per_quarter is not None:
            while finish_load[q] >= capacity_per_quarter:
                q -= 1
        finish_load[q] += 1
        target_finish[i] = q

    # ---- infeasibility with the blocking chain ------------------------------------
    infeasible: list[Infeasibility] = []
    infeasible_units: set[str] = set()

    max_chain = 12

    def chain_for(i: int) -> tuple[str, ...]:
        """Walks back along the predecessor that fixed each start date. Capped:
        a 3,000-link chain is not a useful explanation, and walking it for every
        infeasible unit would be quadratic. The elided count is stated."""
        out: list[str] = []
        cur: int | None = i
        hops = 0
        while cur is not None and hops < max_chain:
            label = "+".join(comps[cur]) + (" [bridge]" if is_bridge[cur] else "")
            step = f"{label} ({quarter_label(e_start[cur])}-{quarter_label(e_finish[cur])})"
            if waited.get(cur):
                step += f" after waiting {waited[cur]} quarter(s) for operator capacity"
            out.append(step)
            reason = binding.get(cur, "")
            if reason == "vendor ETA":
                out.append("vendor ETA")
            cur = binding_pred.get(cur)
            hops += 1
        if cur is not None:
            depth = 0
            probe: int | None = cur
            while probe is not None and depth < 100_000:
                depth += 1
                probe = binding_pred.get(probe)
            out.append(f"... {depth} earlier step(s) not shown")
        return tuple(reversed(out))

    for i in order:
        if i in unbounded or e_finish[i] <= latest_finish[i]:
            continue
        contended = None
        if waited.get(i):
            contended = (
                f"operator capacity ({capacity_per_quarter} parallel migrations per quarter)"
            )
        shared = {r for m in comps[i] if (r := by_id[m].shared_resource) is not None}
        if shared:
            contended = (
                contended + "; " if contended else ""
            ) + f"shared resource {sorted(shared)[0]}"
        for m in comps[i]:
            infeasible_units.add(m)
        infeasible.append(
            Infeasibility(
                unit_id=comps[i][0],
                deadline_quarter=quarter_label(latest_finish[i]),
                earliest_finish_quarter=quarter_label(e_finish[i]),
                deadline_source=latest_src[i],
                blocking_chain=chain_for(i),
                contended_resource=contended,
            )
        )

    # ---- assemble waves and per-unit schedule -------------------------------------
    def urgency_key(uid: str) -> tuple[int, float, str]:
        gap = by_id[uid].urgency_gap_years
        return (1, 0.0, uid) if gap is None else (0, -gap, uid)

    wave_specs: dict[tuple[int, str], list[int]] = defaultdict(list)
    for i in order:
        wave_specs[(level[i], "bridge" if is_bridge[i] else "migration")].append(i)
    waves: list[Wave] = []
    wave_index_of: dict[str, int] = {}
    for key in sorted(wave_specs, key=lambda k: (k[0], 0 if k[1] == "bridge" else 1)):
        members = sorted((m for i in wave_specs[key] for m in comps[i]), key=urgency_key)
        risky = ScheduleRisk.UNBOUNDED if any(comp_of[m] in unbounded for m in members) else None
        idx = len(waves)
        waves.append(Wave(idx, key[1], tuple(members), risky))
        for m in members:
            wave_index_of[m] = idx

    schedule: dict[str, UnitSchedule] = {}
    for m in selves:
        i = comp_of[m]
        risky = ScheduleRisk.UNBOUNDED if i in unbounded else None
        schedule[m] = UnitSchedule(
            unit_id=m,
            wave=wave_index_of[m],
            earliest_start=None if risky else quarter_label(e_start[i]),
            earliest_finish=None if risky else quarter_label(e_finish[i]),
            target_finish=None if risky else quarter_label(target_finish[i]),
            schedule_risk=risky,
            infeasible=m in infeasible_units,
        )

    return Roadmap(
        waves=tuple(waves),
        schedule=schedule,
        bridges=tuple(bridges),
        vendor_dependencies=tuple(
            VendorDependency(
                unit_id=v,
                system_id=by_id[v].system_id,
                eta=by_id[v].eta,
                action=by_id[v].contact_action
                or "engage the vendor for a PQC delivery date; the ETA is theirs, not ours",
                blocks=tuple(sorted(blocked)),
            )
            for v, blocked in sorted(vendor_blocks.items())
        ),
        named_blockers=tuple(
            NamedBlocker(b, by_id[b].system_id, tuple(sorted(blocked)))
            for b, blocked in sorted(blocker_blocks.items())
        ),
        infeasible=tuple(infeasible),
        excluded_trust_anchors=excluded,
        triage=triage,
        notes=tuple(sorted(set(notes))),
    )
