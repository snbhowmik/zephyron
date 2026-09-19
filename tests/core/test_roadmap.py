"""T-084..T-087 - the migration roadmap."""

from __future__ import annotations

from datetime import date

import pytest
from qavach_core.model.enums import CryptoFunction, MigrationAuthority
from qavach_core.roadmap import (
    Edge,
    EdgeKind,
    MigrationUnit,
    RegulatoryGate,
    RoadmapError,
    ScheduleRisk,
    build_roadmap,
    data_format_edges,
    quarter_index,
    quarter_label,
)

AS_OF = date(2026, 9, 20)  # 2026-Q3
SELF, VENDOR = MigrationAuthority.SELF, MigrationAuthority.VENDOR


def unit(
    uid: str,
    *,
    y: float = 0.25,
    deadline: date = date(2029, 12, 31),
    authority: MigrationAuthority = SELF,
    gap: float | None = 0.0,
    **kw,
):  # type: ignore[no-untyped-def]
    return MigrationUnit(
        id=uid,
        system_id=f"sys-{uid}",
        function=CryptoFunction.SIGNATURE,
        authority=authority,
        y_years=y,
        deadline=deadline,
        deadline_bound_by="deadline:test",
        urgency_gap_years=gap,
        **kw,
    )


def edge(tail: str, head: str, kind: EdgeKind = EdgeKind.PROTOCOL_PEER, **kw):  # type: ignore[no-untyped-def]
    return Edge(tail, head, kind, **kw)


def wave_of(road, uid: str) -> int:  # type: ignore[no-untyped-def]
    return road.schedule[uid].wave


def test_quarter_helpers() -> None:
    assert quarter_index(date(2026, 9, 20)) == 2026 * 4 + 2
    assert quarter_label(quarter_index(date(2026, 9, 20))) == "2026-Q3"
    assert quarter_label(quarter_index(date(2028, 1, 1))) == "2028-Q1"


# ---- step 0: authority filter (I9) ----


def test_only_self_units_enter_the_dag_and_the_rest_are_classified() -> None:
    units = [
        unit("own"),
        unit("oem", authority=VENDOR, eta=date(2028, 6, 30)),
        unit("npci", authority=MigrationAuthority.REGULATOR_GATED),
        unit("sectigo", authority=MigrationAuthority.EXTERNAL_TRUST_ANCHOR),
        unit("who", authority=MigrationAuthority.UNKNOWN),
    ]
    road = build_roadmap(
        units, [edge("oem", "own", EdgeKind.LIBRARY_AVAILABILITY), edge("npci", "own")], as_of=AS_OF
    )
    assert set(road.schedule) == {"own"}
    assert road.excluded_trust_anchors == 1 and road.triage == ("who",)
    assert [v.unit_id for v in road.vendor_dependencies] == ["oem"]
    assert road.vendor_dependencies[0].eta == date(2028, 6, 30) and road.vendor_dependencies[
        0
    ].blocks == ("own",)
    assert [b.unit_id for b in road.named_blockers] == ["npci"]


def test_I9_an_external_trust_anchor_never_appears_in_a_wave_or_the_schedule() -> None:
    units = [unit("a"), unit("ca", authority=MigrationAuthority.EXTERNAL_TRUST_ANCHOR)]
    road = build_roadmap(units, [edge("ca", "a", EdgeKind.TRUST_ANCHOR)], as_of=AS_OF)
    assert "ca" not in {u for w in road.waves for u in w.units}
    assert any("external or unknown" in n for n in road.notes)


def test_unknown_authority_is_triaged_never_defaulted_to_self() -> None:
    road = build_roadmap([unit("x", authority=MigrationAuthority.UNKNOWN)], [], as_of=AS_OF)
    assert road.waves == () and road.triage == ("x",)


# ---- step 1: waves and ordering ----


def test_a_chain_yields_one_wave_per_link_in_dependency_order() -> None:
    road = build_roadmap(
        [unit("ca"), unit("server"), unit("client")],
        [edge("ca", "server", EdgeKind.TRUST_ANCHOR), edge("server", "client")],
        as_of=AS_OF,
    )
    assert (wave_of(road, "ca"), wave_of(road, "server"), wave_of(road, "client")) == (0, 1, 2)


def test_independent_units_share_a_wave_ordered_by_mosca_urgency_most_overdue_first() -> None:
    road = build_roadmap(
        [
            unit("low", gap=-3.0),
            unit("late", gap=4.0),
            unit("mid", gap=0.5),
            unit("unscored", gap=None),
        ],
        [],
        as_of=AS_OF,
    )
    assert len(road.waves) == 1 and road.waves[0].units == ("late", "mid", "low", "unscored")


def test_every_one_of_the_seven_edge_types_orders_its_tail_first() -> None:
    gates = {"stqc": RegulatoryGate("stqc", "STQC", eta=date(2027, 12, 31))}
    for kind in EdgeKind:
        if kind is EdgeKind.REGULATORY_GATE:
            road = build_roadmap([unit("h")], [Edge("stqc", "h", kind)], as_of=AS_OF, gates=gates)
            assert road.schedule["h"].earliest_finish is not None
            continue
        road = build_roadmap([unit("t"), unit("h")], [edge("t", "h", kind)], as_of=AS_OF)
        assert wave_of(road, "t") < wave_of(road, "h"), kind


def test_data_format_is_reader_before_writer() -> None:
    edges = data_format_edges("producer", ["consumer-b", "consumer-a"])
    assert [(e.tail, e.head) for e in edges] == [
        ("consumer-a", "producer"),
        ("consumer-b", "producer"),
    ]
    road = build_roadmap(
        [unit("producer"), unit("consumer-a"), unit("consumer-b")], edges, as_of=AS_OF
    )
    assert wave_of(road, "consumer-a") < wave_of(road, "producer")
    assert wave_of(road, "consumer-b") < wave_of(road, "producer")


# ---- regulatory gate: node splitting ----


def test_a_unit_behind_a_gate_can_start_on_schedule_but_not_complete_before_the_gate() -> None:
    gates = {"stqc": RegulatoryGate("stqc", "STQC certification", eta=date(2028, 6, 30))}
    road = build_roadmap(
        [unit("hsm-fw", y=0.25)],
        [Edge("stqc", "hsm-fw", EdgeKind.REGULATORY_GATE)],
        as_of=AS_OF,
        gates=gates,
    )
    s = road.schedule["hsm-fw"]
    assert s.earliest_start == "2026-Q3"  # starts now
    assert s.earliest_finish == "2028-Q2"  # cannot complete before the gate


def test_a_gate_with_no_eta_is_unbounded_and_no_date_is_invented() -> None:
    gates = {"npci": RegulatoryGate("npci", "NPCI PQC profile", eta=None)}
    road = build_roadmap(
        [unit("upi"), unit("after")],
        [Edge("npci", "upi", EdgeKind.REGULATORY_GATE), edge("upi", "after")],
        as_of=AS_OF,
        gates=gates,
    )
    for uid in ("upi", "after"):  # unboundedness propagates to dependents
        s = road.schedule[uid]
        assert s.schedule_risk is ScheduleRisk.UNBOUNDED
        assert (s.earliest_start, s.earliest_finish, s.target_finish) == (None, None, None)
    assert all(w.schedule_risk is ScheduleRisk.UNBOUNDED for w in road.waves)


def test_a_vendor_with_no_eta_leaves_its_dependents_unbounded_and_a_dated_one_delays_them() -> None:
    a = build_roadmap(
        [unit("v", authority=VENDOR, eta=None), unit("app")],
        [edge("v", "app", EdgeKind.LIBRARY_AVAILABILITY)],
        as_of=AS_OF,
    )
    assert a.schedule["app"].schedule_risk is ScheduleRisk.UNBOUNDED
    b = build_roadmap(
        [unit("v", authority=VENDOR, eta=date(2028, 7, 1)), unit("app")],
        [edge("v", "app", EdgeKind.LIBRARY_AVAILABILITY)],
        as_of=AS_OF,
    )
    assert b.schedule["app"].earliest_start == "2028-Q3"


def test_unknown_units_or_gates_are_errors_not_silent() -> None:
    with pytest.raises(RoadmapError):
        build_roadmap([unit("a")], [edge("a", "ghost")], as_of=AS_OF)
    with pytest.raises(RoadmapError):
        build_roadmap([unit("a")], [Edge("nobody", "a", EdgeKind.REGULATORY_GATE)], as_of=AS_OF)
    with pytest.raises(RoadmapError):
        build_roadmap([unit("a"), unit("a")], [], as_of=AS_OF)


# ---- T-086: cycles are findings, not errors ----


def test_a_mutual_dependency_becomes_a_hybrid_bridge_naming_every_member() -> None:
    road = build_roadmap(
        [unit("a"), unit("b"), unit("c")],
        [
            edge("a", "b", EdgeKind.PROTOCOL_PEER),
            edge("b", "a", EdgeKind.PROTOCOL_PEER),
            edge("b", "c"),
        ],
        as_of=AS_OF,
    )
    assert len(road.bridges) == 1
    bridge = road.bridges[0]
    assert bridge.members == ("a", "b") and bridge.variant == "dual-stack"
    assert "retire the classical half" in bridge.phases[-1]
    kinds = [w.kind for w in road.waves]
    assert kinds == ["bridge", "migration"]  # the bridge is its own wave, c comes after it
    assert wave_of(road, "a") == wave_of(road, "b") < wave_of(road, "c")


def test_a_larger_cycle_names_all_members_and_is_one_bridge() -> None:
    ids = ["u1", "u2", "u3", "u4"]
    edges = [edge(ids[i], ids[(i + 1) % 4]) for i in range(4)]
    road = build_roadmap([unit(i) for i in ids], edges, as_of=AS_OF)
    assert len(road.bridges) == 1 and road.bridges[0].members == tuple(ids)


def test_a_cycle_through_certificate_pinning_gets_the_pin_superset_variant_gated_on_telemetry() -> (
    None
):
    road = build_roadmap(
        [unit("app"), unit("api")],
        [edge("app", "api"), edge("api", "app", pinning=True)],
        as_of=AS_OF,
    )
    b = road.bridges[0]
    assert b.variant == "pin-superset" and len(b.phases) == 5
    assert "adoption telemetry" in b.gate and "time-based gate bricks" in b.gate


def test_a_self_loop_is_a_cycle_too() -> None:
    road = build_roadmap([unit("solo")], [edge("solo", "solo")], as_of=AS_OF)
    assert road.bridges and road.bridges[0].members == ("solo",)


def test_a_cycle_is_a_finding_not_an_error_and_nothing_is_dropped() -> None:
    road = build_roadmap([unit("a"), unit("b")], [edge("a", "b"), edge("b", "a")], as_of=AS_OF)
    assert {u for w in road.waves for u in w.units} == {"a", "b"} and road.schedule[
        "a"
    ].earliest_finish


def test_a_very_long_chain_does_not_hit_the_recursion_limit() -> None:
    n = 3000
    units = [unit(f"n{i:05d}") for i in range(n)]
    edges = [edge(f"n{i:05d}", f"n{i + 1:05d}") for i in range(n - 1)]
    road = build_roadmap(units, edges, as_of=AS_OF)
    assert len(road.waves) == n and road.bridges == ()


# ---- T-085: quarters, min-downward ----


def test_scheduling_is_backward_from_the_binding_deadline() -> None:
    road = build_roadmap([unit("a", y=0.5, deadline=date(2028, 12, 31))], [], as_of=AS_OF)
    assert road.schedule["a"].target_finish == "2028-Q4"
    assert road.schedule["a"].earliest_finish == "2027-Q1"  # 2 quarters from 2026-Q3


def test_a_shared_root_inherits_the_earliest_deadline_of_its_dependents() -> None:
    """Min DOWNWARD: the root has a lax own deadline but must finish early
    enough for the tight dependent."""
    road = build_roadmap(
        [
            unit("root-ca", y=1.0, deadline=date(2033, 12, 31)),
            unit("tight", y=0.5, deadline=date(2028, 12, 31)),
            unit("lax", y=0.5, deadline=date(2033, 12, 31)),
        ],
        [
            edge("root-ca", "tight", EdgeKind.TRUST_ANCHOR),
            edge("root-ca", "lax", EdgeKind.TRUST_ANCHOR),
        ],
        as_of=AS_OF,
    )
    # tight: finish 2028-Q4, effort 2q -> starts 2028-Q3 -> root must finish by 2028-Q2
    assert road.schedule["root-ca"].target_finish == "2028-Q2"
    assert road.schedule["lax"].target_finish == "2033-Q4"


def test_the_capacity_limit_pushes_targets_earlier_never_over_the_limit() -> None:
    units = [unit(f"u{i}", deadline=date(2028, 12, 31)) for i in range(5)]
    road = build_roadmap(units, [], as_of=AS_OF, capacity_per_quarter=2)
    finishes = [road.schedule[u.id].target_finish for u in units]
    assert all(finishes.count(q) <= 2 for q in set(finishes))
    assert min(finishes) < "2028-Q4"


# ---- T-087: SCHEDULE_INFEASIBLE names the chain ----


def test_a_slow_chain_that_cannot_meet_the_deadline_is_infeasible_with_the_chain_named() -> None:
    road = build_roadmap(
        [
            unit("ca", y=2.0, deadline=date(2033, 12, 31)),
            unit("server", y=2.0, deadline=date(2027, 12, 31), shared_resource="root-hsm"),
        ],
        [edge("ca", "server", EdgeKind.TRUST_ANCHOR)],
        as_of=AS_OF,
    )
    assert road.schedule["server"].infeasible
    inf = next(i for i in road.infeasible if i.unit_id == "server")
    assert inf.deadline_quarter == "2027-Q4" and inf.earliest_finish_quarter > inf.deadline_quarter
    assert any(step.startswith("ca ") for step in inf.blocking_chain)
    assert inf.contended_resource == "shared resource root-hsm"


def test_the_upstream_unit_is_infeasible_because_of_the_dependent_that_imposed_the_deadline() -> (
    None
):
    road = build_roadmap(
        [
            unit("ca", y=2.0, deadline=date(2033, 12, 31)),
            unit("server", y=2.0, deadline=date(2027, 12, 31)),
        ],
        [edge("ca", "server", EdgeKind.TRUST_ANCHOR)],
        as_of=AS_OF,
    )
    inf = next(i for i in road.infeasible if i.unit_id == "ca")
    assert "dependent server" in inf.deadline_source


def test_capacity_contention_is_detected_and_named() -> None:
    units = [unit(f"s{i}", y=0.25, deadline=date(2027, 3, 31)) for i in range(6)]
    road = build_roadmap(units, [], as_of=AS_OF, capacity_per_quarter=1)
    contended = [i for i in road.infeasible if i.contended_resource]
    assert (
        contended
        and "operator capacity (1 parallel migrations per quarter)"
        in contended[0].contended_resource
    )


def test_a_feasible_estate_has_no_infeasibility() -> None:
    road = build_roadmap([unit("a"), unit("b")], [edge("a", "b")], as_of=AS_OF)
    assert road.infeasible == () and not any(s.infeasible for s in road.schedule.values())


def test_a_vendor_eta_after_the_deadline_makes_the_dependent_infeasible_and_says_why() -> None:
    road = build_roadmap(
        [
            unit("hsm-vendor", authority=VENDOR, eta=date(2028, 9, 30)),
            unit("svc", y=0.5, deadline=date(2028, 6, 30)),
        ],
        [edge("hsm-vendor", "svc", EdgeKind.HARDWARE_GATE)],
        as_of=AS_OF,
    )
    inf = road.infeasible[0]
    assert inf.unit_id == "svc" and "vendor ETA" in inf.blocking_chain


def test_the_roadmap_is_deterministic_and_independent_of_input_order() -> None:
    units = [unit(f"u{i}", y=0.25 * (1 + i % 3), gap=float(i % 5)) for i in range(40)]
    edges = [edge(f"u{i}", f"u{(i * 7 + 3) % 40}") for i in range(40) if i != (i * 7 + 3) % 40]
    a = build_roadmap(units, edges, as_of=AS_OF, capacity_per_quarter=4)
    b = build_roadmap(
        list(reversed(units)), list(reversed(edges)), as_of=AS_OF, capacity_per_quarter=4
    )
    assert a == b


def test_a_long_blocking_chain_is_capped_and_says_how_much_was_elided() -> None:
    n = 40
    units = [unit(f"c{i:03d}", y=1.0, deadline=date(2027, 12, 31)) for i in range(n)]
    edges = [edge(f"c{i:03d}", f"c{i + 1:03d}") for i in range(n - 1)]
    road = build_roadmap(units, edges, as_of=AS_OF)
    chain = next(i for i in road.infeasible if i.unit_id == f"c{n - 1:03d}").blocking_chain
    assert (
        len(chain) <= 14 and chain[0].startswith("...") and "earlier step(s) not shown" in chain[0]
    )
    assert chain[-1].startswith(f"c{n - 1:03d}")


def test_five_thousand_units_with_dependencies_build_in_a_couple_of_seconds() -> None:
    import time

    n = 5000
    units = [unit(f"u{i:05d}", gap=float(i % 7)) for i in range(n)]
    edges = [
        edge(f"u{i:05d}", f"u{(i * 31 + 17) % n:05d}") for i in range(n) if i != (i * 31 + 17) % n
    ]
    start = time.perf_counter()
    road = build_roadmap(units, edges, as_of=AS_OF, capacity_per_quarter=50)
    elapsed = time.perf_counter() - start
    assert len(road.schedule) == n and elapsed < 10, f"{elapsed:.1f}s"
