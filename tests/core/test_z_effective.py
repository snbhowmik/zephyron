"""T-062 - Z_effective = min(scenario, applicable deadlines), and which one bound."""

from __future__ import annotations

from datetime import date

import pytest
from _policy import real_policy
from qavach_core.risk import z_effective

POLICY = real_policy()


def _z(regimes: set[str], crit: int = 3, scenario: str | None = None):  # type: ignore[no-untyped-def]
    return z_effective(
        regulatory_regimes=regimes, criticality=crit, policy=POLICY, scenario=scenario
    )


def test_with_no_regime_the_scenario_alone_binds() -> None:
    z = _z(set())
    assert (z.z_date, z.bound_by, z.binding) == (date(2033, 1, 1), "scenario:nominal", False)


@pytest.mark.parametrize(
    ("scenario", "year"), [("aggressive", 2030), ("nominal", 2033), ("conservative", 2038)]
)
def test_each_scenario_is_selectable_and_named(scenario: str, year: int) -> None:
    z = _z(set(), scenario=scenario)
    assert z.z_date == date(year, 1, 1) and z.bound_by == f"scenario:{scenario}"


def test_a_cii_high_priority_system_is_bound_by_dst_milestone_2_years_before_physics() -> None:
    """The headline NTRO case: the binding constraint is compliance, not physics."""
    z = _z({"cii"}, crit=5)
    assert z.bound_by == "deadline:in_dst_cii_m2_highpriority"
    assert z.z_date == date(2028, 12, 31) and z.z_date < date(2033, 1, 1)
    assert z.binding is False  # the DST roadmap is advisory


def test_a_cii_lower_priority_system_is_bound_by_milestone_3() -> None:
    assert _z({"cii"}, crit=2).bound_by == "deadline:in_dst_cii_m3_full"


def test_the_same_asset_in_a_non_cii_enterprise_gets_the_later_date() -> None:
    """ARCH.md 7.3: high-priority is M2 in both tracks, 2028 vs 2030."""
    assert _z({"cii"}, crit=5).z_date == date(2028, 12, 31)
    ent = _z({"enterprise"}, crit=5)
    assert (
        ent.z_date == date(2030, 12, 31) and ent.bound_by == "deadline:in_dst_ent_m2_highpriority"
    )


def test_the_track_is_never_inferred() -> None:
    z = _z({"sebi-re"}, crit=5)
    assert not any(d.applies and d.id.startswith("in_dst") for d in z.considered)
    assert any("no DST track" in s for s in z.explanation.steps)


def test_an_inventory_deadline_is_reported_but_never_binds_z() -> None:
    z = _z({"cii", "sebi-re"}, crit=5)
    assert z.z_date.year > 2025  # SEBI's passed inventory date did not become Z
    skipped = {d.id: d for d in z.considered}
    assert skipped["in_sebi_cscrf_inventory"].applies is False
    assert "does not bind Z" in skipped["in_sebi_cscrf_inventory"].reason
    assert skipped["in_dst_cii_m1_foundations"].applies is False


def test_a_binding_regulatory_deadline_is_flagged_binding() -> None:
    z = _z({"nss"})
    assert z.bound_by == "deadline:cnsa2_acquisition_gate" and z.binding is True


def test_the_earliest_of_several_applicable_dates_wins() -> None:
    z = _z({"cii", "nss"}, crit=5)
    assert z.z_date == date(2027, 1, 1) and z.bound_by == "deadline:cnsa2_acquisition_gate"


def test_a_deadline_later_than_the_scenario_does_not_bind() -> None:
    z = _z({"us-federal"}, scenario="aggressive")  # NIST 2030-12-31 > 2030-01-01
    assert z.bound_by == "scenario:aggressive"


def test_years_from_uses_the_supplied_date_never_the_clock() -> None:
    z = _z({"cii"}, crit=5)
    assert z.years_from(date(2026, 12, 31)) == pytest.approx(2.0, abs=0.01)
    assert z.years_from(date(2026, 12, 31)) == z.years_from(date(2026, 12, 31))


def test_the_explanation_names_every_deadline_considered_with_citations() -> None:
    z = _z({"cii"}, crit=5)
    d = z.explanation.to_dict()
    assert all(p["basis"] for p in d["policy"])
    assert len(z.considered) == 10
    assert any("scenario 'nominal'" in s for s in d["steps"])
