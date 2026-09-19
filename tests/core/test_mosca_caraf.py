"""T-064, T-065, T-066 - Mosca, CARAF D3 expected value, D4 outcome."""

from __future__ import annotations

from datetime import date

import pytest
from _policy import make_system, real_policy
from qavach_core.model.enums import CryptoFunction, FindingClass, MigrationAuthority
from qavach_core.model.system import DataClass
from qavach_core.risk import (
    Outcome,
    UrgencyBand,
    decide,
    evaluate_mosca,
    expected_value,
    shelf_life_years,
    z_effective,
)

POLICY = real_policy()
AS_OF = date(2026, 9, 20)
QV, CW = FindingClass.QUANTUM_VULNERABLE, FindingClass.CLASSICAL_WEAK


def _mosca(
    fc=QV,
    *,
    function=CryptoFunction.KEY_AGREEMENT,
    retention=10.0,
    lifetime=None,
    y=1.0,  # type: ignore[no-untyped-def]
    regimes=frozenset(),
    crit=3,
    also_qv=False,
):
    system = make_system(retention_years=retention, regimes=regimes, criticality=crit)
    shelf = shelf_life_years(
        function, system=system, policy=POLICY, artefact_lifetime_years=lifetime
    )
    z = z_effective(regulatory_regimes=regimes, criticality=crit, policy=POLICY)
    return evaluate_mosca(
        finding_class=fc,
        also_quantum_vulnerable=also_qv,
        shelf=shelf,
        y_years=y,
        z=z,
        as_of=AS_OF,
        policy=POLICY,
    )


def test_late_when_x_plus_y_exceeds_z() -> None:
    m = _mosca(retention=10, y=1)  # Z nominal = 2033-01-01, ~6.28 y away
    assert m.gap_years == pytest.approx(10 + 1 - 6.28, abs=0.05)
    assert m.band is UrgencyBand.OVERDUE and m.mitigation == "migrate"


def test_early_with_slack_is_planned_and_a_thin_margin_is_imminent() -> None:
    assert _mosca(retention=1, y=0.25).band is UrgencyBand.PLANNED
    thin = _mosca(retention=5, y=0.25)  # gap = 5.25 - 6.28 = -1.03, within the 2y watch window
    assert thin.band is UrgencyBand.IMMINENT and thin.gap_years is not None and thin.gap_years < 0


def test_a_cii_deadline_makes_the_same_asset_overdue_that_physics_would_not() -> None:
    plain = _mosca(retention=3, y=1)
    cii = _mosca(retention=3, y=1, regimes=frozenset({"cii"}), crit=5)
    assert plain.band is UrgencyBand.PLANNED and cii.band is UrgencyBand.OVERDUE


def test_I2_an_offline_root_ca_outranks_an_ephemeral_tls_cert() -> None:
    """Same algorithm class, same Y, same Z: only what the crypto is DOING differs."""
    root = _mosca(function=CryptoFunction.SIGNATURE, lifetime=20, y=1, retention=0)
    tls = _mosca(function=CryptoFunction.SIGNATURE, lifetime=0.25, y=1, retention=0)
    assert root.gap_years is not None and tls.gap_years is not None
    assert root.gap_years > tls.gap_years
    assert root.band is UrgencyBand.OVERDUE and tls.band is UrgencyBand.PLANNED
    assert root.mitigation == "migrate-or-resign"  # integrity: re-signing is recoverable
    assert tls.mitigation == "migrate-at-renewal"


def test_confidentiality_lateness_is_unrecoverable_integrity_is_not() -> None:
    assert _mosca(function=CryptoFunction.ENCRYPTION, retention=10).mitigation == "migrate"
    assert _mosca(function=CryptoFunction.SIGNATURE, lifetime=10).mitigation == "migrate-or-resign"


@pytest.mark.parametrize(
    ("fc", "fragment"),
    [
        (FindingClass.QUANTUM_SAFE, "quantum-safe"),
        (FindingClass.GROVER_AFFECTED, "informational"),
        (CW, "not a quantum finding"),
    ],
)
def test_I1_non_shor_classes_get_no_manufactured_quantum_gap(
    fc: FindingClass, fragment: str
) -> None:
    m = _mosca(fc, retention=30, y=5)
    assert m.band is UrgencyBand.NOT_APPLICABLE and m.gap_years is None and fragment in m.note


def test_a_classical_weak_asset_that_is_also_quantum_vulnerable_stays_in_the_pqc_programme() -> (
    None
):
    m = _mosca(CW, also_qv=True, retention=10)  # RSA-1024
    assert m.band is not UrgencyBand.NOT_APPLICABLE and m.gap_years is not None


def test_I8_unknown_is_a_coverage_gap_never_a_comfortable_band() -> None:
    m = _mosca(FindingClass.UNKNOWN)
    assert m.band is UrgencyBand.COVERAGE_GAP and m.gap_years is None


def test_I8_an_unresolvable_shelf_life_is_a_coverage_gap_not_planned() -> None:
    m = _mosca(function=CryptoFunction.KDF)  # derived key, no known consumers
    assert m.band is UrgencyBand.COVERAGE_GAP


# ---- CARAF D3 ----


def _ev(crit=3, dc=DataClass.CONFIDENTIAL, net=False, gap=0.0):  # type: ignore[no-untyped-def]
    return expected_value(
        system=make_system(criticality=crit, data_class=dc, internet_facing=net),
        gap_years=gap,
        policy=POLICY,
    )


def test_ev_is_the_product_of_its_four_factors() -> None:
    e = _ev(crit=4, dc=DataClass.RESTRICTED, net=True, gap=0.0)
    assert e.ev == pytest.approx(4 * 5 * 1.5 * 1.0)


def test_the_gap_factor_is_clamped_both_ways() -> None:
    assert _ev(gap=1000).gap_factor == 2.0 and _ev(gap=-1000).gap_factor == 0.5
    assert _ev(gap=5).gap_factor == pytest.approx(1.5)


def test_no_gap_is_neutral_not_zero() -> None:
    assert _ev(gap=None).gap_factor == 1.0  # type: ignore[arg-type]


def test_an_internet_facing_system_is_worth_more_than_an_internal_one() -> None:
    assert _ev(net=True).ev > _ev(net=False).ev


# ---- CARAF D4 ----


def _decide(
    *,
    fc=QV,
    authority=MigrationAuthority.SELF,
    crit=3,
    dc=DataClass.CONFIDENTIAL,  # type: ignore[no-untyped-def]
    net=False,
    y=1.0,
    retention=10.0,
    regimes=frozenset(),
):
    system = make_system(
        criticality=crit,
        data_class=dc,
        internet_facing=net,
        retention_years=retention,
        regimes=regimes,
    )
    shelf = shelf_life_years(CryptoFunction.KEY_AGREEMENT, system=system, policy=POLICY)
    z = z_effective(regulatory_regimes=regimes, criticality=crit, policy=POLICY)
    m = evaluate_mosca(
        finding_class=fc,
        also_quantum_vulnerable=False,
        shelf=shelf,
        y_years=y,
        z=z,
        as_of=AS_OF,
        policy=POLICY,
    )
    ev = (
        None
        if m.band is UrgencyBand.COVERAGE_GAP
        else expected_value(system=system, gap_years=m.gap_years, policy=POLICY)
    )
    return decide(
        finding_class=fc,
        authority=authority,
        mosca=m,
        ev=ev,
        y_years=y,
        criticality=crit,
        policy=POLICY,
    )


def test_a_high_value_internet_facing_asset_with_feasible_migration_is_migrate() -> None:
    d = _decide(crit=5, dc=DataClass.RESTRICTED, net=True, y=0.5)
    assert d.outcome is Outcome.MIGRATE and "EV" in d.reason


def test_a_low_value_asset_is_accepted_with_the_numbers_in_the_reason() -> None:
    d = _decide(crit=1, dc=DataClass.PUBLIC, retention=0.0)
    assert d.outcome is Outcome.ACCEPT and "below the risk tolerance" in d.reason


def test_high_value_but_effectively_blocked_is_a_compensating_control() -> None:
    d = _decide(crit=5, dc=DataClass.RESTRICTED, net=True, y=6.0)
    assert d.outcome is Outcome.COMPENSATING_CONTROL and "effectively blocked" in d.reason


def test_a_low_criticality_system_that_is_costly_to_migrate_is_phased_out() -> None:
    d = _decide(crit=2, dc=DataClass.RESTRICTED, net=False, y=4.0)  # EV ~ 2*5*1*gap, Y=4 < 5
    assert d.outcome is Outcome.PHASE_OUT and "decommission" in d.reason


def test_a_vendor_or_regulator_gated_high_value_asset_is_a_compensating_control() -> None:
    for authority in (MigrationAuthority.VENDOR, MigrationAuthority.REGULATOR_GATED):
        d = _decide(crit=5, dc=DataClass.RESTRICTED, net=True, authority=authority)
        assert d.outcome is Outcome.COMPENSATING_CONTROL


def test_I9_an_external_trust_anchor_is_never_scored_never_accepted() -> None:
    d = _decide(crit=1, dc=DataClass.PUBLIC, authority=MigrationAuthority.EXTERNAL_TRUST_ANCHOR)
    assert d.outcome is None and "I9" in d.reason


def test_I9_unknown_authority_is_triaged_never_defaulted_to_self() -> None:
    d = _decide(authority=MigrationAuthority.UNKNOWN)
    assert d.outcome is None and "triage" in d.reason


def test_I8_unclassified_assets_get_no_outcome_however_cheap() -> None:
    d = _decide(fc=FindingClass.UNKNOWN, crit=1, dc=DataClass.PUBLIC)
    assert d.outcome is None and "coverage gap" in d.reason


def test_a_grover_or_safe_asset_is_accept_and_says_so() -> None:
    assert _decide(fc=FindingClass.QUANTUM_SAFE).outcome is Outcome.ACCEPT
    g = _decide(fc=FindingClass.GROVER_AFFECTED, crit=5, dc=DataClass.RESTRICTED, net=True)
    assert g.outcome is Outcome.ACCEPT and "not a migrate-now finding" in g.reason


def test_every_decision_carries_a_nonempty_human_readable_reason() -> None:
    for fc in FindingClass:
        for authority in MigrationAuthority:
            assert _decide(fc=fc, authority=authority).reason.strip()


def test_the_four_outcomes_are_all_reachable() -> None:
    seen = {
        _decide(crit=5, dc=DataClass.RESTRICTED, net=True, y=0.5).outcome,
        _decide(crit=1, dc=DataClass.PUBLIC, retention=0.0).outcome,
        _decide(crit=5, dc=DataClass.RESTRICTED, net=True, y=6.0).outcome,
        _decide(crit=2, dc=DataClass.RESTRICTED, y=4.0).outcome,
    }
    assert seen == {
        Outcome.MIGRATE,
        Outcome.ACCEPT,
        Outcome.COMPENSATING_CONTROL,
        Outcome.PHASE_OUT,
    }
