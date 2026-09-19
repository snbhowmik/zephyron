"""ARCH.md §7.5 - CARAF D3 (expected value) and D4 (mitigation outcome). T-065, T-066.

CARAF is a five-dimension framework (Ma, Colon, Dera, Rashidi, Garg,
*Journal of Cybersecurity* 7(1), 2021), and it composes with Mosca rather than
competing with it. **D3** estimates the expected value of the asset being
compromised:

    EV = criticality x sensitivity x exposure x mosca_gap_factor

**D4** then picks the mitigation commensurate with that value. `Accept` and
`Phase out` are first-class outcomes: a tool whose only answer is "migrate
everything" is useless to an organisation with a finite budget, and saying
"leave this alone" is the differentiator (ARCH.md 7.5).

Rules are ordered and deterministic, and **every outcome carries a
human-readable reason** with the numbers that produced it. Ordering matters:
non-actionable and unscoreable assets are settled first, so no threshold can
ever turn an external trust anchor or an unknown into a comfortable "accept"
(I8, I9).

`EV`, the thresholds and `Y` are planning heuristics (`heuristic=True`), and the
exposure factor uses only `System.internet_facing` - `System` has no "partner"
flag, so the 1.2 tier exists in policy but is not selected automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from qavach_core.model.enums import FindingClass, MigrationAuthority
from qavach_core.model.system import System
from qavach_core.policy import Cited, PolicySnapshot
from qavach_core.risk.explain import Explanation, refs
from qavach_core.risk.mosca import MoscaResult, UrgencyBand


class Outcome(StrEnum):
    MIGRATE = "migrate"
    COMPENSATING_CONTROL = "compensating-control"
    ACCEPT = "accept"
    PHASE_OUT = "phase-out"


@dataclass(frozen=True, slots=True)
class ExpectedValue:
    ev: float
    criticality: int
    sensitivity: int
    exposure: float
    gap_factor: float
    explanation: Explanation


def expected_value(
    *, system: System, gap_years: float | None, policy: PolicySnapshot
) -> ExpectedValue:
    """`gap_years is None` (no Mosca gap - classical/Grover/safe assets) gives a
    neutral gap factor of 1.0: the value of the *system* still matters, the
    quantum timing simply does not modulate it."""
    used: list[Cited] = []
    sens_node = policy.node(f"scoring.caraf.sensitivity_{system.data_classification.value}")
    exposure_node = policy.node(
        "scoring.caraf.exposure_internet_facing"
        if system.internet_facing
        else "scoring.caraf.exposure_internal"
    )
    scale_node = policy.node("scoring.caraf.gap_factor_scale_years")
    min_node = policy.node("scoring.caraf.gap_factor_min")
    max_node = policy.node("scoring.caraf.gap_factor_max")
    used += [sens_node, exposure_node, scale_node, min_node, max_node]

    sensitivity = int(sens_node.value)
    exposure = float(exposure_node.value)
    if gap_years is None:
        gap_factor = 1.0
        gap_step = "no Mosca gap for this finding class: gap factor 1.0 (neutral)"
    else:
        raw = 1.0 + gap_years / float(scale_node.value)
        gap_factor = min(max(raw, float(min_node.value)), float(max_node.value))
        gap_step = (
            f"gap factor = clamp(1 + {gap_years:.3f}/{scale_node.value}, "
            f"{min_node.value}, {max_node.value}) = {gap_factor:.3f}"
        )
    exposure_label = "internet-facing" if system.internet_facing else "internal"
    ev = system.criticality * sensitivity * exposure * gap_factor
    return ExpectedValue(
        ev=ev,
        criticality=system.criticality,
        sensitivity=sensitivity,
        exposure=exposure,
        gap_factor=gap_factor,
        explanation=Explanation(
            name="caraf_d3_expected_value",
            formula="EV = criticality x sensitivity x exposure x mosca_gap_factor",
            inputs={
                "criticality": system.criticality,
                "data_classification": system.data_classification.value,
                "internet_facing": system.internet_facing,
                "gap_years": gap_years,
            },
            policy=refs(used),
            steps=(
                f"sensitivity {sensitivity} ({system.data_classification.value})",
                f"exposure {exposure} ({exposure_label})",
                gap_step,
                f"EV = {system.criticality} x {sensitivity} x {exposure} x "
                f"{gap_factor:.3f} = {ev:.3f}",
            ),
            heuristic=True,
        ),
    )


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: Outcome | None
    """`None` means no outcome is issued - the asset is inventory-only or needs
    triage - and `reason` says which."""
    reason: str
    explanation: Explanation


def decide(
    *,
    finding_class: FindingClass,
    authority: MigrationAuthority,
    mosca: MoscaResult,
    ev: ExpectedValue | None,
    y_years: float,
    criticality: int,
    policy: PolicySnapshot,
) -> Decision:
    accept_node = policy.node("risk_tolerance.accept_below_ev")
    blocked_node = policy.node("risk_tolerance.blocked_migration_min_y_years")
    crit_node = policy.node("risk_tolerance.phase_out_max_criticality")
    ratio_node = policy.node("risk_tolerance.phase_out_ev_per_year_of_effort")
    used = [accept_node, blocked_node, crit_node, ratio_node]
    inputs = {
        "finding_class": finding_class.value,
        "authority": authority.value,
        "band": mosca.band.value,
        "ev": None if ev is None else ev.ev,
        "y_years": y_years,
        "criticality": criticality,
    }

    def out(outcome: Outcome | None, reason: str) -> Decision:
        return Decision(
            outcome,
            reason,
            Explanation(
                name="caraf_d4_outcome",
                formula="ordered rules: not-actionable > coverage gap > safe/informational > "
                "vendor/regulator-blocked > below tolerance > migration blocked > "
                "phase out > migrate",
                inputs=inputs,
                policy=refs(used),
                steps=(reason,),
                heuristic=True,
            ),
        )

    if authority is MigrationAuthority.EXTERNAL_TRUST_ANCHOR:
        return out(
            None, "inventoried only: the operator cannot migrate an external trust anchor (I9)"
        )
    if authority is MigrationAuthority.UNKNOWN:
        return out(
            None, "migration authority unknown: triage queue, never defaulted to 'self' (I9)"
        )
    if mosca.band is UrgencyBand.COVERAGE_GAP or ev is None:
        return out(None, f"coverage gap, not scored: {mosca.note}")
    if finding_class is FindingClass.QUANTUM_SAFE:
        return out(Outcome.ACCEPT, "already quantum-safe: confirm and record")
    if finding_class is FindingClass.GROVER_AFFECTED:
        return out(
            Outcome.ACCEPT,
            "Grover-affected: informational, prefer 256-bit for long-lived data; "
            "not a migrate-now finding",
        )

    accept_below = float(accept_node.value)
    if authority in (MigrationAuthority.VENDOR, MigrationAuthority.REGULATOR_GATED):
        who = "the vendor" if authority is MigrationAuthority.VENDOR else "a regulator"
        if ev.ev >= accept_below:
            return out(
                Outcome.COMPENSATING_CONTROL,
                f"EV {ev.ev:.1f} >= tolerance {accept_below} but the change is gated on {who}: "
                "isolate, shorten key lifetimes, monitor, and track the dependency",
            )
        return out(
            Outcome.ACCEPT,
            f"EV {ev.ev:.1f} < tolerance {accept_below} and gated on {who}: accept and track",
        )
    if ev.ev < accept_below:
        return out(Outcome.ACCEPT, f"EV {ev.ev:.1f} is below the risk tolerance {accept_below}")
    if y_years >= float(blocked_node.value):
        return out(
            Outcome.COMPENSATING_CONTROL,
            f"EV {ev.ev:.1f} is above tolerance but Y = {y_years:.1f} y >= "
            f"{blocked_node.value} y: migration is effectively blocked",
        )
    if criticality <= int(crit_node.value) and ev.ev < float(ratio_node.value) * y_years:
        return out(
            Outcome.PHASE_OUT,
            f"EV {ev.ev:.1f} < {ratio_node.value} x Y ({y_years:.1f} y) on a low-criticality "
            "system: decommission rather than migrate",
        )
    return out(Outcome.MIGRATE, f"EV {ev.ev:.1f} is above tolerance and migration is feasible")
