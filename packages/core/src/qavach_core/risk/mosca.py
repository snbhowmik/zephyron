"""ARCH.md §7.2 - Mosca's inequality, applied per asset. T-064.

If `X + Y > Z` you are already late. `gap = X + Y - Z_effective` in years; a
positive gap is lateness, a negative gap is remaining slack.

Mosca is a *quantum* argument, so it is evaluated only for assets a quantum
computer changes (I1). The other classes get an explicit non-numeric verdict
rather than a manufactured gap:

* `CLASSICAL_WEAK`   not applicable - broken today, fix now, not a Shor finding
  (unless the asset is *also* quantum-vulnerable: RSA-1024 keeps its place in
  the PQC programme, ARCH.md 7.1);
* `GROVER_AFFECTED`  not applicable - informational, never "migrate now";
* `QUANTUM_SAFE`     not applicable - confirmed;
* `UNKNOWN`          `coverage-gap` - never a comfortable band (I8).

An incomplete shelf life (unknown function, derived key with no known consumer)
is also a coverage gap: `x = 0` from missing information must not read as
"planned".

Mitigation follows which channel dominates (ARCH.md 7.2, A-4): a confidentiality
shelf life is `migrate` (harvested ciphertext cannot be un-harvested); an
integrity one is `migrate-or-resign` (re-signing before `Z` is a valid
mitigation). Zero shelf life is `migrate-at-renewal`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from qavach_core.model.enums import FindingClass
from qavach_core.policy import PolicySnapshot
from qavach_core.risk.explain import Explanation, refs
from qavach_core.risk.shelf_life import ShelfLife
from qavach_core.risk.zeff import ZEffective


class UrgencyBand(StrEnum):
    OVERDUE = "overdue"
    IMMINENT = "imminent"
    PLANNED = "planned"
    NOT_APPLICABLE = "not-applicable"
    COVERAGE_GAP = "coverage-gap"


@dataclass(frozen=True, slots=True)
class MoscaResult:
    band: UrgencyBand
    gap_years: float | None
    x_conf: float
    x_integ: float
    y_years: float
    z_years: float
    mitigation: str | None
    note: str
    explanation: Explanation

    @property
    def evaluated(self) -> bool:
        return self.gap_years is not None


def evaluate_mosca(
    *,
    finding_class: FindingClass,
    also_quantum_vulnerable: bool,
    shelf: ShelfLife,
    y_years: float,
    z: ZEffective,
    as_of: date,
    policy: PolicySnapshot,
) -> MoscaResult:
    imminent_node = policy.node("scoring.mosca.imminent_within_years")
    z_years = z.years_from(as_of)
    inputs = {
        "finding_class": finding_class.value,
        "also_quantum_vulnerable": also_quantum_vulnerable,
        "x_conf": shelf.x_conf,
        "x_integ": shelf.x_integ,
        "y_years": y_years,
        "z_effective": z.z_date.isoformat(),
        "z_bound_by": z.bound_by,
        "as_of": as_of.isoformat(),
    }

    def result(
        band: UrgencyBand,
        gap: float | None,
        mitigation: str | None,
        note: str,
        steps: tuple[str, ...],
    ) -> MoscaResult:
        return MoscaResult(
            band=band,
            gap_years=gap,
            x_conf=shelf.x_conf,
            x_integ=shelf.x_integ,
            y_years=y_years,
            z_years=z_years,
            mitigation=mitigation,
            note=note,
            explanation=Explanation(
                name="mosca",
                formula="gap = max(x_conf, x_integ) + Y - Z_effective_years; late if gap > 0",
                inputs=inputs,
                policy=refs([imminent_node]),
                steps=steps,
                heuristic=True,
            ),
        )

    if finding_class is FindingClass.UNKNOWN:
        note = "could not be classified: a coverage failure, not a risk verdict (I8)"
        return result(UrgencyBand.COVERAGE_GAP, None, None, note, (note,))
    if finding_class is FindingClass.QUANTUM_SAFE:
        note = "already quantum-safe: confirm and record"
        return result(UrgencyBand.NOT_APPLICABLE, None, None, note, (note,))
    if finding_class is FindingClass.GROVER_AFFECTED:
        note = "informational: Grover halves symmetric strength; prefer 256-bit for long-lived data"
        return result(UrgencyBand.NOT_APPLICABLE, None, None, note, (note,))
    if finding_class is FindingClass.CLASSICAL_WEAK and not also_quantum_vulnerable:
        note = "classically broken today: fix now; this is not a quantum finding"
        return result(UrgencyBand.NOT_APPLICABLE, None, None, note, (note,))

    if not shelf.complete:
        note = f"shelf life could not be established ({shelf.basis}): a coverage gap, not 'planned'"
        return result(UrgencyBand.COVERAGE_GAP, None, None, note, (note,))

    x = shelf.x
    gap = x + y_years - z_years
    if gap > 0:
        band = UrgencyBand.OVERDUE
    elif gap > -float(imminent_node.value):
        band = UrgencyBand.IMMINENT
    else:
        band = UrgencyBand.PLANNED

    if x == 0:
        mitigation = "migrate-at-renewal"
    elif shelf.x_conf >= shelf.x_integ:
        mitigation = "migrate"
    else:
        mitigation = "migrate-or-resign"

    steps = (
        f"X = max({shelf.x_conf}, {shelf.x_integ}) = {x} y ({shelf.basis})",
        f"Y = {y_years} y (planning heuristic)",
        f"Z_effective = {z.z_date.isoformat()} = {z_years:.3f} y from "
        f"{as_of.isoformat()} ({z.bound_by})",
        f"gap = {x} + {y_years} - {z_years:.3f} = {gap:.3f} y -> {band.value}",
    )
    return result(band, gap, mitigation, steps[-1], steps)
