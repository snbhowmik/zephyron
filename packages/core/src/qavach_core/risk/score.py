"""One asset -> one score, composed from the pieces. Pure and deterministic.

`score_asset` takes the `PolicySnapshot` and `as_of` explicitly and reads
nothing else - no clock, no globals, no live policy files (T-068) - so the same
inputs give byte-identical output on any machine (NFR-09). A score is per
`(asset, system)` pair: an asset shared by two systems is scored in each,
because risk is computed per asset but decided per system (ARCH.md 4).

An asset with no bound system is **not scored against an invented context**: it
gets a coverage-gap result naming the reason, and stays visible (the
"unassigned" bucket, T-051).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date

from qavach_core.model.enums import CryptoFunction, FindingClass, MigrationAuthority
from qavach_core.model.identity import AssetIdentity
from qavach_core.model.locus import Locus
from qavach_core.model.system import System
from qavach_core.policy import PolicySnapshot
from qavach_core.risk.caraf import Decision, ExpectedValue, decide, expected_value
from qavach_core.risk.effort import EffortFacts, MigrationEstimate, estimate_y
from qavach_core.risk.explain import Explanation
from qavach_core.risk.mosca import MoscaResult, UrgencyBand, evaluate_mosca
from qavach_core.risk.shelf_life import ShelfLife, shelf_life_years
from qavach_core.risk.zeff import ZEffective, z_effective


@dataclass(frozen=True, slots=True)
class AssetRiskInput:
    identity: AssetIdentity
    finding_class: FindingClass
    also_quantum_vulnerable: bool
    function: CryptoFunction | None
    authority: MigrationAuthority
    loci: tuple[Locus, ...]
    system: System | None
    artefact_lifetime_years: float | None = None
    consumers: tuple[ShelfLife, ...] = ()
    effort_facts: EffortFacts | None = None


@dataclass(frozen=True, slots=True)
class AssetRiskScore:
    identity: AssetIdentity
    system_id: str | None
    band: UrgencyBand
    outcome: str | None
    reason: str
    shelf_life: ShelfLife | None
    z: ZEffective | None
    y: MigrationEstimate | None
    mosca: MoscaResult | None
    ev: ExpectedValue | None
    decision: Decision | None

    def explanations(self) -> tuple[Explanation, ...]:
        parts = (
            self.shelf_life and self.shelf_life.explanation,
            self.z and self.z.explanation,
            self.y and self.y.explanation,
            self.mosca and self.mosca.explanation,
            self.ev and self.ev.explanation,
            self.decision and self.decision.explanation,
        )
        return tuple(p for p in parts if p)


@dataclass(slots=True)
class ScoreMemo:
    """Per-run caches for what depends only on the *system*, not the asset:
    `Z_effective` (regimes + criticality + scenario) and shelf life (function +
    system + artefact lifetime). Scoring 50k assets across a few dozen systems
    recomputes these thousands of times otherwise. A memo is valid for one
    `(policy, as_of, scenario)` only; make a new one when any of them changes."""

    z: dict[tuple[object, ...], ZEffective] = field(default_factory=dict)
    shelf: dict[tuple[object, ...], ShelfLife] = field(default_factory=dict)


def score_asset(
    asset: AssetRiskInput,
    *,
    policy: PolicySnapshot,
    as_of: date,
    scenario: str | None = None,
    explain: bool = True,
    memo: ScoreMemo | None = None,
) -> AssetRiskScore:
    """`explain=False` is the fast path (`policy/simulate`): identical numbers,
    identical bands and outcomes - same code - but no explanation prose is built.
    `tests/core/test_score.py` asserts the two paths agree."""
    if asset.system is None:
        reason = "no system is bound to this asset: business context is missing (unassigned bucket)"
        return AssetRiskScore(
            asset.identity,
            None,
            UrgencyBand.COVERAGE_GAP,
            None,
            reason,
            None,
            None,
            None,
            None,
            None,
            None,
        )

    system = asset.system
    shelf_key = (asset.function, system.id, system.retention_years, asset.artefact_lifetime_years)
    if memo is not None and not asset.consumers and shelf_key in memo.shelf:
        shelf = memo.shelf[shelf_key]
    else:
        shelf = shelf_life_years(
            asset.function,
            system=system,
            policy=policy,
            artefact_lifetime_years=asset.artefact_lifetime_years,
            consumers=asset.consumers,
        )
        if memo is not None and not asset.consumers:
            memo.shelf[shelf_key] = shelf
    z_key = (system.regulatory_regimes, system.criticality, scenario)
    if memo is not None and z_key in memo.z:
        z = memo.z[z_key]
    else:
        z = z_effective(
            regulatory_regimes=system.regulatory_regimes,
            criticality=system.criticality,
            policy=policy,
            scenario=scenario,
        )
        if memo is not None:
            memo.z[z_key] = z
    y = estimate_y(
        asset.loci,
        authority=asset.authority,
        occurrence_count=len(asset.loci),
        policy=policy,
        facts=asset.effort_facts,
        explain=explain,
    )
    mosca = evaluate_mosca(
        finding_class=asset.finding_class,
        also_quantum_vulnerable=asset.also_quantum_vulnerable,
        shelf=shelf,
        y_years=y.years,
        z=z,
        as_of=as_of,
        policy=policy,
        explain=explain,
    )
    ev = (
        None
        if mosca.band is UrgencyBand.COVERAGE_GAP
        else expected_value(
            system=system, gap_years=mosca.gap_years, policy=policy, explain=explain
        )
    )
    decision = decide(
        finding_class=asset.finding_class,
        authority=asset.authority,
        mosca=mosca,
        ev=ev,
        y_years=y.years,
        criticality=system.criticality,
        policy=policy,
        explain=explain,
    )
    return AssetRiskScore(
        asset.identity,
        system.id,
        mosca.band,
        decision.outcome.value if decision.outcome else None,
        decision.reason,
        shelf,
        z,
        y,
        mosca,
        ev,
        decision,
    )


def score_estate(
    assets: Iterable[AssetRiskInput],
    *,
    policy: PolicySnapshot,
    as_of: date,
    scenario: str | None = None,
    explain: bool = True,
) -> Sequence[AssetRiskScore]:
    memo = ScoreMemo()
    return [
        score_asset(a, policy=policy, as_of=as_of, scenario=scenario, explain=explain, memo=memo)
        for a in assets
    ]
