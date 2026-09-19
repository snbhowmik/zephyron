"""ARCH.md §7.4 - `Y`, migration time in years. T-063.

**A planning heuristic, not a measurement.** `Y` is a base effort by locus kind
multiplied by blocker factors from `migration_effort.yaml`; the weights are
uncalibrated (OQ-02). Every `Explanation` this returns is flagged
`heuristic=True` so a surface cannot present it as fact, and every multiplier
cites the ARCH.md / DST factor it comes from.

Base effort is the **maximum** over an asset's loci (independent sites are
worked in parallel), and the occurrence-count multiplier then accounts for the
extra blast radius. Several factors are observable from the asset itself
(an HSM locus is hardware-bound; `MigrationAuthority.VENDOR` is a third-party
dependency); the rest are context flags the caller supplies - a factor that
is not known is *not* applied, and the explanation lists exactly which were.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from qavach_core.model.enums import MigrationAuthority
from qavach_core.model.locus import (
    CloudLocus,
    ContainerLocus,
    DependencyLocus,
    FileLocus,
    HostLocus,
    HsmLocus,
    Locus,
    NetworkLocus,
    RuntimeLocus,
    SourceLocus,
)
from qavach_core.policy import Cited, PolicySnapshot
from qavach_core.risk.explain import NO_EXPLANATION, Explanation, refs

_LOCUS_KIND: dict[type, str] = {
    SourceLocus: "source",
    DependencyLocus: "dependency",
    ContainerLocus: "container",
    RuntimeLocus: "runtime",
    NetworkLocus: "network",
    CloudLocus: "cloud",
    HsmLocus: "hsm",
    FileLocus: "file",
    HostLocus: "host",
}


def locus_kind(locus: Locus) -> str:
    return _LOCUS_KIND[type(locus)]


@dataclass(frozen=True, slots=True)
class EffortFacts:
    """Context the caller knows and the asset itself does not carry."""

    library_without_pqc: bool = False
    protocol_not_standardised: bool = False
    signature_size_sensitive: bool = False
    wire_format_change: bool = False
    high_handshake_frequency: bool = False


@dataclass(frozen=True, slots=True)
class MigrationEstimate:
    years: float
    base_years: float
    base_locus_kind: str
    applied: tuple[tuple[str, float], ...]
    explanation: Explanation


def estimate_y(
    loci: Sequence[Locus],
    *,
    authority: MigrationAuthority,
    occurrence_count: int,
    policy: PolicySnapshot,
    facts: EffortFacts | None = None,
    explain: bool = True,
) -> MigrationEstimate:
    if not loci:
        raise ValueError("estimate_y needs at least one locus")
    facts = facts or EffortFacts()
    used: list[Cited] = []

    def base_for(kind: str) -> tuple[float, Cited]:
        node = policy.node(f"migration_effort.base_years.{kind}")
        return float(node.value), node

    bases = [(kind, *base_for(kind)) for kind in sorted({locus_kind(item) for item in loci})]
    base_kind, base_years, base_node = max(bases, key=lambda b: (b[1], b[0]))
    used.append(base_node)

    hardware = any(isinstance(item, HsmLocus) for item in loci)
    flags: list[tuple[str, bool]] = [
        ("hardware_bound", hardware),
        ("third_party_saas", authority is MigrationAuthority.VENDOR),
        ("library_without_pqc", facts.library_without_pqc),
        ("protocol_not_standardised", facts.protocol_not_standardised),
        ("signature_size_sensitive", facts.signature_size_sensitive),
        ("wire_format_change", facts.wire_format_change),
        ("high_handshake_frequency", facts.high_handshake_frequency),
    ]
    threshold_node = policy.node("migration_effort.thresholds.high_occurrence_count_over")
    used.append(threshold_node)
    flags.append(("high_occurrence_count", occurrence_count > int(threshold_node.value)))

    years = base_years
    applied: list[tuple[str, float]] = []
    steps = (
        [f"base effort {base_years} y from the {base_kind!r} locus (max over {len(loci)} loci)"]
        if explain
        else []
    )
    for name, active in flags:
        if not active:
            continue
        node = policy.node(f"migration_effort.multipliers.{name}")
        used.append(node)
        factor = float(node.value)
        years *= factor
        applied.append((name, factor))
        if explain:
            steps.append(f"x{factor} {name}")
    if not applied:
        node = policy.node("migration_effort.multipliers.pqc_library_available")
        used.append(node)
        if explain:
            steps.append(f"no blocker factor known: x{node.value} (drop-in assumed)")

    return MigrationEstimate(
        years=years,
        base_years=base_years,
        base_locus_kind=base_kind,
        applied=tuple(applied),
        explanation=(
            Explanation(
                name="y_estimate",
                formula="Y = base_years(locus) x product(applicable multipliers)",
                inputs={
                    "loci": len(loci),
                    "authority": authority.value,
                    "occurrence_count": occurrence_count,
                    "known_factors": sorted(n for n, on in flags if on),
                },
                policy=refs(used),
                steps=tuple(steps),
                heuristic=True,
            )
            if explain
            else NO_EXPLANATION
        ),
    )
