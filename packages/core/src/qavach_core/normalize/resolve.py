"""ARCH.md §5.2 — resolve any tool's algorithm spelling to a canonical
`(algorithm_family, parameter_set, curve, primitive)` tuple. T-012.

Resolution order (ARCH.md §5.2), exactly:
  1. OID — if the claim carries one and it's in the alias table's OID
     section, that is authoritative. (The vendored registry has no
     family-level OID data — verified during T-011 — so this step
     consults `AliasTable.by_oid`, QAVACH's own curated table, not the
     vendored file.)
  2. Registry exact match on family name — no fuzzy matching, ever (§6.5).
  3. Alias table by name — `AliasTable.by_name`, T-013's curated overlay.
  4. Unresolvable → `UnresolvedAlgorithm`. Never dropped silently.

Curve resolution is a related but separate concern (`resolve_curve`) —
canonicalises to the OID where the vendored registry has one, else to its
own registry token (ARCH.md §5.2, A-18). The *full* alias-corpus test
proving `secp256r1`/`prime256v1`/`P-256`/`NIST P-256`/the OID all collapse
to one identity is T-015c's job; this function is the mechanism it tests.
"""

from __future__ import annotations

from dataclasses import dataclass

from qavach_core.normalize.aliases import AliasTable
from qavach_core.normalize.registry import CryptographyRegistry


@dataclass(frozen=True, slots=True)
class RawAlgorithmClaim:
    """What a collector reported, before normalisation."""

    name: str | None
    oid: str | None
    primitive: str | None = None  # self-reported, e.g. CDX algorithmProperties.primitive
    parameter_set: str | None = (
        None  # self-reported, e.g. CDX algorithmProperties.parameterSetIdentifier
    )


@dataclass(frozen=True, slots=True)
class ResolvedAlgorithm:
    algorithm_family: str
    parameter_set: str | None
    primitive: str | None
    resolution_method: str  # "oid" | "registry-exact" | "alias-table" — provenance, not a guess
    oid: str | None = None


@dataclass(frozen=True, slots=True)
class UnresolvedAlgorithm:
    """ARCH.md §5.2 step 4 — never silently dropped. The caller routes this
    to `FindingClass.UNKNOWN` and the unclassified bucket (invariant I8),
    never to a default "safe" value."""

    raw_name: str | None
    raw_oid: str | None
    reason: str


def resolve_algorithm(
    claim: RawAlgorithmClaim,
    *,
    registry: CryptographyRegistry,
    aliases: AliasTable,
) -> ResolvedAlgorithm | UnresolvedAlgorithm:
    # Step 1: OID, via QAVACH's own curated table (the vendored registry
    # has no family-level OID data — see module docstring).
    if claim.oid is not None:
        target = aliases.by_oid.get(claim.oid)
        if target is not None:
            return ResolvedAlgorithm(
                algorithm_family=target.family,
                parameter_set=target.parameter_set or claim.parameter_set,
                primitive=_resolve_primitive(claim, target.family, registry),
                resolution_method="oid",
                oid=claim.oid,
            )

    # Step 2: registry exact match on family name.
    if claim.name is not None:
        family_def = registry.family(claim.name)
        if family_def is not None:
            return ResolvedAlgorithm(
                algorithm_family=family_def.family,
                parameter_set=claim.parameter_set,  # the registry's family entries don't carry one
                primitive=_resolve_primitive(claim, family_def.family, registry),
                resolution_method="registry-exact",
                oid=claim.oid,
            )

    # Step 3: alias table by name.
    if claim.name is not None:
        target = aliases.by_name.get(claim.name)
        if target is not None:
            return ResolvedAlgorithm(
                algorithm_family=target.family,
                parameter_set=target.parameter_set or claim.parameter_set,
                primitive=_resolve_primitive(claim, target.family, registry),
                resolution_method="alias-table",
                oid=claim.oid,
            )

    # Step 4: unresolvable. Never dropped.
    return UnresolvedAlgorithm(
        raw_name=claim.name,
        raw_oid=claim.oid,
        reason="no OID alias, no registry-exact family match, no name alias",
    )


def _resolve_primitive(
    claim: RawAlgorithmClaim, family: str, registry: CryptographyRegistry
) -> str | None:
    """Trust a claim's self-reported primitive first — a tool that already
    knows it observed a MAC call site is not less authoritative than us
    guessing from the family name. Fall back to the registry only when the
    family has exactly one possible primitive; a family like AES spans
    several (block-cipher/ae/key-wrap/mac) and picking one without the
    claim's own mode/context would be a guess, not a resolution."""
    if claim.primitive is not None:
        return claim.primitive
    family_def = registry.family(family)
    if family_def is not None and len(family_def.primitives) == 1:
        return next(iter(family_def.primitives))
    return None


@dataclass(frozen=True, slots=True)
class ResolvedCurve:
    canonical: str  # the OID when the registry has one, else the registry's own token
    resolution_method: str  # "registry"


@dataclass(frozen=True, slots=True)
class UnresolvedCurve:
    raw_name: str | None
    reason: str


def resolve_curve(
    spelling: str | None,
    *,
    registry: CryptographyRegistry,
    aliases: AliasTable | None = None,
) -> ResolvedCurve | UnresolvedCurve | None:
    """Returns None when no curve was claimed at all — that is not the
    same as an unresolved curve (ARCH.md §4.2's "never render 0 for not
    applicable" spirit applies here too: absence and failure are distinct
    states, never conflated).

    Checks the vendored registry first (which already cross-references
    some aliases itself, e.g. P-256/secp256r1/prime256v1), then
    `aliases.curve_aliases` for spellings the registry doesn't know about
    (e.g. X25519 as a spelling of Curve25519 — T-013/T-015c)."""
    if spelling is None:
        return None
    curve_def = registry.curve(spelling)
    if curve_def is None and aliases is not None:
        canonical_spelling = aliases.curve_aliases.get(spelling)
        if canonical_spelling is not None:
            curve_def = registry.curve(canonical_spelling)
    if curve_def is None:
        return UnresolvedCurve(raw_name=spelling, reason="not found in the vendored registry")
    return ResolvedCurve(canonical=curve_def.canonical, resolution_method="registry")
