"""Claims -> assets: the step `reconcile/merge.py` deferred. Pure.

Takes what collectors observed (`ClaimInput`) and produces reconciled, classified
`CryptoAsset`s. Per claim: resolve the algorithm (`normalize.resolve`), resolve a
curve, canonicalise, compute identity, group, merge, classify, derive authority.

**Nothing is dropped (I4, I8).** Every claim ends in exactly one asset. A claim
whose algorithm cannot be resolved becomes an asset of class `UNKNOWN` carrying
its raw name and every occurrence, so it appears in every aggregate as a
coverage failure rather than vanishing; a family with no determinable function
gets `function=None` and is scored at its worst plausible reading. Tests assert
conservation: the occurrences across all assets equal the claims in.

Decisions (recorded in NOTE.md):

* **A tool-reported OID is evidence for resolving the family, not identity.**
  Real output showed tools disagree on OIDs (`cdxgen` labels SHA-1 with a Novell
  OID). The asset's `oid` is set only when *our* curated OID table resolved it.
* Families with one fixed parameter (MD5 = 128) are canonicalised, because tools
  disagree on whether to report it and that fragmented one algorithm into
  several assets on real data.
* A claim's own `primitive` outranks the family default function table.
* Only algorithm assets can be assembled from a `ClaimInput`: certificates,
  protocols and key material need fields (subject, validity, SPKI) the claim
  shape does not carry.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from qavach_core.model.asset import CryptoAsset, Occurrence
from qavach_core.model.enums import AssetType, ConfidenceTier, CryptoFunction, FindingClass
from qavach_core.model.identity import AssetIdentity
from qavach_core.model.locus import Locus
from qavach_core.normalize.aliases import AliasTable
from qavach_core.normalize.function import classify_function
from qavach_core.normalize.registry import CryptographyRegistry
from qavach_core.normalize.resolve import (
    RawAlgorithmClaim,
    ResolvedAlgorithm,
    ResolvedCurve,
    resolve_algorithm,
    resolve_curve,
)
from qavach_core.reconcile.adjudicate import Adjudication, AdjudicationOutcome, apply_adjudications
from qavach_core.reconcile.authority import AuthorityContext, derive_migration_authority
from qavach_core.reconcile.identity import IdentityClaim, asset_identity
from qavach_core.reconcile.merge import MergeResult, OccurrenceClaim, merge
from qavach_core.risk.classify import ClassificationRules, classify


@dataclass(frozen=True, slots=True)
class ClaimInput:
    """What one collector observed at one locus - the collector-agnostic shape
    the worker fills from each `RawClaim` (which lives in `packages/collectors`,
    outside what core may import)."""

    name: str | None
    locus: Locus
    collector: str
    tool_version: str
    confidence: ConfidenceTier
    detection_method: str
    raw_ref: str
    observed_at: datetime
    oid: str | None = None
    primitive: str | None = None
    parameter_set: str | None = None
    mode: str | None = None
    padding: str | None = None


@dataclass(frozen=True, slots=True)
class FamilyFunctions:
    default_function: Mapping[str, CryptoFunction]
    fixed_parameter_set: Mapping[str, str]
    curve_families: frozenset[str]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> FamilyFunctions:
        defaults: dict[str, CryptoFunction] = {}
        for function_name, families in data["default_function"].items():
            function = CryptoFunction(function_name)
            for family in families:
                if family in defaults:
                    raise ValueError(f"family {family!r} has two default functions")
                defaults[family] = function
        return FamilyFunctions(
            default_function=defaults,
            fixed_parameter_set={
                str(k): str(v) for k, v in data.get("fixed_parameter_set", {}).items()
            },
            curve_families=frozenset(data.get("curve_families", [])),
        )


@dataclass(frozen=True, slots=True)
class AssembleKnowledge:
    registry: CryptographyRegistry
    aliases: AliasTable
    rules: ClassificationRules
    family_functions: FamilyFunctions


@dataclass(frozen=True, slots=True)
class AssembleResult:
    assets: tuple[CryptoAsset, ...]
    merges: Mapping[AssetIdentity, MergeResult]
    unresolved: tuple[str, ...]
    """Raw names that did not resolve to a family - already present in `assets`
    as `UNKNOWN`; listed here so a UI can show *what* was not understood."""
    adjudications: AdjudicationOutcome | None = None
    """What happened to each stored operator ruling on this re-merge: applied,
    reopened (new evidence / the code changed), orphaned or superseded - never
    silently applied or dropped (T-025)."""


AuthorityFor = Callable[[AssetIdentity, Sequence[Locus]], AuthorityContext]


def _default_authority(_identity: AssetIdentity, _loci: Sequence[Locus]) -> AuthorityContext:
    """Scans target things the operator pointed QAVACH at, so by default a locus
    is operator-owned. Callers that know better (a certificate chaining to a
    public root, an OEM image) pass their own."""
    return AuthorityContext(locus_in_operator_owned_context=True)


@dataclass(frozen=True, slots=True)
class _Prepared:
    claim: ClaimInput
    identity: AssetIdentity
    family: str
    parameter_set: str | None
    curve: str | None
    function: CryptoFunction | None
    oid: str | None
    resolved: bool


def _prepare(claim: ClaimInput, k: AssembleKnowledge) -> _Prepared:
    raw = RawAlgorithmClaim(
        name=claim.name, oid=claim.oid, primitive=claim.primitive, parameter_set=claim.parameter_set
    )
    result = resolve_algorithm(raw, registry=k.registry, aliases=k.aliases)

    if not isinstance(result, ResolvedAlgorithm):
        label = claim.name or claim.oid or "<unnamed>"
        function = classify_function(claim.primitive)
        identity = asset_identity(
            IdentityClaim(
                asset_type=AssetType.ALGORITHM,
                algorithm_family=f"unresolved:{label.lower()}",
                parameter_set=claim.parameter_set,
            )
        )
        return _Prepared(claim, identity, label, claim.parameter_set, None, function, None, False)

    family, parameter_set, curve = result.algorithm_family, result.parameter_set, None
    if family in k.family_functions.curve_families and parameter_set is not None:
        resolved_curve = resolve_curve(parameter_set, registry=k.registry, aliases=k.aliases)
        if isinstance(resolved_curve, ResolvedCurve):
            curve, parameter_set = resolved_curve.canonical, None
    fixed = k.family_functions.fixed_parameter_set.get(family)
    if fixed is not None and parameter_set in (None, fixed):
        parameter_set = fixed

    function = classify_function(result.primitive) or k.family_functions.default_function.get(
        family
    )
    identity = asset_identity(
        IdentityClaim(
            asset_type=AssetType.ALGORITHM,
            algorithm_family=family,
            parameter_set=parameter_set,
            curve=curve,
            primitive=result.primitive,
            oid=result.oid,
        )
    )
    trusted_oid = result.oid if result.resolution_method == "oid" else None
    return _Prepared(claim, identity, family, parameter_set, curve, function, trusted_oid, True)


def assemble(
    claims: Iterable[ClaimInput],
    knowledge: AssembleKnowledge,
    *,
    authority_for: AuthorityFor = _default_authority,
    adjudications: Sequence[Adjudication] = (),
) -> AssembleResult:
    prepared = [_prepare(c, knowledge) for c in claims]
    by_identity: dict[AssetIdentity, list[_Prepared]] = defaultdict(list)
    for p in prepared:
        by_identity[p.identity].append(p)

    ordered_identities = sorted(by_identity, key=lambda i: (i.kind.value, i.key))
    raw_merges: list[MergeResult] = []
    for identity in ordered_identities:
        group = by_identity[identity]
        raw_merges.append(
            merge(
                identity,
                [
                    OccurrenceClaim(
                        identity=identity,
                        locus=p.claim.locus,
                        collector=p.claim.collector,
                        tool_version=p.claim.tool_version,
                        confidence=p.claim.confidence,
                        detection_method=p.claim.detection_method,
                        raw_ref=p.claim.raw_ref,
                        observed_at=p.claim.observed_at,
                        mode=p.claim.mode,
                        padding=p.claim.padding,
                    )
                    for p in group
                ],
            )
        )
    outcome = apply_adjudications(raw_merges, adjudications) if adjudications else None
    final_merges = list(outcome.results) if outcome else raw_merges

    merges: dict[AssetIdentity, MergeResult] = {}
    assets: list[CryptoAsset] = []
    unresolved: set[str] = set()

    for identity, merged in zip(ordered_identities, final_merges, strict=True):
        group = by_identity[identity]
        head = group[0]
        merges[identity] = merged

        if head.resolved:
            classification = classify(head.family, head.parameter_set, rules=knowledge.rules)
            finding = classification.finding_class
        else:
            finding = FindingClass.UNKNOWN
            unresolved.add(head.family)

        loci = [p.claim.locus for p in group]
        authority, basis = derive_migration_authority(authority_for(identity, loci))
        function = next((p.function for p in group if p.function is not None), None)

        ordered = sorted(
            merged.occurrences,
            key=lambda o: (repr(o.locus), o.collector, o.tool_version, o.raw_ref),
        )
        assets.append(
            CryptoAsset(
                identity=identity,
                asset_type=AssetType.ALGORITHM,
                function=function,
                algorithm_family=head.family,
                parameter_set=head.parameter_set,
                curve=head.curve,
                mode=merged.concluded_mode.value if merged.concluded_mode else None,
                padding=merged.concluded_padding.value if merged.concluded_padding else None,
                oid=next((p.oid for p in group if p.oid), None),
                finding_class=finding,
                migration_authority=authority,
                authority_basis=basis,
                occurrences=tuple(
                    Occurrence(
                        locus=o.locus,
                        collector=o.collector,
                        tool_version=o.tool_version,
                        confidence=o.confidence,
                        detection_method=o.detection_method,
                        raw_ref=o.raw_ref,
                        observed_at=o.observed_at,
                    )
                    for o in ordered
                ),
                concluded_from=merged.concluded_from,
                disputed=merged.disputed,
                disputes=merged.disputes,
            )
        )
        # `also_quantum_vulnerable` is a property of the classification, carried
        # to scoring by `also_quantum_vulnerable_of`.
    return AssembleResult(
        assets=tuple(assets),
        merges=merges,
        unresolved=tuple(sorted(unresolved)),
        adjudications=outcome,
    )


def also_quantum_vulnerable_of(asset: CryptoAsset, knowledge: AssembleKnowledge) -> bool:
    """The classification flag ARCH.md 7.1 keeps beside the class: a classically
    weak asset that Shor also breaks (RSA-1024) stays in the PQC programme."""
    if asset.finding_class is not FindingClass.CLASSICAL_WEAK:
        return False
    return classify(
        asset.algorithm_family, asset.parameter_set, rules=knowledge.rules
    ).also_quantum_vulnerable
