"""ARCH.md §5.1 — CycloneDX 1.4-1.7 version normalisation. T-014.

Extracts `cryptographic-asset` components from a parsed CBOM document
(any declared `specVersion` 1.4-1.7) into `NormalisedClaim`s, resolving
algorithm/curve spellings via T-012's `resolve_algorithm`/`resolve_curve`.
Certificate/related-material/protocol asset types are passed through as
raw properties, not deeply parsed — X.509/keystore parsing needs real I/O
(`cryptography`, `pyjks`) and belongs to the collector layer (ARCH.md
§2.2), not this zero-I/O normalisation stage.

Two version-compatibility details found while checking the vendored 1.7
schema directly, not assumed from ARCH.md's summary:

  - `algorithmProperties.curve` is **deprecated** in 1.7 in favour of
    `ellipticCurve` (matches ARCH.md §5.1's note that 1.7 "deprecat[es]
    1.6's free-text curve" in favour of a standardised enumeration) — a
    1.6-or-earlier document may only have `curve`; a 1.7-native one should
    have `ellipticCurve`. Both are checked, `ellipticCurve` preferred.
  - `evidence.identity` can be a **single object** (deprecated, pre-1.6)
    or an **array** (1.6+, recommended). Always normalised to a tuple here
    so callers never branch on which form the source document used.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from qavach_core.model.enums import AssetType
from qavach_core.normalize.aliases import AliasTable
from qavach_core.normalize.registry import CryptographyRegistry
from qavach_core.normalize.resolve import (
    RawAlgorithmClaim,
    ResolvedAlgorithm,
    ResolvedCurve,
    UnresolvedAlgorithm,
    UnresolvedCurve,
    resolve_algorithm,
    resolve_curve,
)

SUPPORTED_SPEC_VERSIONS = frozenset({"1.4", "1.5", "1.6", "1.7"})


@dataclass(frozen=True, slots=True)
class NormalisedClaim:
    bom_ref: str | None
    asset_type: AssetType
    resolved_algorithm: ResolvedAlgorithm | UnresolvedAlgorithm | None
    resolved_curve: ResolvedCurve | UnresolvedCurve | None
    mode: str | None
    padding: str | None
    oid: str | None
    raw_crypto_properties: Mapping[str, Any]
    evidence_occurrences: tuple[Mapping[str, Any], ...]
    evidence_identity: tuple[Mapping[str, Any], ...]
    """Always an array, even when the source document used the deprecated
    single-object form — never dropped, never guessed which form callers
    should expect."""


def _normalise_identity(identity_raw: Any) -> tuple[Mapping[str, Any], ...]:
    if identity_raw is None:
        return ()
    if isinstance(identity_raw, Mapping):
        return (identity_raw,)  # deprecated single-object form (pre-1.6)
    return tuple(identity_raw)  # array form (1.6+)


def normalise_bom(
    document: Mapping[str, Any],
    *,
    registry: CryptographyRegistry,
    aliases: AliasTable,
) -> list[NormalisedClaim]:
    spec_version = document.get("specVersion")
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise ValueError(
            f"unsupported specVersion {spec_version!r} — ARCH.md §5.1 supports "
            f"{sorted(SUPPORTED_SPEC_VERSIONS)}"
        )

    claims: list[NormalisedClaim] = []
    # `or []`, not a `.get` default: a real tool (CBOMkit-theia, found in
    # T-039) emits an explicit JSON `null` for "no components", which a
    # `.get("components", [])` default does not replace.
    for component in document.get("components") or []:
        if component.get("type") != "cryptographic-asset":
            continue

        crypto_props: Mapping[str, Any] = component.get("cryptoProperties", {})
        asset_type = AssetType(crypto_props["assetType"])
        oid = crypto_props.get("oid")

        resolved_algorithm: ResolvedAlgorithm | UnresolvedAlgorithm | None = None
        resolved_curve: ResolvedCurve | UnresolvedCurve | None = None
        mode: str | None = None
        padding: str | None = None

        if asset_type is AssetType.ALGORITHM:
            algo_props: Mapping[str, Any] = crypto_props.get("algorithmProperties", {})
            # algorithmFamily (1.7) is schema-validated against the exact
            # registry enum; fall back to the component's own free-text
            # name for pre-1.7 documents or tools that don't populate it.
            name = algo_props.get("algorithmFamily") or component.get("name")
            claim = RawAlgorithmClaim(
                name=name,
                oid=oid,
                primitive=algo_props.get("primitive"),
                parameter_set=algo_props.get("parameterSetIdentifier"),
            )
            resolved_algorithm = resolve_algorithm(claim, registry=registry, aliases=aliases)

            curve_spelling = algo_props.get("ellipticCurve") or algo_props.get("curve")
            resolved_curve = resolve_curve(curve_spelling, registry=registry, aliases=aliases)

            mode = algo_props.get("mode")
            padding = algo_props.get("padding")

        evidence: Mapping[str, Any] = component.get("evidence") or {}
        occurrences = tuple(evidence.get("occurrences") or ())
        identity = _normalise_identity(evidence.get("identity"))

        claims.append(
            NormalisedClaim(
                bom_ref=component.get("bom-ref"),
                asset_type=asset_type,
                resolved_algorithm=resolved_algorithm,
                resolved_curve=resolved_curve,
                mode=mode,
                padding=padding,
                oid=oid,
                raw_crypto_properties=crypto_props,
                evidence_occurrences=occurrences,
                evidence_identity=identity,
            )
        )

    return claims
