"""CycloneDX CBOM -> `RawClaim`s, shared by every collector whose tool
emits a CBOM (cdxgen T-032, cbomkit-lib T-038). One implementation, so a
CBOM-emitting scanner can never be mapped two subtly different ways."""

from __future__ import annotations

from qavach_core.model import ConfidenceTier, FileLocus
from qavach_core.normalize import NormalisedClaim, ResolvedAlgorithm, ResolvedCurve

from qavach_collectors.base import RawClaim, Target


def normalised_to_raw_claims(
    normalised_claim: NormalisedClaim, *, target: Target, confidence: ConfidenceTier
) -> list[RawClaim]:
    """One `RawClaim` per `evidence.occurrences[]` entry — a cryptographic
    asset cdxgen found in more than one file becomes more than one
    occurrence, matching `ARCH.md §2.1`'s "a collector reports what it saw"
    contract rather than collapsing multi-location evidence into one
    locus. Falls back to a single claim anchored at the repository root
    when cdxgen supplied no occurrence evidence at all — still real
    information (the component exists), just without a specific file."""
    algo = normalised_claim.resolved_algorithm
    name = (
        algo.algorithm_family
        if isinstance(algo, ResolvedAlgorithm)
        else getattr(algo, "raw_name", None)
    )
    oid = algo.oid if isinstance(algo, ResolvedAlgorithm) else getattr(algo, "raw_oid", None)
    primitive = algo.primitive if isinstance(algo, ResolvedAlgorithm) else None
    parameter_set = algo.parameter_set if isinstance(algo, ResolvedAlgorithm) else None
    curve = normalised_claim.resolved_curve
    curve_name = (
        curve.canonical if isinstance(curve, ResolvedCurve) else getattr(curve, "raw_name", None)
    )

    occurrences = normalised_claim.evidence_occurrences
    if not occurrences:
        return [
            RawClaim(
                locus=FileLocus(path=target.ref, offset=0),
                name=name,
                oid=oid or normalised_claim.oid,
                primitive=primitive,
                parameter_set=parameter_set or curve_name,
                mode=normalised_claim.mode,
                padding=normalised_claim.padding,
                detection_method="ast",
                confidence=confidence,
            )
        ]

    return [
        RawClaim(
            locus=FileLocus(
                path=str(occurrence.get("location", target.ref)),
                # QAVACH-OPEN: LOCUS-01 — ARCH.md §6.2 gives FileLocus an `offset` but
                # never says whether that is a line or a column. CycloneDX
                # occurrences carry both (`line`, `offset`=column). Line is used:
                # loci are part of identity, so two tools must report the same
                # call site the same way to ever corroborate each other.
                offset=int(occurrence.get("line") or occurrence.get("offset") or 0),
            ),
            name=name,
            oid=oid or normalised_claim.oid,
            primitive=primitive,
            parameter_set=parameter_set or curve_name,
            mode=normalised_claim.mode,
            padding=normalised_claim.padding,
            detection_method="ast",
            confidence=confidence,
        )
        for occurrence in occurrences
    ]
