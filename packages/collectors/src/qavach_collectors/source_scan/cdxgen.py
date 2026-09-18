"""ARCH.md §2.2 `source_scan.cdxgen`. T-032.

QAVACH does not analyse source itself (`CLAUDE.md §1`): this collector
invokes cdxgen's `cbom` binary (verified live against the pinned image,
T-006 — a separate release binary alias for "CBOM-oriented cdxgen
defaults," not a subcommand of the base `cdxgen` entrypoint) inside the
sandbox (`packages/sandbox`, `SECURITY.md §3`) against a mounted
repository, and turns its CycloneDX output into `RawClaim`s via the
already-built normalise layer (T-012/T-014) — it contributes no detection
logic of its own.

Build resolution (cdxgen's own dependency-install step, `--install-deps`,
which **defaults true upstream**) is forced off here regardless of
cdxgen's own default, per `SECURITY.md §3.1`: a malicious `pom.xml`/
`package.json` `postinstall` script must not execute on QAVACH's
infrastructure unless the operator explicitly opts in via
`RunContext.allow_build_resolution` — passed straight through as
`requires_network`, since build resolution is the one thing that needs
egress at all.
"""

from __future__ import annotations

import json
from pathlib import Path

from qavach_core.model import ConfidenceTier, FileLocus
from qavach_core.normalize import (
    AliasTable,
    CryptographyRegistry,
    NormalisedClaim,
    ResolvedAlgorithm,
    ResolvedCurve,
    normalise_bom,
)
from qavach_sandbox import SandboxConfig, run_sandboxed

from qavach_collectors.base import (
    CollectorError,
    CollectorResult,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)

# config/scanners.yaml — verified live against the registry's anonymous OCI
# API on 2026-09-18 (T-006). Re-verify before relying on this after that
# date; a digest is exact for the moment it was pulled, not forever.
CDXGEN_IMAGE = (
    "ghcr.io/cdxgen/cdxgen@sha256:1d4418545662790662567f96af62bf0f8a444eb552bf2c4cb7b35eb0a7d6234e"
)
CDXGEN_VERSION = "13.0.1"


class CdxgenCollector:
    name = "source_scan.cdxgen"
    version = CDXGEN_VERSION
    default_confidence = ConfidenceTier.AST
    requires_sandbox = True
    requires_network = False
    """Overridden per-call by `RunContext.allow_build_resolution` — see
    `collect`. The class attribute stays `False` because a `Collector`'s
    *default* posture (what a caller checks before any specific run
    context exists) must be the closed one; ARCH.md §2.1 does not give
    collectors a way to express "sometimes sandboxed with network," so
    this is the smallest defensible reading, flagged here rather than
    silently assumed."""

    def __init__(
        self,
        *,
        registry: CryptographyRegistry,
        aliases: AliasTable,
        image_ref: str = CDXGEN_IMAGE,
    ) -> None:
        self._registry = registry
        self._aliases = aliases
        self._image_ref = image_ref

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        install_flag = "--install-deps" if ctx.allow_build_resolution else "--no-install-deps"
        # cbom's own progress/audit-table chatter goes to its process
        # stdout (confirmed live) — redirected to a log file on the /work
        # tmpfs so it never corrupts the one JSON blob that is allowed to
        # cross the sandbox boundary (packages/sandbox's own contract,
        # T-031). `&&` means a failed run never reaches `cat`, so a
        # non-zero container exit code is exactly cdxgen's own exit code.
        #
        # Uses the base `cdxgen` entrypoint, not the `cbom` release alias:
        # live testing while building this adapter found `cbom` silently
        # ignores `-o` and always writes a relative `bom.json` against its
        # own CWD, which fails under `--read-only` (the README's own
        # warning that "cbom does not accept --component-type" turned out
        # to extend further than documented). `cdxgen --include-crypto`
        # honours `-o` correctly and is the combination the tool's own
        # README recommends for anything beyond bare defaults. No `-t`
        # flag is forced — auto-detection avoids unconditionally
        # triggering the Maven-dependent Java path for non-Java targets.
        command = (
            "sh",
            "-c",
            f"cdxgen --include-crypto {install_flag} "
            "-o /work/bom.json /target >/work/cdxgen-run.log 2>&1 "
            "&& cat /work/bom.json",
        )
        config = SandboxConfig(
            image_ref=self._image_ref,
            target_mount=Path(target.ref),
            command=command,
            requires_network=ctx.allow_build_resolution,
        )
        sandbox_result = run_sandboxed(config)

        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=command,
            exit_code=sandbox_result.exit_code,
            duration_seconds=sandbox_result.duration_seconds,
        )

        if not sandbox_result.ok:
            return CollectorResult(
                raw=sandbox_result.output,
                raw_format=RawFormat.CDX_1_7,
                claims=[],
                tool=tool,
                errors=[
                    CollectorError(
                        message=(
                            f"cbom did not complete successfully: "
                            f"{sandbox_result.stderr.decode(errors='replace')[:500]}"
                        ),
                        fatal=True,
                    )
                ],
                partial=True,
            )

        try:
            document = json.loads(sandbox_result.output.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return CollectorResult(
                raw=sandbox_result.output,
                raw_format=RawFormat.CDX_1_7,
                claims=[],
                tool=tool,
                errors=[
                    CollectorError(message=f"cbom output was not valid JSON: {exc}", fatal=True)
                ],
                partial=True,
            )

        try:
            normalised = normalise_bom(document, registry=self._registry, aliases=self._aliases)
        except ValueError as exc:
            return CollectorResult(
                raw=sandbox_result.output,
                raw_format=RawFormat.CDX_1_7,
                claims=[],
                tool=tool,
                errors=[
                    CollectorError(
                        message=f"cbom output could not be normalised: {exc}", fatal=True
                    )
                ],
                partial=True,
            )

        claims = [
            claim
            for normalised_claim in normalised
            for claim in _to_raw_claims(
                normalised_claim, target=target, confidence=self.default_confidence
            )
        ]

        return CollectorResult(
            raw=sandbox_result.output,
            raw_format=RawFormat.CDX_1_7,
            claims=claims,
            tool=tool,
            errors=[],
            partial=False,
        )


def _to_raw_claims(
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
                offset=int(occurrence.get("offset") or occurrence.get("line") or 0),
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
