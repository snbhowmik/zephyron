"""ARCH.md §2.2 `sbom.syft`: 'Package inventory -> crypto-library mapping.'
T-033.

Syft does no crypto detection of its own — this collector runs it inside
the sandbox (`SECURITY.md §3`) to get a package inventory (as a CycloneDX
SBOM, so the same document shape the rest of QAVACH already speaks), then
maps each package's purl against `crypto_libraries.CryptoLibraryMapping`
to emit `RawClaim`s for whatever cryptographic capability that dependency
is known to provide. `ConfidenceTier.DEPENDENCY` throughout — "you depend
on library X, which provides Y" is real evidence, not a guess, but weaker
than an AST/runtime observation of Y actually being called.
"""

from __future__ import annotations

import json
from pathlib import Path

from packageurl import PackageURL
from qavach_core.model import ConfidenceTier, FileLocus
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
from qavach_collectors.sbom.crypto_libraries import CryptoLibraryMapping

# config/scanners.yaml — verified live against the registry's anonymous OCI
# API on 2026-09-18 (T-006). Re-verify before relying on this after that
# date; a digest is exact for the moment it was pulled, not forever.
SYFT_IMAGE = (
    "ghcr.io/anchore/syft@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02"
)
SYFT_VERSION = "1.x"
"""Syft doesn't stamp its own version into `--help`/`scan --help` output in
a single grep-able line the way cdxgen does; the pinned digest in
`SYFT_IMAGE` is the actual pin — this string is cosmetic for `ToolIdentity`
only."""


class SyftCollector:
    name = "sbom.syft"
    version = SYFT_VERSION
    default_confidence = ConfidenceTier.DEPENDENCY
    requires_sandbox = True
    requires_network = False

    def __init__(
        self, *, crypto_libraries: CryptoLibraryMapping, image_ref: str = SYFT_IMAGE
    ) -> None:
        self._crypto_libraries = crypto_libraries
        self._image_ref = image_ref

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        # Syft's own entrypoint is `/syft` (an absolute path, confirmed via
        # `docker inspect`) — invoked directly, matching T-032's own
        # lesson about always sending `command[0]` as `--entrypoint`
        # rather than assuming a shell is available or needed. `-q`
        # silences syft's own logging so stdout carries only the SBOM.
        command = ("/syft", "scan", "dir:/target", "-o", "cyclonedx-json", "-q")
        config = SandboxConfig(
            image_ref=self._image_ref,
            target_mount=Path(target.ref),
            command=command,
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
                            f"syft did not complete successfully: "
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
                    CollectorError(message=f"syft output was not valid JSON: {exc}", fatal=True)
                ],
                partial=True,
            )

        claims = [
            claim
            for component in document.get("components", [])
            for claim in _to_raw_claims(
                component, mapping=self._crypto_libraries, confidence=self.default_confidence
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
    component: dict[str, object], *, mapping: CryptoLibraryMapping, confidence: ConfidenceTier
) -> list[RawClaim]:
    """One `RawClaim` per capability a package's mapping entry lists —
    never one claim bundling several capabilities together, so each
    resolves and reconciles independently downstream."""
    purl_str = component.get("purl")
    if not isinstance(purl_str, str):
        return []  # syft emits non-package components too (e.g. the scanned manifest file itself)

    try:
        purl = PackageURL.from_string(purl_str)
    except ValueError:
        return []

    capabilities = mapping.lookup(purl)
    if not capabilities:
        return []

    return [
        RawClaim(
            locus=FileLocus(path=purl_str, offset=0),
            name=capability,
            detection_method="dependency",
            confidence=confidence,
        )
        for capability in capabilities
    ]
