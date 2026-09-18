"""ARCH.md §2.2 `source_scan.cbomkit` — cbomkit-lib. T-038.

Runs the QAVACH-owned image built from `docker/cbomkit-lib/Dockerfile`
(`NOTE.md §3.2`): the pinned `cbomkit-lib` plus the `sonar-cryptography`
plugin it depends on, and a small `QavachScan` entrypoint (cbomkit-lib is
a library with no `main`). AST-tier evidence — the plugin resolves the
call sites through the Sonar Java/Python frontends, unlike a string match.

**Why QAVACH builds the image rather than pulling one, and why no
credential is needed.** The plugin (`com.ibm:sonar-cryptography-plugin`)
is published only to GitHub Packages, which demands a PAT even to *read*;
it is not on Maven Central (checked: 0 results). Both projects are
Apache-2.0, so the Dockerfile builds the plugin from its pinned release
tag into the build stage's own local Maven repository. The PAT problem
therefore disappears rather than being worked around — no credential
exists at build time, and none at scan time (`SECURITY.md §6`).

**Source-only Java scanning.** cbomkit-lib itself calls this "the least
accurate" mode and disables it by default; `QavachScan` re-enables it
(`setRequireBuild(false)`) because the sandbox has no network and never
builds the target, and picks up any `.jar` already sitting in the target.
Coverage is therefore weaker for Java than the upstream
build-then-scan sequencing — a stated limit, not a hidden one, matching
how `PRD.md FR-101` states its other coverage caveats.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from qavach_core.model import ConfidenceTier, FileLocus
from qavach_core.normalize import AliasTable, CryptographyRegistry, normalise_bom
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
from qavach_collectors.cbom_claims import normalised_to_raw_claims

CBOMKIT_LIB_VERSION = "1.0.0-SNAPSHOT@8fbc617"
"""cbomkit-lib pinned commit (see the Dockerfile's `CBOMKIT_LIB_REF`)."""

_COMMAND = (
    "java",
    "-cp",
    "/opt/qavach:/opt/qavach/lib/*",
    "QavachScan",
    "/target",
)


def _relative_to_target(claim: RawClaim) -> RawClaim:
    """cbomkit-lib reports paths relative to the *parent* of the scanned
    directory, so every location arrives as `target/app.py` (seen in the
    recorded corpus, T-024). Every other collector reports paths relative to
    the scan root; leaving the prefix would make the same file two different
    loci and stop cross-tool corroboration from ever matching."""
    locus = claim.locus
    if isinstance(locus, FileLocus) and locus.path.startswith("target/"):
        return replace(
            claim, locus=FileLocus(path=locus.path.removeprefix("target/"), offset=locus.offset)
        )
    return claim


class ImageNotBuiltError(RuntimeError):
    pass


class CbomkitCollector:
    name = "source_scan.cbomkit"
    version = CBOMKIT_LIB_VERSION
    default_confidence = ConfidenceTier.AST
    requires_sandbox = True
    requires_network = False

    def __init__(
        self,
        *,
        registry: CryptographyRegistry,
        aliases: AliasTable,
        image_ref: str | None,
    ) -> None:
        """`image_ref` is required, with no default: unlike cdxgen/syft
        there is no upstream image to point at, so a QAVACH-built digest
        must be supplied (`make build-images` prints it). Failing loudly
        here beats a silent fallback to some other image."""
        if not image_ref:
            raise ImageNotBuiltError(
                "no cbomkit-lib image configured: run `make build-images` and pass its digest"
            )
        self._registry = registry
        self._aliases = aliases
        self._image_ref = image_ref

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        config = SandboxConfig(
            image_ref=self._image_ref,
            target_mount=Path(target.ref),
            command=_COMMAND,
            requires_network=False,  # never builds the target; see module docstring
        )
        sandbox_result = run_sandboxed(config)

        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=_COMMAND,
            exit_code=sandbox_result.exit_code,
            duration_seconds=sandbox_result.duration_seconds,
        )

        def degraded(message: str) -> CollectorResult:
            return CollectorResult(
                raw=sandbox_result.output,
                raw_format=RawFormat.CDX_1_6,
                claims=[],
                tool=tool,
                errors=[CollectorError(message=message, fatal=True)],
                partial=True,
            )

        if not sandbox_result.ok:
            stderr_tail = sandbox_result.stderr.decode(errors="replace")[-500:]
            return degraded(f"cbomkit-lib did not complete successfully: {stderr_tail}")

        try:
            document = json.loads(sandbox_result.output.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return degraded(f"cbomkit-lib output was not valid JSON: {exc}")

        try:
            normalised = normalise_bom(document, registry=self._registry, aliases=self._aliases)
        except ValueError as exc:
            return degraded(f"cbomkit-lib output could not be normalised: {exc}")

        claims = [
            _relative_to_target(claim)
            for item in normalised
            for claim in normalised_to_raw_claims(
                item, target=target, confidence=self.default_confidence
            )
        ]
        return CollectorResult(
            raw=sandbox_result.output,
            raw_format=RawFormat.CDX_1_6,
            claims=claims,
            tool=tool,
            errors=[],
            partial=False,
        )
