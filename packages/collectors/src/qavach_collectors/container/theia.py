"""ARCH.md §2.2 `container.theia` — CBOMkit-theia over a container image.
T-039.

Theia's `image` command reads several sources; the sandbox has no Docker
socket and no network, so the target here is always a **local image
archive** (`docker save` tarball or OCI archive) that the orchestration
layer has already fetched. Acquiring the image (registry pull, credentials)
is deliberately not this collector's job — it must never hold registry
credentials or reach a registry.

`DEPENDENCY` tier per `ARCH.md §2.2`'s table: theia finds certificates, keys
and secrets *sitting in the image*, which is evidence of presence and
capability rather than of a call site.

Deployment note: the archive is bind-mounted read-only and read by uid
65534 inside the container. Docker Desktop's file sharing hides host
permissions (verified live: a `0600` file was readable), but on a plain
Linux engine the mounted file's mode applies — whatever writes the archive
must make it world-readable or the scan will fail on `EACCES`.
"""

from __future__ import annotations

import json
from pathlib import Path

from qavach_core.model import ConfidenceTier
from qavach_core.normalize import AliasTable, CryptographyRegistry, normalise_bom
from qavach_sandbox import SandboxConfig, run_sandboxed

from qavach_collectors.base import (
    CollectorError,
    CollectorResult,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)
from qavach_collectors.cbom_claims import normalised_to_raw_claims

# config/scanners.yaml `container.theia`, verified 2026-09-18 (T-006).
THEIA_IMAGE = (
    "ghcr.io/cbomkit/cbomkit-theia"
    "@sha256:46a72eadc9849b919fc4c72e1c851f9783e03c35db8fad49ba99341ac97f8dea"
)
THEIA_VERSION = "edge"
"""Theia stamps its own version as `edge` in the CBOM it emits (observed);
the digest above is the real pin."""


class TheiaCollector:
    name = "container.theia"
    version = THEIA_VERSION
    default_confidence = ConfidenceTier.DEPENDENCY
    requires_sandbox = True
    requires_network = False

    def __init__(
        self,
        *,
        registry: CryptographyRegistry,
        aliases: AliasTable,
        image_ref: str = THEIA_IMAGE,
    ) -> None:
        self._registry = registry
        self._aliases = aliases
        self._image_ref = image_ref

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.CONTAINER_IMAGE

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        archive = Path(target.ref)
        command = ("/app/cbomkit-theia", "image", f"/target/{archive.name}")
        sandbox_result = run_sandboxed(
            SandboxConfig(
                image_ref=self._image_ref,
                target_mount=archive.parent,
                command=command,
                requires_network=False,
            )
        )
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=command,
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
            tail = sandbox_result.stderr.decode(errors="replace")[-500:]
            return degraded(f"cbomkit-theia did not complete successfully: {tail}")
        try:
            document = json.loads(sandbox_result.output.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return degraded(f"cbomkit-theia output was not valid JSON: {exc}")
        try:
            normalised = normalise_bom(document, registry=self._registry, aliases=self._aliases)
        except ValueError as exc:
            return degraded(f"cbomkit-theia output could not be normalised: {exc}")

        claims = [
            claim
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
