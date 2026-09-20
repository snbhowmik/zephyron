"""The production collector registry for centrally-run scans (ARCH.md §2.2).

Until this module existed the API's non-demo registry was *empty*: a live scan
found no collector for any target and produced nothing, while the demo (which
registers replay collectors) looked fine. This registers the real collectors.

**Registers only what can actually run**, like the agent's registry: a collector
whose prerequisite is missing (a QAVACH-built image not yet built, a credential-
only collector) is left out and named in `CentralRegistry.skipped` with the
reason, never registered to fail on every scan. The reasons are surfaced by the
API (`/api/v1/meta`), so an operator sees *why* a target type has no coverage.

Upstream scanner images are pinned by digest in the collectors themselves
(`config/scanners.yaml`); QAVACH-built images are pinned by the content-
addressed ID `docker image inspect` reports - never by a tag (SECURITY.md §3).
Credentialed collectors (AWS, ADCS) need per-job secrets and are not registered
centrally.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from qavach_collectors import CollectorRegistry
from qavach_collectors.binary import BinaryCollector, BinaryKnowledge
from qavach_collectors.cbom_upload import ExternalCbomCollector
from qavach_collectors.container.theia import TheiaCollector
from qavach_collectors.runtime import TracebomCollector
from qavach_collectors.sbom import CryptoLibraryMapping
from qavach_collectors.sbom.syft import SyftCollector
from qavach_collectors.source_scan import (
    CbomkitCollector,
    CdxgenCollector,
    OpengrepCollector,
    load_rules,
)
from qavach_collectors.ssh.collector import SshHostKeyCollector
from qavach_collectors.tls.collector import TlsEndpointCollector
from qavach_collectors.tls.ssrf import NetworkPolicy
from qavach_core.normalize import AliasTable, CryptographyRegistry

BUILT_IMAGES = {
    "source_scan.opengrep": "qavach/opengrep:dev",
    "runtime.tracebom": "qavach/tracebom:dev",
    "source_scan.cbomkit": "qavach/cbomkit-lib:dev",
}
NOT_CENTRAL = {
    "cloud.aws": "needs per-job cloud credentials (SECURITY.md §6); not registered centrally",
    "ad.adcs": "needs per-job domain credentials; not registered centrally",
    "tls.store": "agent-side only (ARCH.md §3a)",
    "hsm.evidence": "agent-side only (ARCH.md §3a)",
    "artefact.deployed": "agent-side only (ARCH.md §3a)",
}


@dataclass(slots=True)
class CentralRegistry:
    registry: CollectorRegistry
    skipped: dict[str, str] = field(default_factory=dict)


def local_image_id(tag: str, engine: str = "docker") -> str | None:
    """The content-addressed ID of a locally built image, or None."""
    try:
        proc = subprocess.run(
            [engine, "image", "inspect", "--format", "{{.Id}}", tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    ident = proc.stdout.strip()
    return ident if proc.returncode == 0 and ident.startswith("sha256:") else None


def build_central_registry(
    config: Path,
    *,
    registry: CryptographyRegistry,
    aliases: AliasTable,
    image_id: Callable[[str], str | None] = local_image_id,
    engine_available: bool = True,
) -> CentralRegistry:
    def yml(path: str) -> Any:
        return yaml.safe_load((config / path).read_text())

    out = CentralRegistry(registry=CollectorRegistry(), skipped=dict(NOT_CENTRAL))
    reg = out.registry

    # -- collectors that need no container ------------------------------------
    policy = NetworkPolicy.from_dict(yml("security/network_policy.yaml"))
    reg.register(TlsEndpointCollector(policy=policy))
    reg.register(SshHostKeyCollector(policy=policy))
    reg.register(ExternalCbomCollector(registry=registry, aliases=aliases))
    reg.register(
        BinaryCollector(knowledge=BinaryKnowledge.from_dict(yml("knowledge/binary_crypto.yaml")))
    )

    # -- sandboxed collectors: need a container engine ---------------------------
    sandboxed = (
        "source_scan.cdxgen",
        "sbom.syft",
        "container.theia",
        *BUILT_IMAGES,
    )
    if not engine_available:
        for name in sandboxed:
            out.skipped[name] = "no container engine available"
        return out

    libraries = CryptoLibraryMapping.from_entries(
        yml("knowledge/crypto_libraries.yaml")["libraries"]
    )
    reg.register(CdxgenCollector(registry=registry, aliases=aliases))
    reg.register(SyftCollector(crypto_libraries=libraries))
    reg.register(TheiaCollector(registry=registry, aliases=aliases))

    built: dict[str, str] = {}
    for name, tag in BUILT_IMAGES.items():
        ident = image_id(tag)
        if ident is None:
            out.skipped[name] = f"{tag} is not built (run `make build-images`)"
        else:
            built[name] = ident
    if "source_scan.opengrep" in built:
        reg.register(
            OpengrepCollector(
                rules=load_rules(yml("opengrep-rules/crypto.yaml")),
                image_ref=built["source_scan.opengrep"],
            )
        )
    if "source_scan.cbomkit" in built:
        reg.register(
            CbomkitCollector(
                registry=registry, aliases=aliases, image_ref=built["source_scan.cbomkit"]
            )
        )
    if "runtime.tracebom" in built:
        reg.register(
            TracebomCollector(
                registry=registry,
                aliases=aliases,
                knowledge=BinaryKnowledge.from_dict(yml("knowledge/binary_crypto.yaml")),
                image_ref=built["runtime.tracebom"],
            )
        )
    return out
