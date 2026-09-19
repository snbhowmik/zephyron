"""Wires the agent-side collectors into the agent's registry. T-031d.

`ARCH.md §3a`: the agent is a thin shell that imports `packages/collectors`
directly and owns no parsing logic. Until this module existed, `run` polled
with an *empty* registry, so a deployed agent would have reported every
collector as "skipped, unregistered" — the collectors were built but not
reachable from the shipped binary.

**Registers only what can actually run.** A collector whose prerequisite is
missing (`tls.store` needs the certfinder binary) is left out and named in
`AgentRegistry.skipped` with the reason, rather than registered and failing on
every path. The runtime already reports an unregistered spec collector as
skipped, so the operator sees it. Never an exception at startup: an agent that
cannot find certfinder should still do HSM and sshd inspection.

**Closed vocabulary.** Every registered name must be in
`spec.AGENT_COLLECTOR_NAMES`; registering anything else raises, so this module
cannot widen what the backend is allowed to ask the agent to run.

**Config and binaries.** Knowledge tables (`hsm_vendors.yaml`,
`crypto_libraries.yaml`) are read from a config directory: bundled beside the
executable when frozen by PyInstaller, the repo's `config/` otherwise, or
`QAVACH_CONFIG_DIR`. Binaries are looked up by `QAVACH_<NAME>_BINARY`, then
the bundle, then next to the executable, then `PATH`.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from qavach_collectors import CollectorRegistry
from qavach_collectors.artefact import DeployedArtefactCollector
from qavach_collectors.hsm import HsmEvidenceCollector, load_vendor_table
from qavach_collectors.sbom import CryptoLibraryMapping
from qavach_collectors.ssh import SshdConfigCollector
from qavach_collectors.tls import TlsStoreCollector
from qavach_core.normalize import AliasTable, CryptographyRegistry

from qavach_agent.spec import AGENT_COLLECTOR_NAMES


@dataclass(slots=True)
class AgentRegistry:
    registry: CollectorRegistry
    skipped: dict[str, str] = field(default_factory=dict)
    """Vocabulary names left unregistered, with the reason."""


def _frozen_root() -> Path | None:
    root = getattr(sys, "_MEIPASS", None)
    return Path(root) if getattr(sys, "frozen", False) and root else None


def default_config_dir(env: Mapping[str, str] | None = None) -> Path:
    environ = env if env is not None else os.environ
    if environ.get("QAVACH_CONFIG_DIR"):
        return Path(environ["QAVACH_CONFIG_DIR"])
    frozen = _frozen_root()
    if frozen is not None:
        return frozen / "config"
    return Path(__file__).resolve().parents[4] / "config"


def locate_binary(name: str, env: Mapping[str, str] | None = None) -> Path | None:
    environ = env if env is not None else os.environ
    override = environ.get(f"QAVACH_{name.upper().replace('-', '_')}_BINARY")
    candidates: list[Path] = [Path(override)] if override else []
    frozen = _frozen_root()
    if frozen is not None:
        candidates.append(frozen / "bin" / name)
    candidates.append(Path(sys.executable).resolve().parent / name)
    for candidate in candidates:
        for form in (candidate, candidate.with_suffix(".exe")):
            if form.is_file() and os.access(form, os.X_OK):
                return form
    found = shutil.which(name, path=environ.get("PATH"))
    return Path(found) if found else None


def _load_yaml(path: Path) -> dict[str, object]:
    loaded = yaml.safe_load(path.read_text())
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} is not a YAML mapping")
    return loaded


def build_registry(
    *, config_dir: Path | None = None, env: Mapping[str, str] | None = None
) -> AgentRegistry:
    config = config_dir or default_config_dir(env)
    knowledge = config / "knowledge"
    result = AgentRegistry(registry=CollectorRegistry())

    def register(collector: object) -> None:
        name = getattr(collector, "name")  # noqa: B009
        if name not in AGENT_COLLECTOR_NAMES:
            raise ValueError(f"{name!r} is outside the agent's collector vocabulary")
        result.registry.register(collector)  # type: ignore[arg-type]

    register(
        HsmEvidenceCollector(vendors=load_vendor_table(_load_yaml(knowledge / "hsm_vendors.yaml")))
    )
    libraries = CryptoLibraryMapping.from_entries(
        _load_yaml(knowledge / "crypto_libraries.yaml")["libraries"]  # type: ignore[arg-type]
    )
    register(DeployedArtefactCollector(crypto_libraries=libraries))
    register(SshdConfigCollector())

    certfinder = locate_binary("certfinder", env)
    if certfinder is None:
        result.skipped["tls.store"] = "the certfinder binary was not found"
    else:
        # Theia is additive (T-036c): without it tls.store still runs, with
        # certfinder alone. Its CBOM needs the registry to be normalised.
        theia = locate_binary("cbomkit-theia", env)
        registry = aliases = None
        if theia is not None:
            registry = CryptographyRegistry.from_dict(
                json.loads(
                    (knowledge / "cdx-crypto-registry" / "cryptography-defs.json").read_text()
                )
            )
            aliases = AliasTable.from_dict(_load_yaml(knowledge / "aliases.yaml"))
        register(
            TlsStoreCollector(
                certfinder_binary=certfinder,
                theia_binary=theia,
                registry=registry,
                aliases=aliases,
            )
        )

    return result
