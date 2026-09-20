"""Configuration loading shared by the API and the RQ worker: both must build the
*same* knowledge, policy and collector registry, so it lives in one place."""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from qavach_collectors import CollectorRegistry
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_core.pipeline import AssembleKnowledge, FamilyFunctions
from qavach_core.policy import PolicySnapshot
from qavach_core.recommend import PqcKnowledge
from qavach_core.risk import ClassificationRules

from qavach_worker.pipeline import Deps

POLICY_DOCS = (
    "z_scenarios",
    "regulatory_deadlines",
    "scoring",
    "risk_tolerance",
    "migration_effort",
    "retention_defaults",
)


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def load_deps(config: Path, registry: CollectorRegistry) -> Deps:
    knowledge = config / "knowledge"
    return Deps(
        registry=registry,
        knowledge=AssembleKnowledge(
            registry=CryptographyRegistry.from_dict(
                json.loads(
                    (knowledge / "cdx-crypto-registry" / "cryptography-defs.json").read_text()
                )
            ),
            aliases=AliasTable.from_dict(_yaml(knowledge / "aliases.yaml")),
            rules=ClassificationRules.from_dict(_yaml(knowledge / "classification_rules.yaml")),
            family_functions=FamilyFunctions.from_dict(_yaml(knowledge / "family_functions.yaml")),
        ),
        policy=PolicySnapshot.from_documents(
            {n: _yaml(config / "policy" / f"{n}.yaml") for n in POLICY_DOCS}
        ),
        pqc=PqcKnowledge.from_documents(
            _yaml(knowledge / "pqc_alternatives.yaml"), _yaml(knowledge / "performance.yaml")
        ),
        clock=lambda: datetime.now(UTC),
    )


def config_dir(default_root: Path) -> Path:
    return Path(os.environ.get("QAVACH_CONFIG_DIR", default_root / "config"))


def production_deps(config: Path) -> tuple[Deps, dict[str, str]]:
    """`Deps` with the real collector registry, plus why anything was left out."""
    from qavach_worker.registry import build_central_registry

    deps = load_deps(config, CollectorRegistry())
    central = build_central_registry(
        config,
        registry=deps.knowledge.registry,
        aliases=deps.knowledge.aliases,
        engine_available=shutil.which("docker") is not None or shutil.which("podman") is not None,
    )
    return Deps(
        registry=central.registry,
        knowledge=deps.knowledge,
        policy=deps.policy,
        pqc=deps.pqc,
        clock=lambda: datetime.now(UTC),
    ), central.skipped
