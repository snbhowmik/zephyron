"""T-031c — the agent build cannot silently drift: every file the registry
reads at run time is bundled, every workflow leg has a pinned certfinder and
a theia target, and the pins are real checksums."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("build_agent", ROOT / "scripts/build_agent.py")
assert _spec and _spec.loader
build_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_agent)

WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/agent-build.yml").read_text())
LEGS = [
    leg["label"].replace("-", "_")
    for leg in WORKFLOW["jobs"]["agent"]["strategy"]["matrix"]["include"]
]


def test_every_bundled_knowledge_file_exists() -> None:
    for relative in build_agent.KNOWLEDGE_FILES:
        assert (ROOT / "config" / relative).is_file(), relative


def test_the_bundle_contains_everything_the_agent_registry_reads() -> None:
    source = (ROOT / "apps/agent/src/qavach_agent/registry.py").read_text()
    read = set(re.findall(r'knowledge\s*/\s*"([^"]+)"(?:\s*/\s*"([^"]+)")?', source))
    needed = {"/".join(p for p in parts if p) for parts in read}
    bundled = {Path(f).as_posix().removeprefix("knowledge/") for f in build_agent.KNOWLEDGE_FILES}
    assert needed and needed <= bundled, needed - bundled


def test_every_workflow_leg_has_a_pinned_certfinder_checksum() -> None:
    pins = yaml.safe_load((ROOT / "config/scanners.yaml").read_text())["agent_artifacts"][
        "tls.store.certfinder"
    ]["sha256_by_platform"]
    for leg in LEGS:
        assert re.fullmatch(r"[0-9a-f]{64}", pins[leg]), leg


def test_every_workflow_leg_has_a_theia_build_target() -> None:
    dockerfile = (ROOT / "docker/theia-build/Dockerfile").read_text()
    targets = re.search(r"for target in ([^;]+);", dockerfile)
    assert targets
    built = {t.replace("/", "_") for t in targets.group(1).split()}
    assert set(LEGS) <= built


def test_platform_key_maps_this_host() -> None:
    system, arch = build_agent.platform_key()
    assert system in {"linux", "darwin", "windows"} and arch in {"amd64", "arm64"}
