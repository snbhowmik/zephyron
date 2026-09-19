"""T-031d — the agent registers the real agent-side collectors, only those
that can run, and only names inside the closed vocabulary."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from qavach_agent.registry import (
    build_registry,
    default_config_dir,
    locate_binary,
)
from qavach_agent.spec import AGENT_COLLECTOR_NAMES
from qavach_collectors import RunContext, Target, TargetType

ROOT = Path(__file__).parent.parent.parent


def _fake_binary(directory: Path, name: str = "certfinder") -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_default_config_dir_is_the_repo_config_when_not_frozen() -> None:
    assert default_config_dir({}) == ROOT / "config"
    assert (default_config_dir({}) / "knowledge" / "hsm_vendors.yaml").is_file()


def test_config_dir_can_be_overridden_by_environment(tmp_path: Path) -> None:
    assert default_config_dir({"QAVACH_CONFIG_DIR": str(tmp_path)}) == tmp_path


def test_registers_every_agent_collector_when_certfinder_is_present(tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path)
    built = build_registry(env={"QAVACH_CERTFINDER_BINARY": str(binary), "PATH": ""})
    names = {c.name for c in built.registry}
    assert names == set(AGENT_COLLECTOR_NAMES)
    assert built.skipped == {}


def test_missing_certfinder_skips_tls_store_and_says_why(tmp_path: Path) -> None:
    built = build_registry(env={"PATH": str(tmp_path)})
    names = {c.name for c in built.registry}
    assert "tls.store" not in names
    assert {"hsm.evidence", "artefact.deployed", "ssh.hostkey"} <= names
    assert "certfinder" in built.skipped["tls.store"]


def test_registered_names_never_leave_the_vocabulary(tmp_path: Path) -> None:
    built = build_registry(env={"PATH": str(tmp_path)})
    assert {c.name for c in built.registry} <= AGENT_COLLECTOR_NAMES


def test_locate_binary_prefers_the_override_and_ignores_non_executables(tmp_path: Path) -> None:
    good = _fake_binary(tmp_path)
    assert locate_binary("certfinder", {"QAVACH_CERTFINDER_BINARY": str(good), "PATH": ""}) == good
    bad = tmp_path / "plain"
    bad.write_text("x")
    bad.chmod(0o600)
    assert locate_binary("certfinder", {"QAVACH_CERTFINDER_BINARY": str(bad), "PATH": ""}) is None


def test_locate_binary_falls_back_to_path(tmp_path: Path) -> None:
    good = _fake_binary(tmp_path)
    assert locate_binary("certfinder", {"PATH": str(tmp_path)}) == good


def test_a_missing_knowledge_file_is_a_startup_error_not_a_silent_gap(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        build_registry(config_dir=tmp_path, env={"PATH": ""})


def test_registered_collectors_run_against_real_paths(tmp_path: Path) -> None:
    """End to end through the same call the runtime makes: a spec path is
    offered to each collector, and only the ones that claim it run."""
    (tmp_path / "sshd_config").write_text("Ciphers aes256-ctr\n")
    (tmp_path / "libsofthsm2.so").write_bytes(b"x")
    built = build_registry(env={"PATH": ""})
    target = Target(type=TargetType.HOST, ref=str(tmp_path))
    ctx = RunContext(scan_run_id="r")
    by_name = {c.name: c.collect(target, ctx) for c in built.registry if c.supports(target)}
    assert "ssh.hostkey" in by_name and by_name["ssh.hostkey"].claims
    assert any(c.locus.path.endswith("libsofthsm2.so") for c in by_name["hsm.evidence"].claims)  # type: ignore[union-attr]
    assert os.path.exists(tmp_path)
