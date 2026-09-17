"""T-031a — the typed scan-spec protocol. Pure, no network."""

from __future__ import annotations

import pytest
from qavach_agent import AGENT_COLLECTOR_NAMES, InvalidScanSpecError, ScanSpec, parse_scan_spec


def test_parses_a_valid_spec() -> None:
    spec = parse_scan_spec({"paths": ["/etc/ssl"], "collectors": ["tls.store"]})
    assert spec == ScanSpec(paths=("/etc/ssl",), collectors=("tls.store",))


def test_rejects_a_command_field() -> None:
    """ARCH.md §3a: 'There is no exec, no shell, no arbitrary payload
    field.' A spec carrying anything beyond paths/collectors is rejected
    outright, not stripped and proceeded with."""
    with pytest.raises(InvalidScanSpecError, match="unexpected field"):
        parse_scan_spec({"paths": ["/etc/ssl"], "collectors": ["tls.store"], "exec": "rm -rf /"})


def test_rejects_an_unknown_collector_name() -> None:
    """A compromised or buggy backend asking for a module the agent never
    shipped must be refused, not silently ignored or run anyway."""
    with pytest.raises(InvalidScanSpecError, match="unknown collector"):
        parse_scan_spec({"paths": ["/etc/ssl"], "collectors": ["arbitrary.shell"]})


@pytest.mark.parametrize("bad_paths", [None, "not-a-list", [1, 2], {"a": "b"}])
def test_rejects_malformed_paths(bad_paths: object) -> None:
    with pytest.raises(InvalidScanSpecError):
        parse_scan_spec({"paths": bad_paths, "collectors": ["tls.store"]})


@pytest.mark.parametrize("bad_collectors", [None, "not-a-list", [1, 2]])
def test_rejects_malformed_collectors(bad_collectors: object) -> None:
    with pytest.raises(InvalidScanSpecError):
        parse_scan_spec({"paths": ["/etc/ssl"], "collectors": bad_collectors})


def test_rejects_non_dict_payload() -> None:
    with pytest.raises(InvalidScanSpecError):
        parse_scan_spec("not a dict")  # type: ignore[arg-type]


def test_rejects_empty_paths() -> None:
    with pytest.raises(InvalidScanSpecError):
        parse_scan_spec({"paths": [], "collectors": ["tls.store"]})


def test_rejects_empty_collectors() -> None:
    with pytest.raises(InvalidScanSpecError):
        parse_scan_spec({"paths": ["/etc/ssl"], "collectors": []})


def test_agent_collector_names_matches_arch_md_s3a_inventory() -> None:
    """ARCH.md §3a names exactly four agent-only collectors: tls.store,
    hsm.evidence, the deployed-artefact collector, and the sshd_config half
    of ssh.hostkey."""
    assert AGENT_COLLECTOR_NAMES == {
        "tls.store",
        "hsm.evidence",
        "artefact.deployed",
        "ssh.hostkey",
    }


def test_multiple_paths_and_collectors_accepted() -> None:
    spec = parse_scan_spec(
        {
            "paths": ["/etc/ssl", "/opt/tomcat/conf"],
            "collectors": ["tls.store", "ssh.hostkey"],
        }
    )
    assert spec.paths == ("/etc/ssl", "/opt/tomcat/conf")
    assert spec.collectors == ("tls.store", "ssh.hostkey")
