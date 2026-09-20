"""scripts/preflight.py: distro detection and the install command it prints."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts/preflight.py")
assert _spec and _spec.loader
preflight = importlib.util.module_from_spec(_spec)
sys.modules["preflight"] = preflight  # dataclasses look the module up by name
_spec.loader.exec_module(preflight)


def test_distro_families_from_os_release() -> None:
    assert preflight.distro_family("ID=ubuntu\nID_LIKE=debian\n") == "deb"
    assert preflight.distro_family('ID="debian"\n') == "deb"
    assert preflight.distro_family('ID="rocky"\nID_LIKE="rhel centos fedora"\n') == "rpm"
    assert preflight.distro_family("ID=fedora\n") == "rpm"
    assert preflight.distro_family("ID=alpine\n") == "unknown"


def test_the_install_command_uses_the_right_package_manager_and_never_guesses() -> None:
    assert preflight.install_command("deb", ["git", "curl"]) == (
        "sudo apt-get update && sudo apt-get install -y git curl"
    )
    assert preflight.install_command("rpm", ["git"]).startswith(("sudo dnf", "sudo yum"))  # type: ignore[union-attr]
    assert preflight.install_command("unknown", ["git"]) is None
    assert preflight.install_command("deb", []) is None


def test_every_prerequisite_names_packages_for_both_families_or_says_why_not() -> None:
    table = yaml.safe_load((ROOT / "config/knowledge/host_prereqs.yaml").read_text())
    for section in ("required", "recommended"):
        for name, spec in table[section].items():
            assert spec["deb"] and spec["rpm"] and spec["why"], name
    for name, spec in table["build_tools"].items():
        assert "deb" in spec and "rpm" in spec, name  # an empty rpm list is a stated absence


def test_a_missing_tool_yields_its_packages_for_this_family() -> None:
    table = {
        "required": {
            "nosuchtool": {
                "why": "w",
                "command": "definitely-not-installed-xyz",
                "deb": ["a"],
                "rpm": ["b"],
            }
        }
    }
    [f] = preflight.check_prereqs(table, "rpm")
    assert not f.ok and f.packages == ["b"]
    [g] = preflight.check_prereqs(table, "deb")
    assert g.packages == ["a"]
