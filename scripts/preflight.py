"""Host preflight (`make preflight`): is this machine ready to run QAVACH?

Checks git, a container engine the service account can actually use, openssl, CA
certificates, the shared workspace directory (exists, writable, group, and - on
Docker Desktop - a path the VM can bind-mount), and that the pinned scanner images
are present. Prints what is missing with the distro-appropriate install command
from `config/knowledge/host_prereqs.yaml`. Nothing is installed unless you pass
`--install --yes` (it then runs the printed command with sudo).

    uv run python scripts/preflight.py [--workspace DIR] [--install --yes] [--build-tools]
"""

from __future__ import annotations

import argparse
import grp
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def distro_family(os_release: str) -> str:
    """`deb`, `rpm` or `unknown` from /etc/os-release text (ID and ID_LIKE)."""
    fields = {}
    for line in os_release.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"').lower()
    ids = f"{fields.get('ID', '')} {fields.get('ID_LIKE', '')}".split()
    if any(i in ids for i in ("debian", "ubuntu")):
        return "deb"
    if any(
        i in ids for i in ("rhel", "fedora", "centos", "rocky", "almalinux", "suse", "opensuse")
    ):
        return "rpm"
    return "unknown"


def install_command(family: str, packages: list[str]) -> str | None:
    if not packages:
        return None
    if family == "deb":
        return "sudo apt-get update && sudo apt-get install -y " + " ".join(packages)
    if family == "rpm":
        manager = "dnf" if shutil.which("dnf") else "yum"
        return f"sudo {manager} install -y " + " ".join(packages)
    return None


@dataclass
class Finding:
    name: str
    ok: bool
    detail: str
    packages: list[str]


def _have(command: str | None, files: str | None) -> bool:
    if command and any(shutil.which(c) for c in command.split("|")):
        return True
    return bool(files and any(Path(f).exists() for f in files.split("|")))


def check_prereqs(
    table: dict[str, Any], family: str, *, section: str = "required"
) -> list[Finding]:
    out = []
    for name, spec in table[section].items():
        ok = _have(spec.get("command"), spec.get("file"))
        out.append(Finding(name, ok, spec["why"], [] if ok else list(spec.get(family, []))))
    return out


def check_engine() -> list[Finding]:
    engine = shutil.which("docker") or shutil.which("podman")
    if not engine:
        return [Finding("engine reachable", False, "no docker/podman on PATH", [])]
    proc = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode == 0:
        return [Finding("engine reachable", True, f"{Path(engine).name} answers", [])]
    hint = ""
    try:
        docker_gid = grp.getgrnam("docker").gr_gid
        if docker_gid not in os.getgroups():
            hint = (
                " - this account is not in group 'docker' "
                "(sudo usermod -aG docker $USER, then log in again)"
            )
    except KeyError:
        pass
    return [Finding("engine reachable", False, "daemon not reachable" + hint, [])]


def check_workspace(path: Path) -> list[Finding]:
    if not path.exists():
        return [
            Finding(
                "workspace",
                False,
                f"{path} does not exist: sudo install -d -m 2775 -g docker {path}",
                [],
            )
        ]
    writable = os.access(path, os.W_OK | os.X_OK)
    mode = path.stat().st_mode & 0o7777
    group = grp.getgrgid(path.stat().st_gid).gr_name
    notes = f"{path} group={group} mode={oct(mode)}"
    if not writable:
        return [Finding("workspace", False, notes + " - not writable by this account", [])]
    if not mode & 0o2000:
        notes += " (no setgid bit: new checkouts will not inherit the group)"
    return [Finding("workspace", True, notes, [])]


def check_images() -> list[Finding]:
    engine = shutil.which("docker") or shutil.which("podman")
    if not engine:
        return []
    have = subprocess.run(
        [engine, "images", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True, text=True, timeout=30, check=False,
    ).stdout.split()  # fmt: skip
    wanted = {
        "qavach/opengrep:dev": "make build-images",
        "qavach/tracebom:dev": "make build-images",
        "qavach/cbomkit-lib:dev": "make build-images",
    }
    return [
        Finding(f"image {tag}", tag in have, "built" if tag in have else f"missing: {fix}", [])
        for tag, fix in wanted.items()
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(os.environ.get("QAVACH_WORKSPACE_DIR", ROOT / "dist" / "workspace")),
    )
    parser.add_argument(
        "--install", action="store_true", help="print the install command for what is missing"
    )
    parser.add_argument("--yes", action="store_true", help="with --install: actually run it (sudo)")
    parser.add_argument("--build-tools", action="store_true", help="include host build toolchains")
    args = parser.parse_args()

    table = yaml.safe_load((ROOT / "config/knowledge/host_prereqs.yaml").read_text())
    release = Path("/etc/os-release").read_text() if Path("/etc/os-release").exists() else ""
    family = distro_family(release)
    findings = check_prereqs(table, family) + check_prereqs(table, family, section="recommended")
    findings += check_engine() + check_workspace(args.workspace) + check_images()
    if args.build_tools:
        for name, spec in table["build_tools"].items():
            pkgs = spec.get(family, [])
            findings.append(
                Finding(f"build tool {name}", False, "optional (host-side builds only)", pkgs)
            )

    width = max(len(f.name) for f in findings)
    for f in findings:
        print(f"{'ok  ' if f.ok else 'MISS'}  {f.name:<{width}}  {f.detail}")
    missing = sorted({p for f in findings if not f.ok for p in f.packages})
    if family == "unknown":
        print(
            "\ndistro family not recognised: install the tools named in "
            "config/knowledge/host_prereqs.yaml yourself"
        )
    cmd = install_command(family, missing)
    if cmd and args.install:
        print(f"\n{cmd}")
        if args.yes:
            return subprocess.run(cmd, shell=True, check=False).returncode  # noqa: S602 - fixed, printed above
        print("(add --yes to run it)")
    return 0 if all(f.ok for f in findings if not f.name.startswith(("build tool", "image"))) else 1


if __name__ == "__main__":
    sys.exit(main())
