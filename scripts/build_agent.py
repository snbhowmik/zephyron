"""T-031c — builds the single-file agent for the OS/arch it runs on.

PyInstaller does not cross-compile, so CI runs this once per runner
(`.github/workflows/agent-build.yml`). Steps: download the pinned certfinder
release for this platform and verify its SHA-256 (fail closed), stage the
CBOMkit-theia binary if one was built for this platform (`make build-theia`),
freeze `apps/agent/launcher.py` with the knowledge tables and both binaries
bundled, then verify the result by running `qavach-agent doctor` from the
frozen executable and writing `SHA256SUMS`.

    uv run python scripts/build_agent.py [--theia-dir dist/theia] [--out dist/agent]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PINS = yaml.safe_load((ROOT / "config" / "scanners.yaml").read_text())
KNOWLEDGE_FILES = (
    "knowledge/hsm_vendors.yaml",
    "knowledge/crypto_libraries.yaml",
    "knowledge/aliases.yaml",
    "knowledge/cdx-crypto-registry/cryptography-defs.json",
)


def platform_key() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if system not in {"linux", "darwin", "windows"} or arch is None:
        sys.exit(f"unsupported platform {system}/{machine}")
    return system, arch


def fetch_certfinder(system: str, arch: str, destination: Path) -> Path:
    pin = PINS["agent_artifacts"]["tls.store.certfinder"]
    key = f"{system}_{arch}"
    expected = pin["sha256_by_platform"].get(key)
    if expected is None:
        sys.exit(f"no pinned certfinder for {key}")
    version = pin["version"].lstrip("v")
    suffix = ".exe" if system == "windows" else ""
    url = (
        f"https://github.com/krisiasty/certfinder/releases/download/"
        f"v{version}/certfinder_{version}_{key}{suffix}"
    )
    target = destination / f"certfinder{suffix}"
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - pinned https URL
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        sys.exit(f"certfinder checksum mismatch for {key}: got {digest}, expected {expected}")
    target.write_bytes(data)
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    return target


def stage_theia(theia_dir: Path | None, system: str, arch: str, destination: Path) -> Path | None:
    if theia_dir is None:
        return None
    suffix = ".exe" if system == "windows" else ""
    source = theia_dir / f"cbomkit-theia-{system}-{arch}{suffix}"
    if not source.is_file():
        print(f"note: no theia binary for {system}/{arch} in {theia_dir}; building without it")
        return None
    sums = {
        line.split()[1]: line.split()[0]
        for line in (theia_dir / "SHA256SUMS").read_text().splitlines()
        if line.strip()
    }
    actual = hashlib.sha256(source.read_bytes()).hexdigest()
    if sums.get(source.name) != actual:
        sys.exit(f"{source.name} does not match SHA256SUMS")
    target = destination / f"cbomkit-theia{suffix}"
    shutil.copy2(source, target)
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--theia-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "agent")
    args = parser.parse_args()

    system, arch = platform_key()
    sep = os.pathsep
    with tempfile.TemporaryDirectory(prefix="qavach-agent-build-") as work_name:
        work = Path(work_name)
        certfinder = fetch_certfinder(system, arch, work)
        theia = stage_theia(args.theia_dir, system, arch, work)

        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--noconfirm",
            "--clean",
            "--name",
            "qavach-agent",
            "--distpath",
            str(args.out),
            "--workpath",
            str(work / "pyi"),
            "--specpath",
            str(work),
            "--paths",
            str(ROOT / "apps/agent/src"),
            "--add-binary",
            f"{certfinder}{sep}bin",
        ]
        if theia is not None:
            command += ["--add-binary", f"{theia}{sep}bin"]
        for relative in KNOWLEDGE_FILES:
            source = ROOT / "config" / relative
            command += ["--add-data", f"{source}{sep}config/{Path(relative).parent}"]
        command.append(str(ROOT / "apps/agent/launcher.py"))
        subprocess.run(command, check=True, cwd=ROOT)

    executable = args.out / ("qavach-agent.exe" if system == "windows" else "qavach-agent")
    # Verify the frozen artefact itself, with a stripped environment, not the source tree.
    doctor = subprocess.run(
        [str(executable), "doctor"],
        capture_output=True,
        text=True,
        env={"PATH": "", "SystemRoot": os.environ.get("SystemRoot", "")},
    )
    if doctor.returncode != 0:
        sys.exit(f"frozen agent failed its own doctor check:\n{doctor.stdout}\n{doctor.stderr}")
    report = json.loads(doctor.stdout)
    if not report["frozen"] or report["skipped"]:
        sys.exit(f"frozen agent is not fully equipped: {doctor.stdout}")
    print(doctor.stdout)

    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    (args.out / "SHA256SUMS").write_text(f"{digest}  {executable.name}\n")
    print(f"built {executable} ({system}/{arch}) sha256={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
