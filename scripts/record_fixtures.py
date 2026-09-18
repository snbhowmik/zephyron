"""T-024 — records real scanner output for `tests/fixtures/targets/polyglot`.

Runs each collector through the real sandbox against the real pinned/built
images and writes the tool's *raw* output plus a claims summary into
`tests/fixtures/scanner-output/`. Re-run after changing the target or bumping
a scanner; commit the diff so a change in tool behaviour is reviewable.
Needs Docker and `make build-images`. Not run in CI.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.sbom import CryptoLibraryMapping
from qavach_collectors.sbom.syft import SyftCollector
from qavach_collectors.source_scan import (
    CbomkitCollector,
    CdxgenCollector,
    OpengrepCollector,
    load_rules,
)
from qavach_core.normalize import AliasTable, CryptographyRegistry

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "tests" / "fixtures" / "targets" / "polyglot"
OUT = ROOT / "tests" / "fixtures" / "scanner-output"


def image_id(tag: str) -> str:
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", tag], capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.exit(f"{tag} is not built: run `make build-images`")
    return proc.stdout.strip()


def main() -> None:
    registry = CryptographyRegistry.from_dict(
        json.loads(
            (ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text()
        )
    )
    aliases = AliasTable.from_dict(
        yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text())
    )
    libraries = CryptoLibraryMapping.from_entries(
        yaml.safe_load((ROOT / "config/knowledge/crypto_libraries.yaml").read_text())["libraries"]
    )
    rules = load_rules(yaml.safe_load((ROOT / "config/opengrep-rules/crypto.yaml").read_text()))

    target = Target(type=TargetType.REPOSITORY, ref=str(TARGET))
    collectors = {
        "cdxgen": (CdxgenCollector(registry=registry, aliases=aliases), "cdx.json"),
        "cbomkit": (
            CbomkitCollector(
                registry=registry, aliases=aliases, image_ref=image_id("qavach/cbomkit-lib:dev")
            ),
            "cdx.json",
        ),
        "opengrep": (
            OpengrepCollector(rules=rules, image_ref=image_id("qavach/opengrep:dev")),
            "sarif",
        ),
        "syft": (SyftCollector(crypto_libraries=libraries), "syft.json"),
    }
    for name, (collector, suffix) in collectors.items():
        result = collector.collect(target, RunContext(scan_run_id="record"))
        directory = OUT / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"polyglot.{suffix}").write_bytes(result.raw)
        print(
            f"{name}: partial={result.partial} claims={len(result.claims)} errors={result.errors}"
        )


if __name__ == "__main__":
    main()
