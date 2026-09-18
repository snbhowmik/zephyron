"""T-039 — `container.theia`. Unit tests use a hand-written CBOM; the
integration test runs the real pinned theia image, sandboxed, over a real
`docker save` archive."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.container import THEIA_IMAGE, TheiaCollector
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_sandbox import SandboxResult

ROOT = Path(__file__).parent.parent.parent
SHELL_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/rsa",
            "name": "RSA-2048",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "algorithmFamily": "RSASSA-PKCS1",
                    "parameterSetIdentifier": "2048",
                },
            },
            "evidence": {"occurrences": [{"location": "/etc/ssl/server.pem"}]},
        }
    ],
}


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    path = ROOT / "config" / "knowledge" / "cdx-crypto-registry" / "cryptography-defs.json"
    return CryptographyRegistry.from_dict(json.loads(path.read_text()))


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(
        yaml.safe_load((ROOT / "config" / "knowledge" / "aliases.yaml").read_text())
    )


def test_supports_only_container_image_targets(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    collector = TheiaCollector(registry=registry, aliases=aliases)
    assert collector.supports(Target(type=TargetType.CONTAINER_IMAGE, ref="/x/image.tar"))
    assert not collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))
    assert "@sha256:" in THEIA_IMAGE


def test_archive_is_mounted_by_parent_dir_and_never_needs_network(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = {}

    def _capture(config):  # type: ignore[no-untyped-def]
        seen["config"] = config
        return SandboxResult(0, json.dumps(CBOM).encode(), b"", 1.0, False)

    monkeypatch.setattr("qavach_collectors.container.theia.run_sandboxed", _capture)
    result = TheiaCollector(registry=registry, aliases=aliases).collect(
        Target(type=TargetType.CONTAINER_IMAGE, ref="/srv/images/app.tar"),
        RunContext(scan_run_id="r"),
    )
    config = seen["config"]
    assert config.target_mount == Path("/srv/images")
    assert config.command == ("/app/cbomkit-theia", "image", "/target/app.tar")
    assert config.requires_network is False
    assert [c.name for c in result.claims] == ["RSASSA-PKCS1"]
    assert result.claims[0].confidence.name == "DEPENDENCY"


def test_failed_run_is_partial_not_raised(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.container.theia.run_sandboxed",
        lambda c: SandboxResult(1, b"", b"boom", 0.1, False),
    )
    result = TheiaCollector(registry=registry, aliases=aliases).collect(
        Target(type=TargetType.CONTAINER_IMAGE, ref="/x/a.tar"), RunContext(scan_run_id="r")
    )
    assert result.partial and result.errors[0].fatal


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="no docker")
def test_real_theia_scans_a_real_image_archive(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    scratch = ROOT / "tests" / "collectors" / ".scratch-theia"
    scratch.mkdir(exist_ok=True)
    try:
        subprocess.run(
            ["docker", "save", SHELL_IMAGE, "-o", str(scratch / "image.tar")],
            capture_output=True,
            check=True,
        )
        (scratch / "image.tar").chmod(0o644)
        result = TheiaCollector(registry=registry, aliases=aliases).collect(
            Target(type=TargetType.CONTAINER_IMAGE, ref=str(scratch / "image.tar")),
            RunContext(scan_run_id="r"),
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    assert not result.partial, result.errors
    document = json.loads(result.raw.decode())
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
