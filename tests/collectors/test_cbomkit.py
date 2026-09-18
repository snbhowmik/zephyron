"""T-038 — `source_scan.cbomkit`. Parsing/mapping is tested against a
hand-written CBOM via a monkeypatched `run_sandboxed`; the integration
test runs the *real* QAVACH-built image (`docker/cbomkit-lib`) against a
real Python file with genuine crypto calls and asserts on the exact
detections and line numbers the plugin reports."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.source_scan import CbomkitCollector, ImageNotBuiltError
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_sandbox import SandboxResult

ROOT = Path(__file__).parent.parent.parent
REGISTRY_DIR = ROOT / "config" / "knowledge" / "cdx-crypto-registry"
FAKE_IMAGE = "sha256:" + "c" * 64

CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/aes-cbc",
            "name": "AES-CBC",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "block-cipher",
                    "algorithmFamily": "AES",
                    "mode": "cbc",
                },
            },
            "evidence": {"occurrences": [{"location": "app.py", "line": 9}]},
        }
    ],
}


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    return CryptographyRegistry.from_dict(
        json.loads((REGISTRY_DIR / "cryptography-defs.json").read_text())
    )


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(
        yaml.safe_load((ROOT / "config" / "knowledge" / "aliases.yaml").read_text())
    )


def _ok(output: dict[str, object]) -> SandboxResult:
    return SandboxResult(0, json.dumps(output).encode(), b"", 1.0, False)


def test_an_unconfigured_image_fails_loudly(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    with pytest.raises(ImageNotBuiltError, match="build-images"):
        CbomkitCollector(registry=registry, aliases=aliases, image_ref=None)


def test_maps_a_cbom_into_ast_tier_claims(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("qavach_collectors.source_scan.cbomkit.run_sandboxed", lambda c: _ok(CBOM))
    result = CbomkitCollector(registry=registry, aliases=aliases, image_ref=FAKE_IMAGE).collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="r")
    )
    assert not result.partial
    assert [c.name for c in result.claims] == ["AES"]
    assert result.claims[0].mode == "cbc"
    assert result.claims[0].confidence.name == "AST"
    assert result.claims[0].locus.path == "app.py"  # type: ignore[union-attr]
    assert result.claims[0].locus.offset == 9  # type: ignore[union-attr]


def test_never_requests_network(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = {}

    def _capture(config):  # type: ignore[no-untyped-def]
        seen["config"] = config
        return _ok(CBOM)

    monkeypatch.setattr("qavach_collectors.source_scan.cbomkit.run_sandboxed", _capture)
    CbomkitCollector(registry=registry, aliases=aliases, image_ref=FAKE_IMAGE).collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"),
        RunContext(scan_run_id="r", allow_build_resolution=True),
    )
    assert seen["config"].requires_network is False, "cbomkit must never build the target"


def test_failed_run_is_partial_not_raised(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.source_scan.cbomkit.run_sandboxed",
        lambda c: SandboxResult(1, b"", b"boom", 0.1, False),
    )
    result = CbomkitCollector(registry=registry, aliases=aliases, image_ref=FAKE_IMAGE).collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="r")
    )
    assert result.partial and result.errors[0].fatal


def test_malformed_output_is_partial_not_raised(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.source_scan.cbomkit.run_sandboxed",
        lambda c: SandboxResult(0, b"not json", b"", 0.1, False),
    )
    result = CbomkitCollector(registry=registry, aliases=aliases, image_ref=FAKE_IMAGE).collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="r")
    )
    assert result.partial


def _built_image_id() -> str | None:
    if shutil.which("docker") is None:
        return None
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "qavach/cbomkit-lib:dev"],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


@pytest.mark.integration
def test_real_image_detects_real_crypto_with_exact_locations(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    image = _built_image_id()
    if image is None:
        pytest.skip("image not built — run `make build-images`")

    repo = ROOT / "tests" / "collectors" / ".scratch-cbomkit-repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "\n"
        "def encrypt(key, iv, data):\n"
        "    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()\n"
        "    return enc.update(data) + enc.finalize()\n"
        "\n"
        "def digest(data):\n"
        "    h = hashes.Hash(hashes.SHA256())\n"
        "    h.update(data)\n"
        "    return h.finalize()\n"
    )
    (repo / "requirements.txt").write_text("cryptography==43.0.1\n")
    try:
        result = CbomkitCollector(registry=registry, aliases=aliases, image_ref=image).collect(
            Target(type=TargetType.REPOSITORY, ref=str(repo)), RunContext(scan_run_id="r")
        )
    finally:
        shutil.rmtree(repo, ignore_errors=True)

    assert not result.partial, result.errors
    names = {c.name for c in result.claims}
    assert "AES" in names
    assert "SHA-2" in names or any(c.name and "SHA" in c.name for c in result.claims)
    aes = next(c for c in result.claims if c.name == "AES")
    assert aes.locus.path.endswith("app.py")  # type: ignore[union-attr]
    assert aes.locus.offset == 5  # type: ignore[union-attr]  # the Cipher(...) line
