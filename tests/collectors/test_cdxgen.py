"""T-032 — `source_scan.cdxgen`, ARCH.md §2.2's cdxgen `cbom` adapter.

Two layers, tested separately per this repo's own established pattern
(`tests/core/test_cbom_normalisation.py`'s docstring: a real cdxgen run is
collector integration-test territory, a hand-written 1.7 document is what
proves the parsing/mapping logic deterministically):

1. The parsing/mapping pipeline (`CdxgenCollector.collect`'s post-sandbox
   half) — exercised against a hand-written CycloneDX 1.7 document via a
   monkeypatched `run_sandboxed`, so it runs with no Docker engine present
   and is deterministic.
2. A real Docker integration test proving the actual sandboxed invocation
   works end to end: the real pinned cbom binary runs, produces JSON, and
   it crosses the boundary and gets parsed without crashing. It does NOT
   assert specific crypto claims are found — live experimentation while
   building this adapter found cdxgen's own Java/JS crypto-detection
   heuristics need a properly-shaped project (pom.xml/build.gradle, or a
   real reachability-analysable JS call site) that a minimal test fixture
   doesn't reliably trigger, and asserting on cdxgen's *detection
   accuracy* is not this adapter's job (`CLAUDE.md §1`: QAVACH does not
   build a crypto-detection engine) — T-024's real fixture corpus is
   where that gets nailed down.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.source_scan.cdxgen import CDXGEN_IMAGE, CdxgenCollector
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_sandbox import SandboxResult

ROOT = Path(__file__).parent.parent.parent
REGISTRY_DIR = ROOT / "config" / "knowledge" / "cdx-crypto-registry"
ALIASES_YAML = ROOT / "config" / "knowledge" / "aliases.yaml"

HAND_WRITTEN_CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/rsa-2048-handwritten",
            "name": "RSA-2048",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "algorithmFamily": "RSASSA-PKCS1",
                    "parameterSetIdentifier": "2048",
                },
                "oid": "1.2.840.113549.1.1.1",
            },
            "evidence": {
                "occurrences": [
                    {"location": "src/main/java/Auth.java", "line": 42},
                    {"location": "src/main/java/Legacy.java"},
                ],
            },
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
    return AliasTable.from_dict(yaml.safe_load(ALIASES_YAML.read_text()))


def _fake_sandbox_result(output: dict[str, object], *, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(
        exit_code=exit_code,
        output=json.dumps(output).encode(),
        stderr=b"",
        duration_seconds=1.0,
        timed_out=False,
    )


def test_supports_only_repository_targets(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    assert collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))
    assert not collector.supports(Target(type=TargetType.CONTAINER_IMAGE, ref="x"))
    assert not collector.supports(Target(type=TargetType.HOST, ref="x"))


def test_parses_a_real_shaped_cbom_into_claims_with_correct_loci(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.source_scan.cdxgen.run_sandboxed",
        lambda config: _fake_sandbox_result(HAND_WRITTEN_CBOM),
    )
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )

    assert not result.partial
    assert result.errors == []
    # One occurrence per evidence.occurrences entry — not collapsed.
    assert len(result.claims) == 2
    paths = {c.locus.path for c in result.claims}  # type: ignore[union-attr]
    assert paths == {"src/main/java/Auth.java", "src/main/java/Legacy.java"}
    assert all(c.name == "RSASSA-PKCS1" for c in result.claims)
    assert all(c.parameter_set == "2048" for c in result.claims)
    assert all(c.oid == "1.2.840.113549.1.1.1" for c in result.claims)
    assert all(c.detection_method == "ast" for c in result.claims)


def test_falls_back_to_repo_root_locus_when_no_occurrences(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = json.loads(json.dumps(HAND_WRITTEN_CBOM))  # deep copy
    document["components"][0]["evidence"] = {}
    monkeypatch.setattr(
        "qavach_collectors.source_scan.cdxgen.run_sandboxed",
        lambda config: _fake_sandbox_result(document),
    )
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert len(result.claims) == 1
    assert result.claims[0].locus.path == "/repo"  # type: ignore[union-attr]


def test_a_failed_sandbox_run_is_reported_as_partial_not_raised(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.source_scan.cdxgen.run_sandboxed",
        lambda config: SandboxResult(
            exit_code=1, output=b"", stderr=b"cbom crashed", duration_seconds=0.5, timed_out=False
        ),
    )
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert result.partial
    assert result.claims == []
    assert result.errors[0].fatal


def test_malformed_json_output_is_reported_as_partial_not_raised(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.source_scan.cdxgen.run_sandboxed",
        lambda config: SandboxResult(
            exit_code=0, output=b"not json", stderr=b"", duration_seconds=0.5, timed_out=False
        ),
    )
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert result.partial
    assert "not valid JSON" in result.errors[0].message


def test_build_resolution_off_by_default_passes_no_install_deps(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = {}

    def _capture(config):
        captured["config"] = config
        return _fake_sandbox_result(
            {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}
        )

    monkeypatch.setattr("qavach_collectors.source_scan.cdxgen.run_sandboxed", _capture)
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )

    config = captured["config"]
    assert "--no-install-deps" in config.command[-1]
    assert "--install-deps " not in config.command[-1]
    assert config.requires_network is False


def test_allow_build_resolution_passes_install_deps_and_requires_network(
    registry: CryptographyRegistry, aliases: AliasTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SECURITY.md §3.1: build resolution is off by default; when the
    operator explicitly opts in, it needs egress — never enabled
    silently."""
    captured = {}

    def _capture(config):
        captured["config"] = config
        return _fake_sandbox_result(
            {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}
        )

    monkeypatch.setattr("qavach_collectors.source_scan.cdxgen.run_sandboxed", _capture)
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"),
        RunContext(scan_run_id="run-1", allow_build_resolution=True),
    )

    config = captured["config"]
    assert "--install-deps " in config.command[-1]
    assert "--no-install-deps" not in config.command[-1]
    assert config.requires_network is True


def test_uses_the_pinned_digest(registry: CryptographyRegistry, aliases: AliasTable) -> None:
    collector = CdxgenCollector(registry=registry, aliases=aliases)
    assert collector._image_ref == CDXGEN_IMAGE
    assert "@sha256:" in CDXGEN_IMAGE


# --- Real Docker integration test ---

_DOCKER_AVAILABLE = shutil.which("docker") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="no Docker on PATH")
def test_real_cbom_run_produces_parseable_output(
    registry: CryptographyRegistry, aliases: AliasTable, tmp_path: Path
) -> None:
    """Proves the actual sandboxed invocation of the real pinned cbom
    binary works end to end: it runs, produces valid CycloneDX JSON on
    stdout (not corrupted by cbom's own progress chatter), and the
    collector parses it into a well-formed (possibly empty)
    `CollectorResult` without raising. Does not assert any specific crypto
    claim was found — see the module docstring."""
    repo_dir = ROOT / "tests" / "collectors" / ".scratch-cdxgen-repo"
    repo_dir.mkdir(exist_ok=True)
    (repo_dir / "pom.xml").write_text(
        """<project><modelVersion>4.0.0</modelVersion>
<groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0</version>
</project>"""
    )
    try:
        collector = CdxgenCollector(registry=registry, aliases=aliases)
        result = collector.collect(
            Target(type=TargetType.REPOSITORY, ref=str(repo_dir)),
            RunContext(scan_run_id="run-real"),
        )
        assert not result.partial, result.errors
        assert result.tool.exit_code == 0
        document = json.loads(result.raw.decode())
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] in {"1.6", "1.7"}
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
