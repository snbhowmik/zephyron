"""T-043 — external CBOM ingestion (`PRD.md FR-180`), including the
`SECURITY.md §9` hostile-input behaviour: size cap before read, nested-JSON
bomb, and per-component isolation of malformed entries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.cbom_upload import ExternalCbomCollector
from qavach_core.normalize import AliasTable, CryptographyRegistry

ROOT = Path(__file__).parent.parent.parent


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    p = ROOT / "config" / "knowledge" / "cdx-crypto-registry" / "cryptography-defs.json"
    return CryptographyRegistry.from_dict(json.loads(p.read_text()))


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(
        yaml.safe_load((ROOT / "config" / "knowledge" / "aliases.yaml").read_text())
    )


def _aes(ref: str, location: str) -> dict[str, object]:
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": "AES-256-GCM",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "ae",
                "algorithmFamily": "AES",
                "parameterSetIdentifier": "256",
                "mode": "gcm",
            },
        },
        "evidence": {"occurrences": [{"location": location, "line": 7}]},
    }


def _write(tmp_path: Path, document: object, name: str = "vendor.cbom.json") -> Target:
    path = tmp_path / name
    path.write_text(json.dumps(document))
    return Target(type=TargetType.CBOM_UPLOAD, ref=str(path))


def _collect(collector: ExternalCbomCollector, target: Target):  # type: ignore[no-untyped-def]
    return collector.collect(target, RunContext(scan_run_id="r"))


@pytest.mark.parametrize("version", ["1.4", "1.5", "1.6", "1.7"])
def test_ingests_every_supported_spec_version(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable, version: str
) -> None:
    target = _write(
        tmp_path,
        {"bomFormat": "CycloneDX", "specVersion": version, "components": [_aes("a", "src/A.java")]},
    )
    result = _collect(ExternalCbomCollector(registry=registry, aliases=aliases), target)
    assert not result.partial, result.errors
    assert [c.name for c in result.claims] == ["AES"]
    assert result.raw_format.value == f"cdx-{version}"
    assert result.claims[0].confidence.name == "ATTESTED"
    assert result.claims[0].locus.offset == 7  # type: ignore[union-attr]


def test_the_document_is_retained_verbatim(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [_aes("a", "x")]}
    target = _write(tmp_path, document)
    result = _collect(ExternalCbomCollector(registry=registry, aliases=aliases), target)
    assert json.loads(result.raw) == document


def test_same_relative_path_from_two_vendors_gets_distinct_loci(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    """Two vendors both reporting `src/Crypto.java` are two different
    files — without a provenance prefix they would share a locus and be
    read as one place disagreeing with itself."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [_aes("a", "src/Crypto.java")],
    }
    collector = ExternalCbomCollector(registry=registry, aliases=aliases)
    a = _collect(
        collector,
        Target(
            type=TargetType.CBOM_UPLOAD,
            ref=str(_write(tmp_path, doc, "a.json").ref),
            options={"source": "vendor-a"},
        ),
    )
    b = _collect(
        collector,
        Target(
            type=TargetType.CBOM_UPLOAD,
            ref=str(_write(tmp_path, doc, "b.json").ref),
            options={"source": "vendor-b"},
        ),
    )
    assert a.claims[0].locus.path != b.claims[0].locus.path  # type: ignore[union-attr]
    assert a.claims[0].locus.path.startswith("vendor-a!")  # type: ignore[union-attr]


def test_one_malformed_component_does_not_discard_the_rest(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    bad = {"type": "cryptographic-asset", "bom-ref": "bad", "name": "x", "cryptoProperties": {}}
    target = _write(
        tmp_path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [bad, _aes("good", "ok.java")],
        },
    )
    result = _collect(ExternalCbomCollector(registry=registry, aliases=aliases), target)
    assert result.partial
    assert [c.name for c in result.claims] == ["AES"], "the healthy component must survive"
    assert len(result.errors) == 1 and not result.errors[0].fatal
    assert "'bad'" in result.errors[0].message


def test_non_crypto_components_are_ignored_not_errors(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    lib = {"type": "library", "name": "left-pad", "version": "1.0"}
    target = _write(tmp_path, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [lib]})
    result = _collect(ExternalCbomCollector(registry=registry, aliases=aliases), target)
    assert not result.partial and result.claims == []


def test_size_cap_is_enforced_before_the_file_is_read(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b" " * 4096)
    collector = ExternalCbomCollector(registry=registry, aliases=aliases, max_bytes=1024)
    result = _collect(collector, Target(type=TargetType.CBOM_UPLOAD, ref=str(path)))
    assert result.partial and result.errors[0].fatal
    assert "cap" in result.errors[0].message
    assert result.raw == b"", "an over-cap file must not be read into memory at all"


def test_deeply_nested_json_degrades_instead_of_raising(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    path = tmp_path / "nested.json"
    path.write_text("[" * 200_000 + "]" * 200_000)
    result = _collect(
        ExternalCbomCollector(registry=registry, aliases=aliases),
        Target(type=TargetType.CBOM_UPLOAD, ref=str(path)),
    )
    assert result.partial and result.errors[0].fatal


@pytest.mark.parametrize(
    "content",
    [b"not json", b"\xff\xfe\x00", b"[1, 2, 3]", b'{"specVersion": "9.9", "components": []}'],
)
def test_garbage_and_unsupported_versions_degrade_not_raise(
    tmp_path: Path, registry: CryptographyRegistry, aliases: AliasTable, content: bytes
) -> None:
    path = tmp_path / "x.json"
    path.write_bytes(content)
    result = _collect(
        ExternalCbomCollector(registry=registry, aliases=aliases),
        Target(type=TargetType.CBOM_UPLOAD, ref=str(path)),
    )
    assert result.partial and result.errors[0].fatal


def test_missing_file_degrades_not_raises(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    result = _collect(
        ExternalCbomCollector(registry=registry, aliases=aliases),
        Target(type=TargetType.CBOM_UPLOAD, ref="/nonexistent/x.json"),
    )
    assert result.partial


def test_supports_only_cbom_upload_targets(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    c = ExternalCbomCollector(registry=registry, aliases=aliases)
    assert c.supports(Target(type=TargetType.CBOM_UPLOAD, ref="x"))
    assert not c.supports(Target(type=TargetType.REPOSITORY, ref="x"))
