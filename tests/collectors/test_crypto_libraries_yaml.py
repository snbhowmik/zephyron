"""T-034 — `config/knowledge/crypto_libraries.yaml`'s own exit criteria,
enforced as a real test rather than left as a one-time manual check:
every `provides` value must be a real, resolvable algorithm family name,
never a typo or a spelling `resolve_algorithm` (T-012) doesn't recognise,
and the schema must never grow a usage/confidence field that would
contradict TASK.md T-034's "capability, not usage" requirement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from qavach_core.normalize import (
    AliasTable,
    CryptographyRegistry,
    RawAlgorithmClaim,
    UnresolvedAlgorithm,
    resolve_algorithm,
)

ROOT = Path(__file__).parent.parent.parent
REGISTRY_DIR = ROOT / "config" / "knowledge" / "cdx-crypto-registry"
CRYPTO_LIBRARIES_YAML = ROOT / "config" / "knowledge" / "crypto_libraries.yaml"


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


@pytest.fixture(scope="module")
def raw_libraries() -> list[dict[str, object]]:
    data = yaml.safe_load(CRYPTO_LIBRARIES_YAML.read_text())
    libraries: list[dict[str, object]] = data["libraries"]
    return libraries


def test_starts_with_at_least_40_libraries(raw_libraries: list[dict[str, object]]) -> None:
    """TASK.md T-034: 'Start with 40 libraries covering Java, Python, Go,
    JS. This is real curation work, not a config stub.'"""
    assert len(raw_libraries) >= 40


def test_covers_all_four_ecosystems(raw_libraries: list[dict[str, object]]) -> None:
    purl_types = {entry["type"] for entry in raw_libraries}
    assert purl_types == {"pypi", "maven", "golang", "npm"}


def test_no_duplicate_package_keys(raw_libraries: list[dict[str, object]]) -> None:
    keys = [(e["type"], e.get("namespace"), e["name"]) for e in raw_libraries]
    assert len(keys) == len(set(keys)), "duplicate (type, namespace, name) entries found"


def test_schema_never_smuggles_in_usage_semantics(raw_libraries: list[dict[str, object]]) -> None:
    """TASK.md T-034: 'Schema must force capability not usage semantics.'
    A `used`/`confidence`/`observed` field on an entry would describe
    whether the capability was *exercised* in the scanned codebase — a
    different, much stronger claim than 'this dependency provides X' —
    and must never appear here."""
    forbidden_keys = {"used", "confidence", "observed", "usage", "detected"}
    allowed_keys = {"type", "namespace", "name", "provides"}
    for entry in raw_libraries:
        assert forbidden_keys.isdisjoint(entry.keys()), f"usage-semantics field found in {entry}"
        assert set(entry.keys()) <= allowed_keys, f"unexpected field in {entry}"


def test_every_provides_entry_resolves_to_a_real_algorithm_family(
    raw_libraries: list[dict[str, object]],
    registry: CryptographyRegistry,
    aliases: AliasTable,
) -> None:
    """The real regression test: every capability name in the file must
    resolve through the actual `resolve_algorithm` pipeline, not just look
    plausible. Catches a typo'd family name (e.g. "AES-256" instead of
    "AES", or "SHA256" instead of "SHA-2") the moment it's introduced,
    rather than letting it silently become an `UNKNOWN` finding at scan
    time (invariant I8) long after this file was written."""
    unresolved: list[tuple[str, str]] = []
    for entry in raw_libraries:
        package_name = f"{entry['type']}:{entry.get('namespace', '')}/{entry['name']}"
        for capability in entry["provides"]:  # type: ignore[union-attr]
            claim = RawAlgorithmClaim(name=capability, oid=None)
            resolved = resolve_algorithm(claim, registry=registry, aliases=aliases)
            if isinstance(resolved, UnresolvedAlgorithm):
                unresolved.append((package_name, capability))

    assert unresolved == [], f"unresolvable capability names: {unresolved}"


def test_loads_into_a_crypto_library_mapping_and_looks_up_a_known_package(
    raw_libraries: list[dict[str, object]],
) -> None:
    from packageurl import PackageURL
    from qavach_collectors.sbom import CryptoLibraryMapping

    mapping = CryptoLibraryMapping.from_entries(raw_libraries)
    purl = PackageURL.from_string("pkg:pypi/cryptography@43.0.1")
    capabilities = mapping.lookup(purl)
    assert capabilities is not None
    assert "AES" in capabilities
    assert "RSASSA-PKCS1" in capabilities
