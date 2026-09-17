"""T-013 — config/knowledge/aliases.yaml against the real resolver (T-012).

Loading the YAML here is ordinary test I/O (packages/core itself never
reads this file — AliasTable.from_dict() takes an already-parsed dict).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from qavach_core.normalize import (
    AliasTable,
    CryptographyRegistry,
    RawAlgorithmClaim,
    ResolvedAlgorithm,
    ResolvedCurve,
    resolve_algorithm,
    resolve_curve,
)

ALIASES_YAML = Path(__file__).parent.parent.parent / "config" / "knowledge" / "aliases.yaml"
REGISTRY_JSON = (
    Path(__file__).parent.parent.parent
    / "config"
    / "knowledge"
    / "cdx-crypto-registry"
    / "cryptography-defs.json"
)


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(yaml.safe_load(ALIASES_YAML.read_text()))


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    import json

    return CryptographyRegistry.from_dict(json.loads(REGISTRY_JSON.read_text()))


def test_aliases_yaml_parses(aliases: AliasTable) -> None:
    assert len(aliases.by_oid) > 0
    assert len(aliases.by_name) > 0
    assert len(aliases.curve_aliases) > 0


@pytest.mark.parametrize(
    ("oid", "expected_family", "expected_param"),
    [
        ("2.16.840.1.101.3.4.4.1", "ML-KEM", "512"),
        ("2.16.840.1.101.3.4.4.2", "ML-KEM", "768"),
        ("2.16.840.1.101.3.4.4.3", "ML-KEM", "1024"),
        ("2.16.840.1.101.3.4.3.17", "ML-DSA", "44"),
        ("2.16.840.1.101.3.4.3.18", "ML-DSA", "65"),
        ("2.16.840.1.101.3.4.3.19", "ML-DSA", "87"),
        ("2.16.840.1.101.3.4.3.20", "SLH-DSA", "SHA2-128s"),
        ("2.16.840.1.101.3.4.3.26", "SLH-DSA", "SHAKE-128s"),
        ("2.16.840.1.101.3.4.3.30", "SLH-DSA", "SHAKE-256s"),
    ],
)
def test_pqc_oids_resolve_via_real_curated_data(
    oid: str,
    expected_family: str,
    expected_param: str,
    registry: CryptographyRegistry,
    aliases: AliasTable,
) -> None:
    """A-19's golden test, algorithm-resolution half — classification
    (must be QUANTUM_SAFE) is covered separately once classify.py (T-015)
    exists; this proves the OID -> (family, parameter_set) half using the
    real, primary-source-verified aliases.yaml, not a synthetic fixture."""
    claim = RawAlgorithmClaim(name=None, oid=oid)
    result = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedAlgorithm), f"{oid} did not resolve: {result}"
    assert result.algorithm_family == expected_family
    assert result.parameter_set == expected_param
    assert result.resolution_method == "oid"


@pytest.mark.parametrize(
    ("name", "expected_family", "expected_param"),
    [
        ("Kyber768", "ML-KEM", "768"),
        ("CRYSTALS-Kyber1024", "ML-KEM", "1024"),
        ("Dilithium2", "ML-DSA", "44"),
        ("Dilithium3", "ML-DSA", "65"),
        ("Dilithium5", "ML-DSA", "87"),
        ("EC", "ECDSA", None),
        ("RSA", "RSASSA-PKCS1", None),
        ("rsaEncryption", "RSASSA-PKCS1", None),
    ],
)
def test_name_aliases_resolve_via_real_curated_data(
    name: str,
    expected_family: str,
    expected_param: str | None,
    registry: CryptographyRegistry,
    aliases: AliasTable,
) -> None:
    claim = RawAlgorithmClaim(name=name, oid=None)
    result = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedAlgorithm), f"{name!r} did not resolve: {result}"
    assert result.algorithm_family == expected_family
    assert result.parameter_set == expected_param


@pytest.mark.parametrize("spelling", ["X25519", "x25519", "curve25519"])
def test_x25519_spellings_collapse_to_curve25519(
    spelling: str, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    result = resolve_curve(spelling, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedCurve)
    assert result.canonical == "Curve25519"
