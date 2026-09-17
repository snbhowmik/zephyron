"""T-012 — algorithm resolution against the *real* vendored registry
(T-011), not just synthetic fixtures. Loading the JSON file here is
ordinary test I/O, not a violation of packages/core's own zero-I/O rule —
the I/O happens in this test file, not inside qavach_core's source
(CryptographyRegistry.from_dict itself takes an already-parsed dict).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from qavach_core.normalize import (
    AliasTable,
    CryptographyRegistry,
    RawAlgorithmClaim,
    ResolvedAlgorithm,
    ResolvedCurve,
    UnresolvedAlgorithm,
    UnresolvedCurve,
    resolve_algorithm,
    resolve_curve,
)

REGISTRY_JSON = (
    Path(__file__).parent.parent.parent
    / "config"
    / "knowledge"
    / "cdx-crypto-registry"
    / "cryptography-defs.json"
)


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    return CryptographyRegistry.from_dict(json.loads(REGISTRY_JSON.read_text()))


@pytest.fixture
def empty_aliases() -> AliasTable:
    return AliasTable.from_dict({})


# --- Step 2: registry exact match (real data, not a fixture) ---


def test_resolves_ml_kem_by_registry_exact_match(
    registry: CryptographyRegistry, empty_aliases: AliasTable
) -> None:
    claim = RawAlgorithmClaim(name="ML-KEM", oid=None)
    result = resolve_algorithm(claim, registry=registry, aliases=empty_aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.algorithm_family == "ML-KEM"
    assert result.resolution_method == "registry-exact"


def test_resolves_ecdsa_primitive_from_registry_when_unambiguous(
    registry: CryptographyRegistry, empty_aliases: AliasTable
) -> None:
    """ECDSA has exactly one primitive (signature) across its variants —
    the resolver should fill it in even when the claim itself is silent."""
    claim = RawAlgorithmClaim(name="ECDSA", oid=None, primitive=None)
    result = resolve_algorithm(claim, registry=registry, aliases=empty_aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.primitive == "signature"


def test_does_not_guess_primitive_for_a_multi_primitive_family(
    registry: CryptographyRegistry, empty_aliases: AliasTable
) -> None:
    """AES spans block-cipher/ae/key-wrap/mac — resolving family must not
    silently pick one when the claim doesn't say which."""
    claim = RawAlgorithmClaim(name="AES", oid=None, primitive=None)
    result = resolve_algorithm(claim, registry=registry, aliases=empty_aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.primitive is None


def test_trusts_claims_own_primitive_over_registry_guess(
    registry: CryptographyRegistry, empty_aliases: AliasTable
) -> None:
    claim = RawAlgorithmClaim(name="AES", oid=None, primitive="ae")
    result = resolve_algorithm(claim, registry=registry, aliases=empty_aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.primitive == "ae"


# --- Step 1: OID via the alias table (registry itself has none — T-011) ---


def test_resolves_ml_kem_768_by_curated_oid(registry: CryptographyRegistry) -> None:
    aliases = AliasTable.from_dict(
        {"oids": {"2.16.840.1.101.3.4.4.2": {"family": "ML-KEM", "parameter_set": "768"}}}
    )
    claim = RawAlgorithmClaim(name=None, oid="2.16.840.1.101.3.4.4.2")
    result = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.algorithm_family == "ML-KEM"
    assert result.parameter_set == "768"
    assert result.resolution_method == "oid"


def test_oid_takes_priority_over_a_conflicting_name(registry: CryptographyRegistry) -> None:
    """A claim with both a curated OID and a name that would ALSO resolve
    must use the OID (step 1 beats step 2) — ARCH.md §5.2's stated order."""
    aliases = AliasTable.from_dict(
        {"oids": {"2.16.840.1.101.3.4.4.2": {"family": "ML-KEM", "parameter_set": "768"}}}
    )
    claim = RawAlgorithmClaim(name="ML-KEM", oid="2.16.840.1.101.3.4.4.2")
    result = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.resolution_method == "oid"
    assert result.parameter_set == "768"


# --- Step 3: alias table by name (pre-standardisation names) ---


def test_resolves_kyber768_via_name_alias(
    registry: CryptographyRegistry,
) -> None:
    aliases = AliasTable.from_dict(
        {"names": {"Kyber768": {"family": "ML-KEM", "parameter_set": "768"}}}
    )
    claim = RawAlgorithmClaim(name="Kyber768", oid=None)
    result = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedAlgorithm)
    assert result.algorithm_family == "ML-KEM"
    assert result.parameter_set == "768"
    assert result.resolution_method == "alias-table"


# --- Step 4: never dropped silently ---


def test_unresolvable_algorithm_is_never_silently_dropped(
    registry: CryptographyRegistry, empty_aliases: AliasTable
) -> None:
    claim = RawAlgorithmClaim(name="TotallyMadeUpAlgorithm9000", oid=None)
    result = resolve_algorithm(claim, registry=registry, aliases=empty_aliases)
    assert isinstance(result, UnresolvedAlgorithm)
    assert result.raw_name == "TotallyMadeUpAlgorithm9000"


def test_no_fuzzy_matching_ever(registry: CryptographyRegistry, empty_aliases: AliasTable) -> None:
    """ARCH.md §6.5: a near-miss must not silently merge with a real
    family. "ML-KEM " (trailing space) or "ml-kem" (wrong case) must NOT
    resolve via registry-exact — that is what the alias table is for,
    deliberately, so every acceptable spelling is a reviewable line in
    aliases.yaml, not an algorithm's guess."""
    for near_miss in ("ML-KEM ", "ml-kem", "MLKEM", "ML_KEM"):
        claim = RawAlgorithmClaim(name=near_miss, oid=None)
        result = resolve_algorithm(claim, registry=registry, aliases=empty_aliases)
        assert isinstance(result, UnresolvedAlgorithm), f"{near_miss!r} should not registry-match"


# --- Curve resolution against real data (A-18's canonical example) ---


def test_curve_aliases_collapse_to_the_same_oid(registry: CryptographyRegistry) -> None:
    """ARCH.md §5.2/§8.5: secp256r1 = prime256v1 = P-256 = the OID.
    All four spellings must resolve to the identical canonical value."""
    spellings = ["secp256r1", "prime256v1", "P-256", "1.2.840.10045.3.1.7"]
    results = [resolve_curve(s, registry=registry) for s in spellings]
    for r in results:
        assert isinstance(r, ResolvedCurve)
    canonicals = {r.canonical for r in results if isinstance(r, ResolvedCurve)}
    assert canonicals == {"1.2.840.10045.3.1.7"}, canonicals


def test_curve_without_an_oid_canonicalises_to_registry_token(
    registry: CryptographyRegistry,
) -> None:
    result = resolve_curve("BLS12-381", registry=registry)
    assert isinstance(result, ResolvedCurve)
    assert result.canonical == "BLS12-381"


def test_unknown_curve_is_never_silently_dropped(registry: CryptographyRegistry) -> None:
    result = resolve_curve("not-a-real-curve", registry=registry)
    assert isinstance(result, UnresolvedCurve)


def test_no_curve_claimed_is_distinct_from_unresolved(registry: CryptographyRegistry) -> None:
    """Absence and failure are different states — ARCH.md §4.2's "never
    render 0 for not applicable" spirit. An RSA key has no curve at all;
    that is not the same as a curve QAVACH failed to recognise."""
    assert resolve_curve(None, registry=registry) is None
