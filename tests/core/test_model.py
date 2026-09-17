"""T-010 — ARCH.md §4 domain model.

These tests lock in the exact string/int values ARCH.md specifies (they are
load-bearing for CBOM export and cross-tool interop, not implementation
detail), the immutability contract, and the two invariants that are easy to
silently violate later: no scalar key_size (§4.2), and ConfidenceTier's
ordering driving §6.4's precedence.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest
from qavach_core.model import (
    AssetIdentity,
    AssetType,
    ConfidenceTier,
    CryptoAsset,
    CryptoFunction,
    DataClass,
    Dispute,
    FileLocus,
    FindingClass,
    HostLocus,
    IdentityKind,
    MigrationAuthority,
    Occurrence,
    System,
)
from qavach_core.model.dispute import AttributeClaim

# --- Enum values are a contract with CycloneDX / external consumers ---


def test_asset_type_values() -> None:
    assert AssetType.ALGORITHM == "algorithm"
    assert AssetType.CERTIFICATE == "certificate"
    assert AssetType.PROTOCOL == "protocol"
    assert AssetType.RELATED_MATERIAL == "related-crypto-material"


def test_crypto_function_values() -> None:
    assert {f.value for f in CryptoFunction} == {
        "key-encapsulation",
        "key-agreement",
        "encryption",
        "signature",
        "mac",
        "hash",
        "kdf",
        "drbg",
    }


def test_finding_class_values() -> None:
    assert {f.value for f in FindingClass} == {
        "quantum-vulnerable",
        "classical-weak",
        "grover-affected",
        "quantum-safe",
        "unknown",
    }


def test_migration_authority_values() -> None:
    assert {m.value for m in MigrationAuthority} == {
        "self",
        "vendor",
        "external-trust-anchor",
        "regulator-gated",
        "unknown",
    }


def test_confidence_tier_ordering() -> None:
    """Higher wins (ARCH.md §6.4). Get this backwards and every precedence
    decision in reconciliation inverts silently."""
    assert (
        ConfidenceTier.RUNTIME
        > ConfidenceTier.ARTEFACT
        > ConfidenceTier.ATTESTED
        > ConfidenceTier.DEPENDENCY
        > ConfidenceTier.AST
        > ConfidenceTier.PATTERN
        > ConfidenceTier.HEURISTIC
    )
    assert ConfidenceTier.RUNTIME == 100
    assert ConfidenceTier.HEURISTIC == 10


# --- Immutability ---


@pytest.mark.parametrize(
    ("instance_factory", "attr"),
    [
        (lambda: AssetIdentity(kind=IdentityKind.ALGO, key="abc"), "key"),
        (lambda: FileLocus(path="/tmp/x", offset=0), "path"),
    ],
)
def test_model_objects_are_frozen(instance_factory, attr: str) -> None:
    instance = instance_factory()
    with pytest.raises(dataclasses.FrozenInstanceError):
        instance.__setattr__(attr, "mutated")  # noqa: B010 — deliberately testing the setattr path


# --- ARCH.md §6.1 identity shape ---


def test_asset_identity_matches_arch_example() -> None:
    identity = AssetIdentity(kind=IdentityKind.CA_KEY, key="deadbeef")
    assert identity.kind == "ca-key"
    assert identity.key == "deadbeef"


# --- ARCH.md §4.2: no scalar key_size, ever ---


def test_crypto_asset_has_no_scalar_key_size_field() -> None:
    field_names = {f.name for f in dataclasses.fields(CryptoAsset)}
    assert "key_size" not in field_names, (
        "ARCH.md §4.2: CryptoAsset must never grow a scalar key_size field — "
        "store parameter_set, and a separate modulus length only where meaningful."
    )
    assert "parameter_set" in field_names


# --- CryptoAsset validation ---


def _occurrence(**overrides: object) -> Occurrence:
    defaults: dict[str, object] = {
        "locus": FileLocus(path="/etc/ssl/cert.pem", offset=0),
        "collector": "tls.store",
        "tool_version": "1.0.0",
        "confidence": ConfidenceTier.ARTEFACT,
        "detection_method": "filename",
        "raw_ref": "raw://scan/1/occ/1",
        "observed_at": datetime(2026, 9, 18, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Occurrence(**defaults)  # type: ignore[arg-type]


def _asset(**overrides: object) -> CryptoAsset:
    defaults: dict[str, object] = {
        "identity": AssetIdentity(kind=IdentityKind.ALGO, key="hash"),
        "asset_type": AssetType.ALGORITHM,
        "function": CryptoFunction.SIGNATURE,
        "algorithm_family": "RSA",
        "parameter_set": "2048",
        "curve": None,
        "mode": None,
        "padding": "PKCS1v15",
        "oid": "1.2.840.113549.1.1.1",
        "finding_class": FindingClass.QUANTUM_VULNERABLE,
        "migration_authority": MigrationAuthority.SELF,
        "authority_basis": "locus is in the operator's own repo",
        "occurrences": (_occurrence(),),
        "concluded_from": ConfidenceTier.ARTEFACT,
        "disputed": False,
        "disputes": (),
    }
    defaults.update(overrides)
    return CryptoAsset(**defaults)  # type: ignore[arg-type]


def test_crypto_asset_requires_at_least_one_occurrence() -> None:
    with pytest.raises(ValueError, match="occurrence"):
        _asset(occurrences=())


def test_crypto_asset_disputed_requires_a_dispute() -> None:
    with pytest.raises(ValueError, match="Dispute"):
        _asset(disputed=True, disputes=())


def test_crypto_asset_disputed_with_a_dispute_is_valid() -> None:
    dispute = Dispute(
        attribute="padding",
        claims=(
            AttributeClaim(
                value="OAEP",
                source_collector="source_scan.cdxgen",
                confidence=ConfidenceTier.AST,
                locus=FileLocus(path="src/Main.java", offset=42),
            ),
            AttributeClaim(
                value="PKCS1v15",
                source_collector="source_scan.opengrep",
                confidence=ConfidenceTier.PATTERN,
                locus=FileLocus(path="src/Main.java", offset=42),
            ),
        ),
    )
    asset = _asset(disputed=True, disputes=(dispute,))
    assert asset.disputed
    assert not dispute.resolved


# --- System validation (ARCH.md §4: criticality 1..5) ---


def _system(**overrides: object) -> System:
    defaults: dict[str, object] = {
        "id": "sys-1",
        "name": "payments-api",
        "owner": "platform-team",
        "criticality": 5,
        "data_classification": DataClass.CONFIDENTIAL,
        "retention_years": 7.0,
        "retention_inferred": False,
        "internet_facing": True,
        "regulatory_regimes": frozenset({"sebi-re"}),
        "depends_on": frozenset(),
    }
    defaults.update(overrides)
    return System(**defaults)  # type: ignore[arg-type]


@pytest.mark.parametrize("criticality", [0, 6, -1])
def test_system_rejects_out_of_range_criticality(criticality: int) -> None:
    with pytest.raises(ValueError, match="criticality"):
        _system(criticality=criticality)


@pytest.mark.parametrize("criticality", [1, 2, 3, 4, 5])
def test_system_accepts_valid_criticality(criticality: int) -> None:
    assert _system(criticality=criticality).criticality == criticality


def test_system_rejects_negative_retention() -> None:
    with pytest.raises(ValueError, match="retention_years"):
        _system(retention_years=-1.0)


# --- HostLocus resolves OQ-09: identity is the agent's, not a typed string ---


def test_host_locus_carries_agent_identity_not_a_bare_hostname() -> None:
    locus = HostLocus(host_identity="agent-7f3c9e", path="/etc/pki/tls/certs/x.pem", offset=0)
    assert locus.host_identity == "agent-7f3c9e"
