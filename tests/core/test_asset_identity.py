"""T-020 — asset_identity() (ARCH.md §6.1)."""

from __future__ import annotations

import pytest
from qavach_core.model.enums import AssetType
from qavach_core.model.identity import IdentityKind
from qavach_core.reconcile.identity import IdentityClaim, asset_identity


def test_end_entity_certificate_identity_is_its_own_fingerprint() -> None:
    claim = IdentityClaim(asset_type=AssetType.CERTIFICATE, sha256_fingerprint="abc123")
    identity = asset_identity(claim)
    assert identity.kind == IdentityKind.CERT
    assert identity.key == "abc123"


def test_two_certificates_with_different_fingerprints_are_different_assets() -> None:
    """Certificates are instances, not classes (ARCH.md §6.1) — merging
    them destroys the inventory."""
    a = asset_identity(IdentityClaim(asset_type=AssetType.CERTIFICATE, sha256_fingerprint="aaa"))
    b = asset_identity(IdentityClaim(asset_type=AssetType.CERTIFICATE, sha256_fingerprint="bbb"))
    assert a != b


def test_ca_identity_is_its_spki_hash_not_its_fingerprint() -> None:
    """A-7, resolves OQ-03: a CA reissued with the same key is the same
    risk asset — identity is the SPKI hash, not the per-certificate
    fingerprint."""
    claim = IdentityClaim(
        asset_type=AssetType.CERTIFICATE,
        is_ca=True,
        spki_sha256="spki-deadbeef",
        sha256_fingerprint="this-changes-every-reissue",
    )
    identity = asset_identity(claim)
    assert identity.kind == IdentityKind.CA_KEY
    assert identity.key == "spki-deadbeef"


def test_ca_reissued_with_same_key_is_the_same_identity() -> None:
    reissue_1 = IdentityClaim(
        asset_type=AssetType.CERTIFICATE,
        is_ca=True,
        spki_sha256="spki-deadbeef",
        sha256_fingerprint="fingerprint-2024",
    )
    reissue_2 = IdentityClaim(
        asset_type=AssetType.CERTIFICATE,
        is_ca=True,
        spki_sha256="spki-deadbeef",
        sha256_fingerprint="fingerprint-2026",
    )
    assert asset_identity(reissue_1) == asset_identity(reissue_2)


def test_rekeyed_ca_is_a_new_identity() -> None:
    original = IdentityClaim(asset_type=AssetType.CERTIFICATE, is_ca=True, spki_sha256="spki-old")
    rekeyed = IdentityClaim(asset_type=AssetType.CERTIFICATE, is_ca=True, spki_sha256="spki-new")
    assert asset_identity(original) != asset_identity(rekeyed)


def test_certificate_without_fingerprint_or_ca_spki_raises() -> None:
    with pytest.raises(ValueError, match="sha256_fingerprint"):
        asset_identity(IdentityClaim(asset_type=AssetType.CERTIFICATE))


def test_related_material_identity_prefers_spki_over_material_ref() -> None:
    claim = IdentityClaim(
        asset_type=AssetType.RELATED_MATERIAL,
        spki_sha256="spki-key-hash",
        material_ref="keystore-alias-fallback",
    )
    identity = asset_identity(claim)
    assert identity.kind == IdentityKind.KEY
    assert identity.key == "spki-key-hash"


def test_related_material_falls_back_to_material_ref_without_spki() -> None:
    """A keystore alias plus locus is a weaker identity than SPKI hash —
    ARCH.md §6.1 explicitly allows this fallback."""
    claim = IdentityClaim(asset_type=AssetType.RELATED_MATERIAL, material_ref="alias:mykey")
    identity = asset_identity(claim)
    assert identity.kind == IdentityKind.KEY
    assert identity.key == "alias:mykey"


def test_related_material_without_either_raises() -> None:
    with pytest.raises(ValueError, match="spki_sha256 or material_ref"):
        asset_identity(IdentityClaim(asset_type=AssetType.RELATED_MATERIAL))


def test_algorithm_identity_is_a_hash_of_core_attributes() -> None:
    claim = IdentityClaim(
        asset_type=AssetType.ALGORITHM,
        algorithm_family="RSASSA-PKCS1",
        parameter_set="2048",
        oid="1.2.840.113549.1.1.1",
    )
    identity = asset_identity(claim)
    assert identity.kind == IdentityKind.ALGO
    assert len(identity.key) == 64  # sha256 hex digest


def test_same_algorithm_in_ten_files_is_one_identity() -> None:
    """ARCH.md §6.1: algorithms are classes — same algorithm in ten files
    is one asset with ten occurrences, not ten assets."""
    make = lambda: IdentityClaim(  # noqa: E731
        asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="256"
    )
    identities = [asset_identity(make()) for _ in range(10)]
    assert len({i.key for i in identities}) == 1


def test_different_parameter_sets_are_different_algorithm_identities() -> None:
    aes_128 = asset_identity(
        IdentityClaim(asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="128")
    )
    aes_256 = asset_identity(
        IdentityClaim(asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="256")
    )
    assert aes_128 != aes_256


def test_mode_and_padding_are_not_part_of_algorithm_identity() -> None:
    """A-5: mode/padding are usage qualifiers, deliberately left out of the
    identity hash — IdentityClaim doesn't even have fields for them, which
    is itself the enforcement mechanism (the merge engine, T-022, handles
    mode/padding as per-occurrence usage data, not identity)."""
    assert not hasattr(IdentityClaim(asset_type=AssetType.ALGORITHM), "mode")
    assert not hasattr(IdentityClaim(asset_type=AssetType.ALGORITHM), "padding")


def test_protocol_uses_class_identity_like_algorithm() -> None:
    """ARCH.md §6.1: 'Algorithms AND protocols are classes.'"""
    claim = IdentityClaim(
        asset_type=AssetType.PROTOCOL, algorithm_family="TLS", parameter_set="1.3"
    )
    identity = asset_identity(claim)
    assert identity.kind == IdentityKind.ALGO


def test_identity_hash_is_deterministic_across_calls() -> None:
    """NFR-09: reproducible across runs and machines."""
    claim = IdentityClaim(
        asset_type=AssetType.ALGORITHM,
        algorithm_family="ML-KEM",
        parameter_set="768",
        oid="2.16.840.1.101.3.4.4.2",
    )
    assert asset_identity(claim) == asset_identity(claim)
