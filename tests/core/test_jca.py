"""Java compound algorithm names (normalize/jca.py) and the base aliases, measured
against real JCA names rather than hand-picked easy ones."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from qavach_core.model.enums import ConfidenceTier, FindingClass
from qavach_core.model.locus import FileLocus
from qavach_core.normalize.jca import decompose_jca
from qavach_core.normalize.resolve import RawAlgorithmClaim, ResolvedAlgorithm, resolve_algorithm
from qavach_core.pipeline import ClaimInput, assemble

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/demo.py")
assert _spec and _spec.loader
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)
K, _P, _Q = demo.load_knowledge()


def names_of(name: str) -> list[str]:
    parts = decompose_jca(name)
    assert parts is not None, name
    return [p.name for p in parts]


def test_signature_names_split_into_signature_and_digest() -> None:
    assert names_of("SHA256withRSA") == ["RSA", "SHA-256"]
    assert names_of("SHA1withDSA") == ["DSA", "SHA-1"]
    assert names_of("SHA384withECDSA") == ["ECDSA", "SHA-384"]
    assert names_of("SHA256withRSAandMGF1") == ["RSASSA-PSS", "SHA-256"]
    assert names_of("NONEwithRSA") == ["RSA"]  # no digest to report


def test_pbe_names_expose_the_weak_hash_and_the_weak_cipher() -> None:
    assert names_of("PBEWithMD5AndDES") == ["PBES1", "MD5", "DES"]
    assert names_of("PBEWithSHA1AndDESede") == ["PBES1", "SHA-1", "3DES"]
    assert names_of("PBEWithHmacSHA256AndAES_128") == ["PBES2", "SHA-256", "AES"]
    aes = decompose_jca("PBEWithHmacSHA256AndAES_128")[2]  # type: ignore[index]
    assert aes.parameter_set == "128"
    rc2 = decompose_jca("PBEWithSHA1AndRC2_40")[2]  # type: ignore[index]
    assert (rc2.name, rc2.parameter_set) == ("RC2", "40")


def test_hmac_and_pbkdf2_names() -> None:
    assert names_of("HmacSHA256") == ["HMAC", "SHA-256"]
    assert names_of("HmacSHA512/256") == ["HMAC", "SHA-512/256"]
    assert names_of("PBKDF2WithHmacSHA1") == ["PBKDF2", "HMAC", "SHA-1"]


def test_transformations_keep_their_mode_and_padding() -> None:
    [aes] = decompose_jca("AES/ECB/PKCS5Padding")  # type: ignore[misc]
    assert (aes.name, aes.mode, aes.padding) == ("AES", "ECB", "PKCS5Padding")
    [aes128] = decompose_jca("AES_128/CBC/NoPadding")  # type: ignore[misc]
    assert aes128.parameter_set == "128"
    assert names_of("RSA/ECB/OAEPWithSHA-256AndMGF1Padding") == ["RSAES-OAEP", "SHA-256"]
    assert names_of("RSA/ECB/PKCS1Padding") == ["RSAES-PKCS1"]


@pytest.mark.parametrize(
    "name",
    ["Ed25519", "DH", "DESede", "SHA1", "X25519", "ARCFOUR", "SHA-512/256", "TripleDES", "XDH"],
)
def test_the_simple_jca_names_the_spec_defines_now_resolve(name: str) -> None:
    r = resolve_algorithm(
        RawAlgorithmClaim(name=name, oid=None), registry=K.registry, aliases=K.aliases
    )
    assert isinstance(r, ResolvedAlgorithm), name


@pytest.mark.parametrize("name", ["", "WithoutTheKeyword", "FooWithBar", "PBEWithNothing", "A/B/C"])
def test_a_name_outside_the_grammar_is_left_alone_not_guessed(name: str) -> None:
    assert decompose_jca(name) is None


def claim(name: str) -> ClaimInput:
    return ClaimInput(
        name=name,
        locus=FileLocus(path="A.java", offset=1),
        collector="c",
        tool_version="1",
        confidence=ConfidenceTier.AST,
        detection_method="ast",
        raw_ref="r",
        observed_at=demo.NOW,
    )


def test_pbewithmd5anddes_becomes_two_classical_weak_findings_not_one_unknown() -> None:
    result = assemble([claim("PBEWithMD5AndDES")], K)
    by_family = {a.algorithm_family: a.finding_class for a in result.assets}
    assert by_family["MD5"] is FindingClass.CLASSICAL_WEAK
    assert by_family["DES"] is FindingClass.CLASSICAL_WEAK
    assert result.expanded_claims == 2  # one claim became three
    # every component keeps the original locus (nothing dropped, I4)
    assert all(a.occurrences[0].locus == FileLocus(path="A.java", offset=1) for a in result.assets)


def test_sha256withrsa_is_a_quantum_vulnerable_signature_plus_a_grover_hash() -> None:
    by_family = {
        a.algorithm_family: a.finding_class for a in assemble([claim("SHA256withRSA")], K).assets
    }
    assert by_family["RSASSA-PKCS1"] is FindingClass.QUANTUM_VULNERABLE
    assert by_family["SHA-2"] is FindingClass.GROVER_AFFECTED  # informational (I1)


def test_aes_ecb_keeps_its_mode_through_the_assembler() -> None:
    [asset] = assemble([claim("AES/ECB/PKCS5Padding")], K).assets
    assert asset.mode is not None and asset.mode.lower() == "ecb"


def test_measured_coverage_of_61_common_jca_names() -> None:
    """The measurement that motivated this: 38 of these 61 did not resolve before."""
    names = (
        "SHA256withRSA SHA1withRSA SHA1withDSA SHA256withECDSA SHA384withECDSA SHA512withRSA "
        "MD5withRSA NONEwithRSA SHA256withRSAandMGF1 RSASSA-PSS Ed25519 Ed448 EdDSA "
        "PBEWithMD5AndDES PBEWithSHA1AndDESede PBEWithSHA1AndRC2_40 PBEWithHmacSHA256AndAES_128 "
        "PBEWithHmacSHA1AndAES_256 PBKDF2WithHmacSHA1 PBKDF2WithHmacSHA256 PBKDF2WithHmacSHA512 "
        "HmacSHA256 HmacSHA1 HmacMD5 HmacSHA512 HmacSHA384 AES/CBC/PKCS5Padding AES/GCM/NoPadding "
        "AES/ECB/PKCS5Padding DES/CBC/PKCS5Padding DESede/CBC/PKCS5Padding RSA/ECB/PKCS1Padding "
        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding AES_128/CBC/NoPadding ChaCha20-Poly1305 RC4 ARCFOUR "
        "Blowfish SHA-256 SHA256 SHA-1 SHA1 SHA-512 SHA-384 MD5 MD2 SHA3-256 SHA-512/256 DH ECDH "
        "DiffieHellman X25519 XDH EC RSA DSA AES DES DESede TripleDES 3DES"
    ).split()
    result = assemble([claim(n) for n in names], K)
    assert result.unresolved == (), f"still unresolved: {result.unresolved}"
