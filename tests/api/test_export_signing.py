"""T-097 - the real signers behind `qavach_core.export`'s detached-signature protocol."""

from __future__ import annotations

import base64
import json

import pytest
from qavach_api.export_signing import ED25519_LIMITATION, generate_signer, verify
from qavach_core.export import sign_export, verify_export

DATA = json.dumps(
    {"bomFormat": "CycloneDX", "components": list(range(50))}, sort_keys=True
).encode()


def test_an_ml_dsa_65_signature_verifies() -> None:
    signer = generate_signer()
    envelope = sign_export(DATA, signer, key_id="k1")
    assert envelope["algorithm"] == "ML-DSA-65" and envelope["standard"] == "FIPS 204"
    assert envelope["limitation"] is None
    assert verify_export(DATA, envelope, verify)


def test_the_ml_dsa_sizes_match_fips_204_and_performance_yaml() -> None:
    envelope = sign_export(DATA, generate_signer())
    assert len(base64.b64decode(envelope["signature"])) == 3309
    assert len(base64.b64decode(envelope["public_key"])) == 1952


def test_tampering_truncation_and_a_forged_public_key_fail() -> None:
    envelope = sign_export(DATA, generate_signer())
    assert not verify_export(DATA + b" ", envelope, verify)
    assert not verify_export(DATA[:-1], envelope, verify)
    other = sign_export(DATA, generate_signer())
    assert not verify_export(DATA, {**envelope, "public_key": other["public_key"]}, verify)


def test_the_ed25519_fallback_states_its_limitation_instead_of_downgrading_silently() -> None:
    envelope = sign_export(DATA, generate_signer(prefer="Ed25519"))
    assert envelope["algorithm"] == "Ed25519" and envelope["limitation"] == ED25519_LIMITATION
    assert "quantum-vulnerable" in envelope["limitation"]
    assert verify_export(DATA, envelope, verify)


@pytest.mark.parametrize("algorithm", ["ROT13", "", "ML-DSA-44"])
def test_an_unknown_algorithm_never_verifies(algorithm: str) -> None:
    assert verify(algorithm, b"\x00" * 32, b"\x00" * 64, b"m") is False


def test_a_malformed_public_key_or_signature_is_false_not_an_exception() -> None:
    assert verify("ML-DSA-65", b"short", b"short", b"m") is False
    assert verify("Ed25519", b"short", b"short", b"m") is False
