"""T-015 — the four finding classes (invariant I1), table-driven from the
real config/knowledge/classification_rules.yaml, not a synthetic fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from qavach_core.model.enums import FindingClass
from qavach_core.risk.classify import ClassificationRules, classify

RULES_YAML = (
    Path(__file__).parent.parent.parent / "config" / "knowledge" / "classification_rules.yaml"
)
REGISTRY_JSON = (
    Path(__file__).parent.parent.parent
    / "config"
    / "knowledge"
    / "cdx-crypto-registry"
    / "cryptography-defs.json"
)


@pytest.fixture(scope="module")
def rules() -> ClassificationRules:
    return ClassificationRules.from_dict(yaml.safe_load(RULES_YAML.read_text()))


# --- ARCH.md §7.1's own worked examples, exactly ---


def test_md5_is_classical_weak_unconditionally(rules: ClassificationRules) -> None:
    result = classify("MD5", None, rules=rules)
    assert result.finding_class == FindingClass.CLASSICAL_WEAK
    assert not result.also_quantum_vulnerable


def test_rsa_2048_is_quantum_vulnerable_only(rules: ClassificationRules) -> None:
    result = classify("RSASSA-PKCS1", "2048", rules=rules)
    assert result.finding_class == FindingClass.QUANTUM_VULNERABLE
    assert not result.also_quantum_vulnerable  # the flag is for the CLASSICAL_WEAK case only


def test_rsa_1024_is_classical_weak_and_also_quantum_vulnerable(rules: ClassificationRules) -> None:
    """ARCH.md §7.1's canonical example: RSA-1024 is BOTH. Classical wins
    as finding_class (the attack works today); also_quantum_vulnerable
    keeps it in the PQC programme's scope."""
    result = classify("RSASSA-PKCS1", "1024", rules=rules)
    assert result.finding_class == FindingClass.CLASSICAL_WEAK
    assert result.also_quantum_vulnerable


def test_ecdsa_is_quantum_vulnerable(rules: ClassificationRules) -> None:
    assert classify("ECDSA", "P-256", rules=rules).finding_class == FindingClass.QUANTUM_VULNERABLE


def test_aes_128_is_grover_affected_never_quantum_vulnerable(rules: ClassificationRules) -> None:
    """The single highest-value regression in the whole classifier —
    redlining AES-128 as "migrate immediately" is what CLAUDE.md §2 calls
    out as instantly destroying credibility with a domain reviewer."""
    result = classify("AES", "128", rules=rules)
    assert result.finding_class == FindingClass.GROVER_AFFECTED
    assert result.finding_class != FindingClass.QUANTUM_VULNERABLE


def test_aes_256_is_quantum_safe(rules: ClassificationRules) -> None:
    assert classify("AES", "256", rules=rules).finding_class == FindingClass.QUANTUM_SAFE


def test_ml_kem_is_quantum_safe(rules: ClassificationRules) -> None:
    assert classify("ML-KEM", "768", rules=rules).finding_class == FindingClass.QUANTUM_SAFE


def test_sha_256_is_grover_affected_informational_never_safe_and_never_migrate_now(
    rules: ClassificationRules,
) -> None:
    """CLAUDE.md invariant I1 names "SHA-256 in some uses" as GROVER_AFFECTED
    (informational). An earlier version of this test pinned it as UNKNOWN because
    ARCH.md 7.1's table omits it; recorded end-to-end on real scanner output
    (T-120), that reported the most common hash in existence as a coverage
    failure. A 256-bit hash keeps ~128-bit preimage strength against Grover - the
    same margin as AES-128 - so it gets the same informational class. It is NOT
    quantum-safe (that stays reserved for 384+), and never "migrate now"."""
    result = classify("SHA-2", "256", rules=rules)
    assert result.finding_class == FindingClass.GROVER_AFFECTED
    assert result.finding_class != FindingClass.QUANTUM_SAFE


def test_sha_256_with_no_parameter_is_still_unknown(rules: ClassificationRules) -> None:
    """The class depends on the width; with no width we cannot say (I8)."""
    assert classify("SHA-2", None, rules=rules).finding_class == FindingClass.UNKNOWN


def test_chacha20_is_quantum_safe_because_its_key_is_always_256_bits(
    rules: ClassificationRules,
) -> None:
    assert classify("ChaCha20", None, rules=rules).finding_class == FindingClass.QUANTUM_SAFE


def test_sha_384_and_512_are_quantum_safe(rules: ClassificationRules) -> None:
    assert classify("SHA-2", "384", rules=rules).finding_class == FindingClass.QUANTUM_SAFE
    assert classify("SHA-2", "512", rules=rules).finding_class == FindingClass.QUANTUM_SAFE


def test_sha3_any_size_is_quantum_safe(rules: ClassificationRules) -> None:
    for size in ("224", "256", "384", "512"):
        assert classify("SHA-3", size, rules=rules).finding_class == FindingClass.QUANTUM_SAFE


def test_unresolvable_family_is_unknown(rules: ClassificationRules) -> None:
    assert classify("TotallyMadeUpAlgorithm9000", None, rules=rules).finding_class == (
        FindingClass.UNKNOWN
    )


# --- T-015's required property test: no symmetric algorithm ever lands
# in QUANTUM_VULNERABLE, checked over every family the real vendored
# registry actually defines, not a hand-picked list. ---

_ASYMMETRIC_PRIMITIVES = {"kem", "signature", "pke", "key-agree"}


def _all_registry_families_by_primitive() -> dict[str, set[str]]:
    data = json.loads(REGISTRY_JSON.read_text())
    by_family: dict[str, set[str]] = {}
    for a in data["algorithms"]:
        primitives = {v["primitive"] for v in a.get("variant", []) if v.get("primitive")}
        by_family[a["family"]] = primitives
    return by_family


@pytest.mark.parametrize(
    "family",
    [
        f
        for f, primitives in _all_registry_families_by_primitive().items()
        if primitives and not (primitives & _ASYMMETRIC_PRIMITIVES)
    ],
)
def test_no_symmetric_algorithm_ever_classifies_quantum_vulnerable(
    family: str, rules: ClassificationRules
) -> None:
    """Every family in the real registry whose primitives are ALL
    symmetric (block-cipher/ae/stream-cipher/mac/hash/kdf/drbg/xof/
    key-wrap — i.e. none of kem/signature/pke/key-agree) must never
    classify QUANTUM_VULNERABLE, for any parameter_set at all."""
    for parameter_set in (None, "0", "128", "256", "9999"):
        result = classify(family, parameter_set, rules=rules)
        assert result.finding_class != FindingClass.QUANTUM_VULNERABLE, (
            f"{family} (symmetric) classified QUANTUM_VULNERABLE at parameter_set={parameter_set!r}"
        )
