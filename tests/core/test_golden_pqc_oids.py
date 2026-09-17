"""T-015b, A-19 — golden test. Every OID in the NIST ML-KEM/ML-DSA/SLH-DSA
arcs must resolve to a named parameter set and classify QUANTUM_SAFE,
never UNKNOWN (IDEATION.md §2.2a: a competitor's dashboard displays these
exact OIDs as raw dotted-decimal strings — a post-quantum tool that
cannot name the algorithms it recommends migrating *to* is not credible).

Every OID here was verified against a primary source before being added to
config/knowledge/aliases.yaml (see that file's header) — not hand-written
from memory, per ARCH.md A-19's explicit instruction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from qavach_core.model.enums import FindingClass
from qavach_core.normalize import (
    AliasTable,
    CryptographyRegistry,
    RawAlgorithmClaim,
    ResolvedAlgorithm,
    resolve_algorithm,
)
from qavach_core.risk.classify import ClassificationRules, classify

ROOT = Path(__file__).parent.parent.parent
ALIASES_YAML = ROOT / "config" / "knowledge" / "aliases.yaml"
RULES_YAML = ROOT / "config" / "knowledge" / "classification_rules.yaml"
REGISTRY_JSON = ROOT / "config" / "knowledge" / "cdx-crypto-registry" / "cryptography-defs.json"

# The full verified NIST PQC arc — every OID currently in aliases.yaml's
# `oids:` section under ML-KEM/ML-DSA/SLH-DSA. If aliases.yaml gains more
# PQC OIDs later, this list should grow with it (kept explicit, not
# derived from the file, so a golden test failure is legible on its own).
NIST_PQC_OIDS = [
    "2.16.840.1.101.3.4.4.1",  # ML-KEM-512
    "2.16.840.1.101.3.4.4.2",  # ML-KEM-768
    "2.16.840.1.101.3.4.4.3",  # ML-KEM-1024
    "2.16.840.1.101.3.4.3.17",  # ML-DSA-44
    "2.16.840.1.101.3.4.3.18",  # ML-DSA-65
    "2.16.840.1.101.3.4.3.19",  # ML-DSA-87
    "2.16.840.1.101.3.4.3.20",  # SLH-DSA-SHA2-128s
    "2.16.840.1.101.3.4.3.21",  # SLH-DSA-SHA2-128f
    "2.16.840.1.101.3.4.3.22",  # SLH-DSA-SHA2-192s
    "2.16.840.1.101.3.4.3.23",  # SLH-DSA-SHA2-192f
    "2.16.840.1.101.3.4.3.24",  # SLH-DSA-SHA2-256s
    "2.16.840.1.101.3.4.3.25",  # SLH-DSA-SHA2-256f
    "2.16.840.1.101.3.4.3.26",  # SLH-DSA-SHAKE-128s
    "2.16.840.1.101.3.4.3.27",  # SLH-DSA-SHAKE-128f
    "2.16.840.1.101.3.4.3.28",  # SLH-DSA-SHAKE-192s
    "2.16.840.1.101.3.4.3.29",  # SLH-DSA-SHAKE-192f
    "2.16.840.1.101.3.4.3.30",  # SLH-DSA-SHAKE-256s
    "2.16.840.1.101.3.4.3.31",  # SLH-DSA-SHAKE-256f
]


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    return CryptographyRegistry.from_dict(json.loads(REGISTRY_JSON.read_text()))


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(yaml.safe_load(ALIASES_YAML.read_text()))


@pytest.fixture(scope="module")
def rules() -> ClassificationRules:
    return ClassificationRules.from_dict(yaml.safe_load(RULES_YAML.read_text()))


@pytest.mark.parametrize("oid", NIST_PQC_OIDS)
def test_pqc_oid_resolves_to_a_named_parameter_set(
    oid: str, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    claim = RawAlgorithmClaim(name=None, oid=oid)
    result = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedAlgorithm), f"{oid} resolved to {result!r}, expected a name"
    assert result.parameter_set is not None
    assert result.algorithm_family in {"ML-KEM", "ML-DSA", "SLH-DSA"}


@pytest.mark.parametrize("oid", NIST_PQC_OIDS)
def test_pqc_oid_classifies_quantum_safe_never_unknown(
    oid: str,
    registry: CryptographyRegistry,
    aliases: AliasTable,
    rules: ClassificationRules,
) -> None:
    claim = RawAlgorithmClaim(name=None, oid=oid)
    resolved = resolve_algorithm(claim, registry=registry, aliases=aliases)
    assert isinstance(resolved, ResolvedAlgorithm)
    result = classify(resolved.algorithm_family, resolved.parameter_set, rules=rules)
    assert result.finding_class == FindingClass.QUANTUM_SAFE, (
        f"{oid} ({resolved.algorithm_family}-{resolved.parameter_set}) "
        f"classified {result.finding_class}, expected QUANTUM_SAFE"
    )
    assert result.finding_class != FindingClass.UNKNOWN
