"""T-014 — CycloneDX 1.4-1.7 version normalisation, and Phase 1's exit
criterion directly: a hand-written CycloneDX 1.7 CBOM and a
differently-shaped 1.7 CBOM (simulating what a tool that hasn't adopted
every 1.7 field yet would emit — TASK.md's "cdxgen 1.7 CBOM" criterion;
a *real* cdxgen-generated fixture is T-024's job in Phase 2, not
reproduced here since running the actual 15.5GB cdxgen image is collector
integration-test territory, not this layer's unit tests) both normalise
into an identical resolved result for the same underlying algorithm.

Both hand-written documents are validated against the real vendored
schema (T-011) before being normalised, so this test can't pass against a
document that isn't actually valid CycloneDX 1.7.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator
from qavach_core.model.enums import AssetType
from qavach_core.normalize import (
    AliasTable,
    CryptographyRegistry,
    ResolvedAlgorithm,
    ResolvedCurve,
    normalise_bom,
)
from referencing import Registry, Resource

ROOT = Path(__file__).parent.parent.parent
REGISTRY_DIR = ROOT / "config" / "knowledge" / "cdx-crypto-registry"
ALIASES_YAML = ROOT / "config" / "knowledge" / "aliases.yaml"


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    return CryptographyRegistry.from_dict(
        json.loads((REGISTRY_DIR / "cryptography-defs.json").read_text())
    )


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(yaml.safe_load(ALIASES_YAML.read_text()))


@pytest.fixture(scope="module")
def schema_validator() -> Draft7Validator:
    resources = [
        (p.name, Resource.from_contents(json.loads(p.read_text())))
        for p in REGISTRY_DIR.glob("*.schema.json")
    ]
    bom_schema = json.loads((REGISTRY_DIR / "bom-1.7.schema.json").read_text())
    return Draft7Validator(bom_schema, registry=Registry().with_resources(resources))


# --- Two differently-shaped 1.7 documents for the SAME algorithm ---

HAND_WRITTEN_1_7 = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/rsa-2048-handwritten",
            "name": "RSA-2048",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "algorithmFamily": "RSASSA-PKCS1",
                    "parameterSetIdentifier": "2048",
                },
                "oid": "1.2.840.113549.1.1.1",
            },
            "evidence": {
                "occurrences": [{"location": "src/main/java/Auth.java"}],
                "identity": [
                    {
                        "field": "name",
                        "confidence": 0.9,
                        "methods": [{"technique": "source-code-analysis", "confidence": 0.9}],
                    }
                ],
            },
        }
    ],
}

# Simulates a tool shaped closer to a real generator's output style: no
# algorithmFamily field populated (some tools only emit `name`), the
# deprecated `curve` field instead of `ellipticCurve`, and the deprecated
# single-object `identity` form (pre-1.6-style, still schema-valid via the
# `oneOf` in 1.7) — same underlying algorithm as above, described
# differently, and via a *different* claim (ECDSA + curve, to also
# exercise curve resolution end-to-end).
TOOL_STYLE_1_7 = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "version": 1,
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "crypto/ecdsa-p256-tool",
            "name": "ECDSA",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "curve": "secp256r1",  # deprecated field, not ellipticCurve
                },
            },
            "evidence": {
                "occurrences": [{"location": "src/Main.go"}],
                "identity": {  # deprecated single-object form, not an array
                    "field": "name",
                    "confidence": 0.7,
                    "methods": [{"technique": "ast-fingerprint", "confidence": 0.7}],
                },
            },
        }
    ],
}


@pytest.mark.parametrize(
    "document", [HAND_WRITTEN_1_7, TOOL_STYLE_1_7], ids=["hand_written", "tool_style"]
)
def test_fixtures_are_actually_valid_cyclonedx_1_7(
    document: dict, schema_validator: Draft7Validator
) -> None:
    errors = list(schema_validator.iter_errors(document))
    assert not errors, [e.message for e in errors]


def test_hand_written_rsa_resolves_correctly(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    claims = normalise_bom(HAND_WRITTEN_1_7, registry=registry, aliases=aliases)
    assert len(claims) == 1
    claim = claims[0]
    assert claim.asset_type is AssetType.ALGORITHM
    assert isinstance(claim.resolved_algorithm, ResolvedAlgorithm)
    assert claim.resolved_algorithm.algorithm_family == "RSASSA-PKCS1"
    assert claim.resolved_algorithm.parameter_set == "2048"


def test_tool_style_ecdsa_resolves_curve_via_deprecated_field(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    """Proves the deprecated `curve` field (not `ellipticCurve`) is still
    read — a 1.6-vintage tool that hasn't adopted the new field name must
    not silently lose its curve information."""
    claims = normalise_bom(TOOL_STYLE_1_7, registry=registry, aliases=aliases)
    assert len(claims) == 1
    claim = claims[0]
    assert isinstance(claim.resolved_algorithm, ResolvedAlgorithm)
    assert claim.resolved_algorithm.algorithm_family == "ECDSA"
    assert isinstance(claim.resolved_curve, ResolvedCurve)
    assert claim.resolved_curve.canonical == "1.2.840.10045.3.1.7"  # P-256's OID


def test_evidence_occurrences_preserved_verbatim(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    claims = normalise_bom(HAND_WRITTEN_1_7, registry=registry, aliases=aliases)
    assert claims[0].evidence_occurrences == ({"location": "src/main/java/Auth.java"},)


@pytest.mark.parametrize(
    ("document", "expected_technique"),
    [
        (HAND_WRITTEN_1_7, "source-code-analysis"),  # array form (1.6+)
        (TOOL_STYLE_1_7, "ast-fingerprint"),  # deprecated single-object form
    ],
    ids=["array_form", "single_object_form"],
)
def test_evidence_identity_normalised_to_array_regardless_of_source_form(
    document: dict, expected_technique: str, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    """T-014's core version-compatibility job: `evidence.identity` can be a
    single object (deprecated, pre-1.6) or an array (1.6+) in the source
    document — callers must always see a tuple, never have to branch."""
    claims = normalise_bom(document, registry=registry, aliases=aliases)
    identity = claims[0].evidence_identity
    assert isinstance(identity, tuple)
    assert len(identity) == 1
    assert identity[0]["methods"][0]["technique"] == expected_technique


def test_bom_ref_preserved(registry: CryptographyRegistry, aliases: AliasTable) -> None:
    claims = normalise_bom(HAND_WRITTEN_1_7, registry=registry, aliases=aliases)
    assert claims[0].bom_ref == "crypto/rsa-2048-handwritten"


def test_non_cryptographic_asset_components_are_skipped(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {"type": "library", "name": "some-lib"},
            HAND_WRITTEN_1_7["components"][0],
        ],
    }
    claims = normalise_bom(document, registry=registry, aliases=aliases)
    assert len(claims) == 1


def test_non_algorithm_asset_types_pass_through_without_algorithm_resolution(
    registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto/some-cert",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {"subjectName": "CN=example.com"},
                },
            }
        ],
    }
    claims = normalise_bom(document, registry=registry, aliases=aliases)
    assert len(claims) == 1
    assert claims[0].asset_type is AssetType.CERTIFICATE
    assert claims[0].resolved_algorithm is None
    assert (
        claims[0].raw_crypto_properties["certificateProperties"]["subjectName"] == "CN=example.com"
    )


@pytest.mark.parametrize("bad_version", ["1.0", "2.0", None, "not-a-version"])
def test_unsupported_spec_version_raises(
    bad_version: str | None, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    document = {"bomFormat": "CycloneDX", "specVersion": bad_version, "components": []}
    with pytest.raises(ValueError, match="specVersion"):
        normalise_bom(document, registry=registry, aliases=aliases)


@pytest.mark.parametrize("version", ["1.4", "1.5", "1.6", "1.7"])
def test_every_supported_version_is_accepted(
    version: str, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    """ARCH.md §5.1: inputs arrive as 1.4-1.7. All four must be accepted —
    this doesn't test version-SPECIFIC schema quirks beyond what's already
    covered above, just that the version gate itself doesn't reject a
    supported version."""
    document = {"bomFormat": "CycloneDX", "specVersion": version, "components": []}
    assert normalise_bom(document, registry=registry, aliases=aliases) == []


@pytest.mark.parametrize("components", [None, []])
def test_null_or_empty_components_yields_no_claims(
    registry: CryptographyRegistry, aliases: AliasTable, components: object
) -> None:
    """Regression, found by real tool output (T-039): CBOMkit-theia emits
    `"components": null` when it finds nothing. A `.get("components", [])`
    default does not cover an explicit null, and every hand-written fixture
    had a list — so this only surfaced against the real scanner."""
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    assert normalise_bom(document, registry=registry, aliases=aliases) == []
