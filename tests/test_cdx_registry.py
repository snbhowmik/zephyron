"""T-011 — the vendored CycloneDX 1.7 schema + Cryptography Registry must
actually work, fully offline. A vendored file set that silently needs the
network at validation time breaks invariant I7 (air-gap) in a way that
would not show up until someone tries it on a disconnected deployment.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

REGISTRY_DIR = Path(__file__).parent.parent / "config" / "knowledge" / "cdx-crypto-registry"
REQUIRED_FILES = {
    "bom-1.7.schema.json",
    "cryptography-defs.schema.json",
    "cryptography-defs.json",
    "jsf-0.82.schema.json",
    "spdx.schema.json",
}


def test_all_required_files_are_present() -> None:
    present = {p.name for p in REGISTRY_DIR.glob("*.json")}
    missing = REQUIRED_FILES - present
    assert not missing, f"config/knowledge/cdx-crypto-registry/ is missing: {missing}"


def test_all_files_are_valid_json() -> None:
    for name in REQUIRED_FILES:
        json.loads((REGISTRY_DIR / name).read_text())  # raises on malformed JSON


def test_cryptography_registry_contains_pqc_families() -> None:
    """Golden-test precursor for A-19/T-015b — if these aren't even in the
    vendored registry, the OID-resolution golden test can't pass."""
    data = json.loads((REGISTRY_DIR / "cryptography-defs.json").read_text())
    families = {a["family"] for a in data["algorithms"]}
    assert {"ML-KEM", "ML-DSA", "SLH-DSA"} <= families


@pytest.fixture
def _validator(monkeypatch: pytest.MonkeyPatch) -> Draft7Validator:
    """A Draft7Validator built entirely from local files, with the socket
    module replaced so any network attempt during validation raises
    instead of silently succeeding or silently failing offline."""

    def _no_network(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("network access attempted during schema validation")

    monkeypatch.setattr(socket, "socket", _no_network)

    resources = []
    for path in REGISTRY_DIR.glob("*.schema.json"):
        resources.append((path.name, Resource.from_contents(json.loads(path.read_text()))))
    registry = Registry().with_resources(resources)
    bom_schema = json.loads((REGISTRY_DIR / "bom-1.7.schema.json").read_text())
    return Draft7Validator(bom_schema, registry=registry)


def test_schema_validates_a_real_component_fully_offline(_validator: Draft7Validator) -> None:
    sample_bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "ML-KEM-768",
                "bom-ref": "crypto/ml-kem-768",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "kem",
                        "parameterSetIdentifier": "768",
                        "executionEnvironment": "software-plain-ram",
                        "implementationPlatform": "generic",
                    },
                    "oid": "2.16.840.1.101.3.4.4.2",
                },
            }
        ],
    }
    errors = list(_validator.iter_errors(sample_bom))
    assert not errors, [e.message for e in errors]


def test_schema_rejects_an_invalid_document(_validator: Draft7Validator) -> None:
    """A schema that accepts everything proves nothing — confirm it
    actually rejects a malformed document, not just that it accepts a
    valid one."""
    bad_bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": "not-an-int"}
    errors = list(_validator.iter_errors(bad_bom))
    assert errors


def test_bom_schema_declares_1_7_cryptography_refs() -> None:
    """Regression guard: if a future refresh vendors a bom schema that no
    longer references the cryptography-defs files, the other tests in this
    module would still pass (they'd just validate against a schema that
    silently stopped constraining crypto properties). Catch that directly."""
    raw = (REGISTRY_DIR / "bom-1.7.schema.json").read_text()
    assert "cryptography-defs.schema.json" in raw
