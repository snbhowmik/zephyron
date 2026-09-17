"""T-016 — CDX primitive -> CryptoFunction mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from qavach_core.model.enums import CryptoFunction
from qavach_core.normalize.function import classify_function

REGISTRY_JSON = (
    Path(__file__).parent.parent.parent
    / "config"
    / "knowledge"
    / "cdx-crypto-registry"
    / "cryptography-defs.json"
)


@pytest.mark.parametrize(
    ("primitive", "expected"),
    [
        ("kem", CryptoFunction.KEY_ENCAPSULATION),
        ("key-agree", CryptoFunction.KEY_AGREEMENT),
        ("pke", CryptoFunction.ENCRYPTION),
        ("block-cipher", CryptoFunction.ENCRYPTION),
        ("ae", CryptoFunction.ENCRYPTION),
        ("stream-cipher", CryptoFunction.ENCRYPTION),
        ("key-wrap", CryptoFunction.ENCRYPTION),
        ("signature", CryptoFunction.SIGNATURE),
        ("mac", CryptoFunction.MAC),
        ("hash", CryptoFunction.HASH),
        ("xof", CryptoFunction.HASH),
        ("kdf", CryptoFunction.KDF),
        ("drbg", CryptoFunction.DRBG),
    ],
)
def test_classify_function(primitive: str, expected: CryptoFunction) -> None:
    assert classify_function(primitive) == expected


def test_none_in_none_out() -> None:
    assert classify_function(None) is None


def test_unmapped_primitive_returns_none_not_a_guess() -> None:
    assert classify_function("other") is None
    assert classify_function("something-cdx-adds-later-we-dont-know-yet") is None


def test_every_primitive_the_real_registry_actually_uses_is_covered_or_deliberately_unmapped() -> (
    None
):
    """Regression guard: if the vendored registry ever ships a primitive
    value this module doesn't know about, that should be a visible test
    failure prompting a deliberate mapping decision — not a silent None
    nobody notices until risk scoring quietly skips an asset."""
    data = json.loads(REGISTRY_JSON.read_text())
    primitives_in_registry = {
        v["primitive"]
        for a in data["algorithms"]
        for v in a.get("variant", [])
        if v.get("primitive")
    }
    deliberately_unmapped = {"other"}
    from qavach_core.normalize.function import _PRIMITIVE_TO_FUNCTION

    unknown = primitives_in_registry - set(_PRIMITIVE_TO_FUNCTION) - deliberately_unmapped
    assert not unknown, f"registry uses primitive(s) with no mapping decision: {unknown}"
