"""T-015c, A-18 — curve canonicalisation before identity hashing.
`secp256r1` = `prime256v1` = `P-256` = `NIST P-256` = the OID must all
collapse to one identity; this extends that single ARCH.md example into a
broader corpus over curves QAVACH actually expects to see (NIST P-curves,
secp256k1, Curve25519/448), using the real vendored registry + aliases.yaml.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from qavach_core.normalize import AliasTable, CryptographyRegistry, ResolvedCurve, resolve_curve

ROOT = Path(__file__).parent.parent.parent
ALIASES_YAML = ROOT / "config" / "knowledge" / "aliases.yaml"
REGISTRY_JSON = ROOT / "config" / "knowledge" / "cdx-crypto-registry" / "cryptography-defs.json"


@pytest.fixture(scope="module")
def registry() -> CryptographyRegistry:
    return CryptographyRegistry.from_dict(json.loads(REGISTRY_JSON.read_text()))


@pytest.fixture(scope="module")
def aliases() -> AliasTable:
    return AliasTable.from_dict(yaml.safe_load(ALIASES_YAML.read_text()))


# Each group: every spelling in the tuple must canonicalise identically.
# Sourced directly from the vendored registry's own cross-referenced
# aliases (ARCH.md §8.5's curve-name canonicalisation gap) — not invented.
CURVE_ALIAS_GROUPS = [
    ("secp256r1", "prime256v1", "P-256", "1.2.840.10045.3.1.7"),
    ("secp384r1", "ansip384r1", "P-384", "1.3.132.0.34"),
    ("secp521r1", "ansip521r1", "P-521", "1.3.132.0.35"),
    ("secp192r1", "prime192v1", "P-192", "1.2.840.10045.3.1.1"),
    ("secp224r1", "ansip224r1", "P-224", "1.3.132.0.33"),
    ("ansip256k1", "secp256k1", "1.3.132.0.10"),
]


@pytest.mark.parametrize("group", CURVE_ALIAS_GROUPS, ids=lambda g: g[0])
def test_curve_alias_group_collapses_to_one_identity(
    group: tuple[str, ...], registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    results = [resolve_curve(spelling, registry=registry, aliases=aliases) for spelling in group]
    for spelling, result in zip(group, results, strict=True):
        assert isinstance(result, ResolvedCurve), f"{spelling!r} did not resolve: {result!r}"
    canonicals = {r.canonical for r in results if isinstance(r, ResolvedCurve)}
    assert len(canonicals) == 1, f"{group} did not collapse to one identity: {canonicals}"
    # The canonical value is the OID itself (ARCH.md §5.2 A-18), the last
    # element of every group above.
    assert canonicals == {group[-1]}


@pytest.mark.parametrize(
    ("spelling", "expected_canonical"),
    [
        ("X25519", "Curve25519"),
        ("x25519", "Curve25519"),
        ("curve25519", "Curve25519"),
        ("X448", "Curve448"),
        ("x448", "Curve448"),
    ],
)
def test_curve_alias_overlay_covers_gaps_the_registry_itself_does_not(
    spelling: str, expected_canonical: str, registry: CryptographyRegistry, aliases: AliasTable
) -> None:
    """The vendored registry lists Curve25519 and Curve448 but does not
    cross-reference X25519/X448 as aliases of them the way it does for
    P-256/secp256r1/prime256v1 — found while building T-013. Without
    aliases.yaml's `curves:` overlay, these would resolve differently and
    the same key would land under two identities."""
    result = resolve_curve(spelling, registry=registry, aliases=aliases)
    assert isinstance(result, ResolvedCurve)
    assert result.canonical == expected_canonical


def test_resolving_without_the_alias_overlay_would_have_failed_for_x25519(
    registry: CryptographyRegistry,
) -> None:
    """Proves the previous test's claim rather than asserting it — without
    `aliases=`, X25519 genuinely does not resolve against the bare
    registry. This is the regression the overlay exists to prevent."""
    from qavach_core.normalize import UnresolvedCurve

    result = resolve_curve("X25519", registry=registry)  # no aliases passed
    assert isinstance(result, UnresolvedCurve)
