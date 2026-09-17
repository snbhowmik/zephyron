"""ARCH.md §5.2 — pure value objects over the vendored CycloneDX
Cryptography Registry (`config/knowledge/cdx-crypto-registry/
cryptography-defs.json`, T-011).

`CryptographyRegistry.from_dict()` takes an already-parsed dict — it never
opens a file itself. `packages/core` has zero I/O (CLAUDE.md §2); reading
`cryptography-defs.json` off disk is the caller's job (e.g. the worker
pipeline at startup), which then passes the parsed dict in here.

**Important, found verifying T-011:** the vendored registry has no OID for
algorithm *families* (RSA, ML-KEM, ...) — only for elliptic *curves*. OID
resolution for algorithm families (ARCH.md §5.2 step 1) comes from
`AliasTable` (`normalize/aliases.py`, T-013's data), not from this file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AlgorithmFamilyDef:
    """One `algorithms[]` entry from the vendored registry."""

    family: str
    primitives: frozenset[str]  # every distinct primitive across the family's variants


@dataclass(frozen=True, slots=True)
class CurveDef:
    """One deduplicated elliptic curve, keyed by OID where it has one.

    ARCH.md §5.2 (A-18): "canonicalise to the OID where one exists,
    otherwise to the registry token" — `canonical` is exactly that value:
    the OID string when present, else the curve's own registry name.
    """

    canonical: str
    oid: str | None
    names: frozenset[str]  # every spelling the registry itself cross-references


@dataclass(frozen=True, slots=True)
class CryptographyRegistry:
    families: Mapping[str, AlgorithmFamilyDef]
    curve_by_spelling: Mapping[str, CurveDef] = field(default_factory=dict)

    def family(self, name: str) -> AlgorithmFamilyDef | None:
        """Exact match only (ARCH.md §5.2 step 2) — no fuzzy matching,
        ever (§6.5). Case-sensitive: the registry's own family names are
        the authority for what "exact" means."""
        return self.families.get(name)

    def curve(self, spelling: str) -> CurveDef | None:
        return self.curve_by_spelling.get(spelling) or self.curve_by_spelling.get(spelling.lower())

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> CryptographyRegistry:
        families: dict[str, AlgorithmFamilyDef] = {}
        for entry in data.get("algorithms", []):
            family_name = entry["family"]
            primitives = frozenset(
                v["primitive"] for v in entry.get("variant", []) if v.get("primitive")
            )
            families[family_name] = AlgorithmFamilyDef(family=family_name, primitives=primitives)

        curve_by_spelling: dict[str, CurveDef] = {}
        curves_by_oid: dict[str, CurveDef] = {}
        for group in data.get("ellipticCurves", []):
            for curve in group.get("curves", []):
                oid = curve.get("oid")
                spellings = {curve["name"]} | {a["name"] for a in curve.get("aliases", [])}
                if oid and oid in curves_by_oid:
                    # Same curve described again under a different grouping
                    # (e.g. P-256 appears under "nist", "secg" and "x962").
                    # Merge spellings into the first CurveDef seen for this
                    # OID rather than creating a second, competing entry.
                    existing = curves_by_oid[oid]
                    merged = CurveDef(
                        canonical=existing.canonical,
                        oid=oid,
                        names=existing.names | spellings,
                    )
                    curves_by_oid[oid] = merged
                    for spelling in merged.names:
                        curve_by_spelling[spelling] = merged
                        curve_by_spelling[spelling.lower()] = merged
                    curve_by_spelling[oid] = merged
                    continue

                canonical = oid if oid else curve["name"]
                curve_def = CurveDef(canonical=canonical, oid=oid, names=frozenset(spellings))
                if oid:
                    curve_by_spelling[oid] = curve_def
                    curves_by_oid[oid] = curve_def
                for spelling in spellings:
                    curve_by_spelling[spelling] = curve_def
                    curve_by_spelling[spelling.lower()] = curve_def

        return CryptographyRegistry(families=families, curve_by_spelling=curve_by_spelling)
