"""T-024 — the recorded corpus: real output from cdxgen, cbomkit-lib,
Opengrep and Syft over one target, replayed through each collector's parser
and reconciled. These expectations were read off real output, not designed;
when a tool's behaviour changes, re-record and review the diff."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from qavach_collectors import RawClaim, RunContext, Target, TargetType
from qavach_collectors.sbom import CryptoLibraryMapping
from qavach_collectors.sbom import syft as syft_mod
from qavach_collectors.sbom.syft import SyftCollector
from qavach_collectors.source_scan import (
    CbomkitCollector,
    CdxgenCollector,
    OpengrepCollector,
    load_rules,
)
from qavach_collectors.source_scan import cbomkit as cbomkit_mod
from qavach_collectors.source_scan import cdxgen as cdxgen_mod
from qavach_collectors.source_scan import opengrep as opengrep_mod
from qavach_core.model.enums import AssetType
from qavach_core.normalize import AliasTable, CryptographyRegistry, resolve_algorithm
from qavach_core.normalize.resolve import RawAlgorithmClaim, ResolvedAlgorithm
from qavach_core.reconcile import IdentityClaim, OccurrenceClaim, asset_identity, merge_all
from qavach_sandbox import SandboxResult

ROOT = Path(__file__).parent.parent.parent
CORPUS = ROOT / "tests/fixtures/scanner-output"
IMAGE = "sha256:" + "a" * 64

REGISTRY = CryptographyRegistry.from_dict(
    json.loads((ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text())
)
ALIASES = AliasTable.from_dict(yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text()))
LIBRARIES = CryptoLibraryMapping.from_entries(
    yaml.safe_load((ROOT / "config/knowledge/crypto_libraries.yaml").read_text())["libraries"]
)
RULES = load_rules(yaml.safe_load((ROOT / "config/opengrep-rules/crypto.yaml").read_text()))
TARGET = Target(type=TargetType.REPOSITORY, ref="/repo")


def _replay(
    mp: pytest.MonkeyPatch, module: ModuleType, collector: Any, filename: str
) -> list[RawClaim]:
    recorded = (CORPUS / filename).read_bytes()
    mp.setattr(module, "run_sandboxed", lambda config: SandboxResult(0, recorded, b"", 1.0, False))
    result = collector.collect(TARGET, RunContext(scan_run_id="r"))
    assert not result.partial, result.errors
    return list(result.claims)


@pytest.fixture(scope="module")
def claims() -> Iterator[dict[str, list[RawClaim]]]:
    mp = pytest.MonkeyPatch()  # undone below, so no other test sees the replay
    try:
        yield {
            "cdxgen": _replay(
                mp,
                cdxgen_mod,
                CdxgenCollector(registry=REGISTRY, aliases=ALIASES),
                "cdxgen/polyglot.cdx.json",
            ),
            "cbomkit": _replay(
                mp,
                cbomkit_mod,
                CbomkitCollector(registry=REGISTRY, aliases=ALIASES, image_ref=IMAGE),
                "cbomkit/polyglot.cdx.json",
            ),
            "opengrep": _replay(
                mp,
                opengrep_mod,
                OpengrepCollector(rules=RULES, image_ref=IMAGE),
                "opengrep/polyglot.sarif",
            ),
            "syft": _replay(
                mp,
                syft_mod,
                SyftCollector(crypto_libraries=LIBRARIES),
                "syft/polyglot.syft.json",
            ),
        }
    finally:
        mp.undo()


def _summary(claims: list[RawClaim]) -> set[tuple[object, ...]]:
    return {
        (c.name, c.locus.path, c.locus.offset, c.parameter_set, c.mode)  # type: ignore[union-attr]
        for c in claims
    }


def test_cbomkit_reports_exact_call_sites_with_scan_root_relative_paths(
    claims: dict[str, list[RawClaim]],
) -> None:
    assert _summary(claims["cbomkit"]) == {
        ("AES", "app.py", 6, "128", "cbc"),
        ("SHA-2", "app.py", 11, "256", None),
        ("DES", "src/main/java/Legacy.java", 6, "56", "ecb"),
        ("MD5", "src/main/java/Legacy.java", 7, "128", None),
    }
    assert {c.confidence.name for c in claims["cbomkit"]} == {"AST"}


def test_opengrep_covers_the_five_languages_cbomkit_cannot(
    claims: dict[str, list[RawClaim]],
) -> None:
    files = {c.locus.path for c in claims["opengrep"]}  # type: ignore[union-attr]
    assert files == {"Hasher.cs", "cipher.rb", "keys.rs", "legacy.c", "legacy.php"}
    assert {c.confidence.name for c in claims["opengrep"]} == {"PATTERN"}


def test_cdxgen_finds_crypto_assets_but_no_call_site_locations(
    claims: dict[str, list[RawClaim]],
) -> None:
    """Real behaviour: cdxgen names the algorithms present but supplies no
    `evidence.occurrences`, so every claim falls back to the repo-root locus."""
    assert {c.name for c in claims["cdxgen"]} == {
        "AES",
        "DES",
        "MD5",
        "RC4",
        "RSASSA-PKCS1",
        "SHA-1",
        "SHA-2",
    }
    assert {c.locus.path for c in claims["cdxgen"]} == {"/repo"}  # type: ignore[union-attr]


def test_syft_contributes_dependency_capability_only(claims: dict[str, list[RawClaim]]) -> None:
    assert claims["syft"] and {c.confidence.name for c in claims["syft"]} == {"DEPENDENCY"}
    assert all(c.parameter_set is None for c in claims["syft"])


def test_no_tool_leaks_a_container_or_prefixed_path(claims: dict[str, list[RawClaim]]) -> None:
    """Corroboration across tools needs the same file to be the same locus."""
    for tool in ("cbomkit", "opengrep"):
        for c in claims[tool]:
            path = c.locus.path  # type: ignore[union-attr]
            assert not path.startswith(("/", "target/")), (tool, path)


def _resolve(c: RawClaim) -> ResolvedAlgorithm | None:
    r = resolve_algorithm(
        RawAlgorithmClaim(
            name=c.name, oid=c.oid, primitive=c.primitive, parameter_set=c.parameter_set
        ),
        registry=REGISTRY,
        aliases=ALIASES,
    )
    return r if isinstance(r, ResolvedAlgorithm) else None


def test_every_recorded_claim_resolves_none_falls_to_unknown(
    claims: dict[str, list[RawClaim]],
) -> None:
    """Regression for the recording itself: cdxgen's lower-case `aes`/`rsa`/
    `sha-256` and cbomkit's `DES-56-ECB` used to resolve to UNKNOWN."""
    unresolved = [(t, c.name) for t, cs in claims.items() for c in cs if _resolve(c) is None]
    assert unresolved == []


def _merged(claims: dict[str, list[RawClaim]]):  # type: ignore[no-untyped-def]
    occurrences = []
    for tool, tool_claims in claims.items():
        for c in tool_claims:
            r = _resolve(c)
            assert r is not None
            identity = asset_identity(
                IdentityClaim(
                    asset_type=AssetType.ALGORITHM,
                    algorithm_family=r.algorithm_family,
                    parameter_set=r.parameter_set,
                    primitive=r.primitive,
                    oid=r.oid,
                )
            )
            occurrences.append(
                (
                    r,
                    OccurrenceClaim(
                        identity=identity,
                        locus=c.locus,
                        collector=tool,
                        tool_version="1",
                        confidence=c.confidence,
                        detection_method=c.detection_method,
                        raw_ref="r",
                        observed_at=datetime(2026, 9, 19, tzinfo=UTC),
                        mode=c.mode,
                        padding=c.padding,
                    ),
                )
            )
    return occurrences, merge_all([o for _, o in occurrences])


def test_reconciliation_conserves_every_claim_and_invents_no_dispute(
    claims: dict[str, list[RawClaim]],
) -> None:
    occurrences, merged = _merged(claims)
    total = sum(len(v) for v in claims.values())
    assert sum(len(m.occurrences) for m in merged) == total  # I4: nothing dropped
    assert not any(m.disputed for m in merged)


@pytest.mark.xfail(
    strict=True,
    reason="OQ-18: ARCH.md 6.1 hashes the raw OID and primitive into asset identity, and the "
    "tools disagree on both (cdxgen labels SHA-1 with a Novell OID), so the same algorithm "
    "fragments into several assets.",
)
def test_the_same_algorithm_from_different_tools_is_one_asset(
    claims: dict[str, list[RawClaim]],
) -> None:
    occurrences, merged = _merged(claims)
    md5 = [
        m
        for m in merged
        if any(r.algorithm_family == "MD5" for r, o in occurrences if o.identity == m.identity)
    ]
    assert len(md5) == 1
