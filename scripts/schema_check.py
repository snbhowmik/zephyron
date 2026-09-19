"""T-091 / invariant I5 - `make schema-check`.

Builds a sample CBOM and Risk Register from a fixed asset set and fails if:

1. the CBOM does not validate against the official CycloneDX 1.7 schema
   (vendored, validated fully offline - a network attempt raises, I7);
2. the CBOM contains any risk data, any undocumented `qavach:` property, or a
   `purl` on a cryptographic-asset (`purity.cbom_violations`);
3. `docs/CUSTOM_PROPERTIES.md` and the exporter disagree about the documented
   `qavach:` property set, in either direction (T-098);
4. the Risk Register does not validate against `docs/schema/risk-register-1.0.json`;
5. the checks above would not actually catch what they claim to: each is run
   against a deliberately polluted copy and must reject it. A guard that has
   never been seen to fail is not a guard.

    uv run python scripts/schema_check.py
"""

from __future__ import annotations

import copy
import json
import re
import socket
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator, Draft202012Validator
from qavach_core.export import (
    DOCUMENTED_PROPERTIES,
    RegisterInput,
    build_cbom,
    build_register,
    cbom_violations,
    downgrade_to_1_6,
)
from qavach_core.model.asset import CryptoAsset, Occurrence
from qavach_core.model.enums import (
    AssetType,
    ConfidenceTier,
    CryptoFunction,
    FindingClass,
    MigrationAuthority,
)
from qavach_core.model.locus import FileLocus, NetworkLocus, SourceLocus
from qavach_core.model.system import DataClass, System
from qavach_core.policy import PolicySnapshot
from qavach_core.reconcile import IdentityClaim, asset_identity
from qavach_core.risk import AssetRiskInput, score_asset
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
CDX_DIR = ROOT / "config" / "knowledge" / "cdx-crypto-registry"
AS_OF = date(2026, 9, 20)
NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
POLICY_DOCS = (
    "z_scenarios",
    "regulatory_deadlines",
    "scoring",
    "risk_tolerance",
    "migration_effort",
    "retention_defaults",
)


def load_policy() -> PolicySnapshot:
    return PolicySnapshot.from_documents(
        {
            n: yaml.safe_load((ROOT / "config" / "policy" / f"{n}.yaml").read_text())
            for n in POLICY_DOCS
        }
    )


def known_families() -> frozenset[str]:
    registry = json.loads((CDX_DIR / "cryptography-defs.json").read_text())
    return frozenset(a["family"] for a in registry["algorithms"])


def _asset(
    family: str,
    function: CryptoFunction,
    finding: FindingClass,
    *,
    parameter: str | None = None,
    mode: str | None = None,
    authority: MigrationAuthority = MigrationAuthority.SELF,
    occurrences: tuple[Occurrence, ...],
    primitive: str | None = None,
) -> CryptoAsset:
    identity = asset_identity(
        IdentityClaim(
            asset_type=AssetType.ALGORITHM,
            algorithm_family=family,
            parameter_set=parameter,
            primitive=primitive,
        )
    )
    return CryptoAsset(
        identity=identity,
        asset_type=AssetType.ALGORITHM,
        function=function,
        algorithm_family=family,
        parameter_set=parameter,
        curve=None,
        mode=mode,
        padding=None,
        oid=None,
        finding_class=finding,
        migration_authority=authority,
        authority_basis="sample",
        occurrences=occurrences,
        concluded_from=max(o.confidence for o in occurrences),
        disputed=False,
        disputes=(),
    )


def _occ(locus: Any, tier: ConfidenceTier, method: str, collector: str) -> Occurrence:
    return Occurrence(
        locus=locus,
        collector=collector,
        tool_version="1.0",
        confidence=tier,
        detection_method=method,
        raw_ref="raw://sample",
        observed_at=NOW,
    )


def sample_assets() -> list[CryptoAsset]:
    src = SourceLocus(
        repo="github.com/acme/pay",
        commit="abc123",
        path="src/Auth.java",
        start_line=42,
        end_line=42,
    )
    tls = NetworkLocus(host="pay.acme.in", port=443, sni="pay.acme.in", protocol="tls")
    QV, CW, GR, QS = (
        FindingClass.QUANTUM_VULNERABLE,
        FindingClass.CLASSICAL_WEAK,
        FindingClass.GROVER_AFFECTED,
        FindingClass.QUANTUM_SAFE,
    )
    return [
        _asset(
            "RSASSA-PKCS1",
            CryptoFunction.SIGNATURE,
            QV,
            parameter="2048",
            occurrences=(
                _occ(tls, ConfidenceTier.RUNTIME, "runtime", "tls.endpoint"),
                _occ(src, ConfidenceTier.AST, "ast", "source_scan.cbomkit"),
            ),
        ),
        _asset(
            "ECDSA",
            CryptoFunction.SIGNATURE,
            QV,
            occurrences=(_occ(tls, ConfidenceTier.RUNTIME, "runtime", "tls.endpoint"),),
        ),
        _asset(
            "ECDH",
            CryptoFunction.KEY_AGREEMENT,
            QV,
            occurrences=(_occ(tls, ConfidenceTier.RUNTIME, "runtime", "tls.endpoint"),),
        ),
        _asset(
            "AES",
            CryptoFunction.ENCRYPTION,
            GR,
            parameter="128",
            mode="cbc",
            occurrences=(_occ(src, ConfidenceTier.AST, "ast", "source_scan.cbomkit"),),
        ),
        _asset(
            "AES",
            CryptoFunction.ENCRYPTION,
            QS,
            parameter="256",
            mode="gcm",
            occurrences=(
                _occ(
                    FileLocus(path="a.py", offset=6),
                    ConfidenceTier.AST,
                    "ast",
                    "source_scan.cdxgen",
                ),
            ),
        ),
        _asset(
            "ML-KEM",
            CryptoFunction.KEY_ENCAPSULATION,
            QS,
            parameter="768",
            occurrences=(_occ(tls, ConfidenceTier.RUNTIME, "runtime", "tls.endpoint"),),
        ),
        _asset(
            "MD5",
            CryptoFunction.HASH,
            CW,
            occurrences=(
                _occ(
                    FileLocus(path="legacy.c", offset=6),
                    ConfidenceTier.PATTERN,
                    "pattern",
                    "source_scan.opengrep",
                ),
            ),
        ),
        _asset(
            "3DES",
            CryptoFunction.ENCRYPTION,
            CW,
            mode="cbc",
            occurrences=(_occ(src, ConfidenceTier.AST, "ast", "source_scan.cbomkit"),),
        ),
        _asset(
            "Vendor-Proprietary-Cipher",
            CryptoFunction.ENCRYPTION,
            FindingClass.UNKNOWN,
            authority=MigrationAuthority.UNKNOWN,
            occurrences=(
                _occ(
                    FileLocus(path="blob.bin", offset=0),
                    ConfidenceTier.HEURISTIC,
                    "other",
                    "binary.static",
                ),
            ),
        ),
    ]


def sample_system() -> System:
    return System(
        id="payments",
        name="Payments",
        owner="team-a",
        criticality=5,
        data_classification=DataClass.RESTRICTED,
        retention_years=10.0,
        retention_inferred=False,
        internet_facing=True,
        regulatory_regimes=frozenset({"cii"}),
        depends_on=frozenset(),
    )


def sample_documents() -> tuple[dict[str, Any], dict[str, Any], list[RegisterInput]]:
    policy = load_policy()
    assets = sample_assets()
    system = sample_system()
    items = []
    for asset in assets:
        score = score_asset(
            AssetRiskInput(
                identity=asset.identity,
                finding_class=asset.finding_class,
                also_quantum_vulnerable=False,
                function=asset.function,
                authority=asset.migration_authority,
                loci=tuple(o.locus for o in asset.occurrences),
                system=system,
                artefact_lifetime_years=0.25
                if asset.function is CryptoFunction.SIGNATURE
                else None,
            ),
            policy=policy,
            as_of=AS_OF,
        )
        items.append(RegisterInput(asset=asset, score=score))
    cbom = build_cbom(
        assets, timestamp=NOW, qavach_version="0.1.0", scope="root", known_families=known_families()
    )
    register = build_register(
        items,
        cbom=cbom,
        policy_snapshot_id=policy.snapshot_id,
        z_scenario="nominal",
        as_of=AS_OF,
        generated_at=NOW,
    )
    return cbom, register, items


def cbom_validator() -> Draft7Validator:
    """Built entirely from local files; any network attempt raises (I7)."""
    resources = [
        (p.name, Resource.from_contents(json.loads(p.read_text())))
        for p in CDX_DIR.glob("*.schema.json")
    ]
    registry: Registry = Registry().with_resources(resources)
    schema = json.loads((CDX_DIR / "bom-1.7.schema.json").read_text())
    return Draft7Validator(schema, registry=registry)


def cbom_1_6_validator() -> Draft7Validator:
    directory = ROOT / "config" / "knowledge" / "cdx-1.6"
    resources = [
        (p.name, Resource.from_contents(json.loads(p.read_text())))
        for p in directory.glob("*.schema.json")
    ]
    registry: Registry = Registry().with_resources(resources)
    return Draft7Validator(
        json.loads((directory / "bom-1.6.schema.json").read_text()), registry=registry
    )


def register_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((ROOT / "docs/schema/risk-register-1.0.json").read_text())
    )


def documented_in_markdown() -> set[str]:
    text = (ROOT / "docs" / "CUSTOM_PROPERTIES.md").read_text()
    return set(re.findall(r"^\|\s*`(qavach:[a-z0-9-]+)`", text, flags=re.MULTILINE))


def errors_of(validator: Any, document: Any) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in validator.iter_errors(document)
    ]


def run_checks() -> list[str]:
    def blocked(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("network access attempted during schema validation (I7)")

    real_socket, socket.socket = socket.socket, blocked  # type: ignore[assignment,misc]
    try:
        problems: list[str] = []
        cbom, register, _ = sample_documents()
        cv, rv = cbom_validator(), register_validator()

        problems += [f"CBOM schema: {e}" for e in errors_of(cv, cbom)]
        problems += [f"CBOM purity: {v}" for v in cbom_violations(cbom)]
        downgraded, _losses = downgrade_to_1_6(cbom)
        problems += [f"CBOM 1.6 schema: {e}" for e in errors_of(cbom_1_6_validator(), downgraded)]
        problems += [f"CBOM 1.6 purity: {v}" for v in cbom_violations(downgraded)]
        problems += [f"register schema: {e}" for e in errors_of(rv, register)]

        documented = documented_in_markdown()
        for name in sorted(DOCUMENTED_PROPERTIES - documented):
            problems.append(f"{name} is emitted but not documented in docs/CUSTOM_PROPERTIES.md")
        for name in sorted(documented - DOCUMENTED_PROPERTIES):
            problems.append(f"{name} is documented but the exporter cannot emit it")

        # Guard the guards: each must reject what it claims to reject.
        def polluted(mutate: Any) -> dict[str, Any]:
            doc = copy.deepcopy(cbom)
            mutate(doc)
            return doc

        cases = {
            "an undocumented qavach: property": lambda d: d["components"][0]["properties"].append(
                {"name": "qavach:notes", "value": "x"}
            ),
            "a risk score property": lambda d: d["components"][0]["properties"].append(
                {"name": "qavach:risk-score", "value": "9"}
            ),
            "a Mosca property in another namespace": lambda d: d["components"][0][
                "properties"
            ].append({"name": "acme:mosca-gap", "value": "3"}),
            "a purl on a cryptographic-asset": lambda d: d["components"][0].__setitem__(
                "purl", "pkg:generic/rsa"
            ),
        }
        for label, mutate in cases.items():
            if not cbom_violations(polluted(mutate)):
                problems.append(f"SELF-TEST FAILED: the purity check did not reject {label}")
        if not errors_of(cv, polluted(lambda d: d.__setitem__("specVersion", 7))):
            problems.append("SELF-TEST FAILED: the CBOM schema did not reject an invalid document")
        bad_register = copy.deepcopy(register)
        del bad_register["entries"][0]["reason"]
        if not errors_of(rv, bad_register):
            problems.append("SELF-TEST FAILED: the register schema did not reject a missing reason")
        return problems
    finally:
        socket.socket = real_socket  # type: ignore[misc]


def main() -> int:
    problems = run_checks()
    for p in problems:
        print(f"FAIL: {p}")
    if problems:
        return 1
    print(
        "schema-check OK: CBOM valid against CycloneDX 1.7, no risk data in it, "
        "register valid, docs consistent"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
