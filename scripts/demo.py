"""T-120 (first cut) - `make demo`: real recorded scanner output through every layer.

Replays the recorded cdxgen / cbomkit-lib / Opengrep / Syft / tracebom output
(`tests/fixtures/scanner-output/`, T-024) and drives it through assemble ->
bind -> score -> recommend -> roadmap -> export, then VALIDATES the CBOM against
the official CycloneDX 1.7 schema. Nothing here is synthetic except the two
example systems in `tests/fixtures/demo/systems.csv` and the repository they are
bound to.

    uv run python scripts/demo.py [--out dist/demo]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.binary import BinaryKnowledge
from qavach_collectors.runtime import TracebomCollector
from qavach_collectors.runtime import tracebom as tracebom_mod
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
from qavach_core.context import (
    BindingKey,
    bind_assets,
    keys_for_locus,
    parse_systems_csv,
    system_dependency_edges,
)
from qavach_core.export import (
    RegisterInput,
    build_cbom,
    build_register,
    build_sarif,
    cbom_violations,
    unit_id,
)
from qavach_core.model.enums import MigrationAuthority
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_core.pipeline import (
    AssembleKnowledge,
    ClaimInput,
    FamilyFunctions,
    also_quantum_vulnerable_of,
    assemble,
)
from qavach_core.policy import PolicySnapshot
from qavach_core.recommend import Constraints, PqcKnowledge, recommend
from qavach_core.risk import AssetRiskInput, ClassificationRules, score_asset
from qavach_core.roadmap import Edge, EdgeKind, MigrationUnit, build_roadmap
from qavach_sandbox import SandboxResult

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "fixtures" / "scanner-output"
REPO = "github.com/acme/polyglot-payments"
AS_OF = date(2026, 9, 20)
NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
IMAGE = "sha256:" + "0" * 64
POLICY_DOCS = (
    "z_scenarios",
    "regulatory_deadlines",
    "scoring",
    "risk_tolerance",
    "migration_effort",
    "retention_defaults",
)


def _yaml(path: str) -> Any:
    return yaml.safe_load((ROOT / path).read_text())


def load_knowledge() -> tuple[AssembleKnowledge, PolicySnapshot, PqcKnowledge]:
    registry = CryptographyRegistry.from_dict(
        json.loads(
            (ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text()
        )
    )
    knowledge = AssembleKnowledge(
        registry=registry,
        aliases=AliasTable.from_dict(_yaml("config/knowledge/aliases.yaml")),
        rules=ClassificationRules.from_dict(_yaml("config/knowledge/classification_rules.yaml")),
        family_functions=FamilyFunctions.from_dict(_yaml("config/knowledge/family_functions.yaml")),
    )
    policy = PolicySnapshot.from_documents(
        {n: _yaml(f"config/policy/{n}.yaml") for n in POLICY_DOCS}
    )
    pqc = PqcKnowledge.from_documents(
        _yaml("config/knowledge/pqc_alternatives.yaml"), _yaml("config/knowledge/performance.yaml")
    )
    return knowledge, policy, pqc


def replay_corpus(knowledge: AssembleKnowledge) -> list[ClaimInput]:
    """Runs each real collector's *parser* over its recorded real output."""
    libraries = CryptoLibraryMapping.from_entries(
        _yaml("config/knowledge/crypto_libraries.yaml")["libraries"]
    )
    rules = load_rules(_yaml("config/opengrep-rules/crypto.yaml"))
    binary = BinaryKnowledge.from_dict(_yaml("config/knowledge/binary_crypto.yaml"))
    registry, aliases = knowledge.registry, knowledge.aliases
    target = Target(type=TargetType.REPOSITORY, ref="/repo", options={"cmd": "python3 app.py"})
    plan = [
        (
            cdxgen_mod,
            CdxgenCollector(registry=registry, aliases=aliases),
            "cdxgen/polyglot.cdx.json",
        ),
        (
            cbomkit_mod,
            CbomkitCollector(registry=registry, aliases=aliases, image_ref=IMAGE),
            "cbomkit/polyglot.cdx.json",
        ),
        (opengrep_mod, OpengrepCollector(rules=rules, image_ref=IMAGE), "opengrep/polyglot.sarif"),
        (syft_mod, SyftCollector(crypto_libraries=libraries), "syft/polyglot.syft.json"),
        (
            tracebom_mod,
            TracebomCollector(
                registry=registry, aliases=aliases, knowledge=binary, image_ref=IMAGE
            ),
            "tracebom/python-ssl.cdx.json",
        ),
    ]
    claims: list[ClaimInput] = []
    for module, collector, filename in plan:
        recorded = (CORPUS / filename).read_bytes()
        with mock.patch.object(
            module,
            "run_sandboxed",
            lambda _c, data=recorded: SandboxResult(0, data, b"", 1.0, False),
        ):
            result = collector.collect(target, RunContext(scan_run_id="demo"))
        for raw in result.claims:
            claims.append(
                ClaimInput(
                    name=raw.name,
                    oid=raw.oid,
                    primitive=raw.primitive,
                    parameter_set=raw.parameter_set,
                    mode=raw.mode,
                    padding=raw.padding,
                    locus=raw.locus,
                    collector=result.tool.name,
                    tool_version=result.tool.version,
                    confidence=raw.confidence,
                    detection_method=raw.detection_method,
                    raw_ref=f"{result.tool.name}:{filename}",
                    observed_at=NOW,
                )
            )
    return claims


def build_demo(out: Path | None = None) -> dict[str, Any]:
    knowledge, policy, pqc = load_knowledge()
    claims = replay_corpus(knowledge)
    assembled = assemble(claims, knowledge)
    assets = list(assembled.assets)

    imported = parse_systems_csv((ROOT / "tests/fixtures/demo/systems.csv").read_text(), policy)
    if not imported.ok:
        raise SystemExit(f"systems import failed: {imported.errors}")
    systems = {s.id: s for s in imported.systems}

    scan_target = BindingKey("repo", REPO)
    binding = bind_assets(
        {
            a.identity: [
                k for o in a.occurrences for k in keys_for_locus(o.locus, scan_target=scan_target)
            ]
            for a in assets
        },
        imported.bindings,
    )

    items: list[RegisterInput] = []
    units: dict[str, dict[str, Any]] = {}
    for asset in assets:
        system_ids = binding.systems_for(asset.identity) or (None,)
        for system_id in system_ids:
            system = systems.get(system_id) if system_id else None
            score = score_asset(
                AssetRiskInput(
                    identity=asset.identity,
                    finding_class=asset.finding_class,
                    also_quantum_vulnerable=also_quantum_vulnerable_of(asset, knowledge),
                    function=asset.function,
                    authority=asset.migration_authority,
                    loci=tuple(o.locus for o in asset.occurrences),
                    system=system,
                ),
                policy=policy,
                as_of=AS_OF,
            )
            rec = recommend(
                finding_class=asset.finding_class,
                also_quantum_vulnerable=also_quantum_vulnerable_of(asset, knowledge),
                function=asset.function,
                algorithm_family=asset.algorithm_family,
                knowledge=pqc,
                constraints=Constraints(
                    regimes=system.regulatory_regimes if system else frozenset()
                ),
            )
            items.append(RegisterInput(asset=asset, score=score, recommendation=rec))
            if (
                system
                and score.outcome
                and score.y
                and score.z
                and asset.migration_authority is MigrationAuthority.SELF
            ):
                uid = unit_id(system.id, asset.function)
                u = units.setdefault(
                    uid,
                    {
                        "system": system.id,
                        "function": asset.function,
                        "y": 0.0,
                        "deadline": score.z.z_date,
                        "bound": score.z.bound_by,
                        "gap": None,
                    },
                )
                u["y"] = max(u["y"], score.y.years)
                if score.mosca and score.mosca.gap_years is not None:
                    u["gap"] = (
                        max(u["gap"], score.mosca.gap_years)
                        if u["gap"] is not None
                        else score.mosca.gap_years
                    )

    migration_units = [
        MigrationUnit(
            id=uid,
            system_id=u["system"],
            function=u["function"],
            authority=MigrationAuthority.SELF,
            y_years=u["y"],
            deadline=u["deadline"],
            deadline_bound_by=u["bound"],
            urgency_gap_years=u["gap"],
        )
        for uid, u in sorted(units.items())
    ]
    edges = []
    for dependent, dependency in system_dependency_edges(imported.systems):
        for uid, u in units.items():
            counterpart = unit_id(dependency, u["function"]) if u["system"] == dependent else None
            if counterpart and counterpart in units:
                edges.append(Edge(counterpart, uid, EdgeKind.PROTOCOL_PEER))
    roadmap = build_roadmap(migration_units, edges, as_of=AS_OF, capacity_per_quarter=4)

    from schema_check import (  # type: ignore[import-not-found]
        cbom_validator,
        errors_of,
        known_families,
    )

    cbom = build_cbom(
        assets, timestamp=NOW, qavach_version="0.1.0", known_families=known_families()
    )
    register = build_register(
        items,
        cbom=cbom,
        policy_snapshot_id=policy.snapshot_id,
        z_scenario="nominal",
        as_of=AS_OF,
        generated_at=NOW,
        roadmap=roadmap,
    )
    sarif = build_sarif(items, qavach_version="0.1.0")
    problems = errors_of(cbom_validator(), cbom) + cbom_violations(cbom)

    authority = Counter(a.migration_authority.value for a in assets)
    summary: dict[str, Any] = {
        "claims_in": len(claims),
        "occurrences_out": sum(len(a.occurrences) for a in assets),
        "assets": len(assets),
        "by_finding_class": register["summary"]["by_finding_class"],
        "by_band": register["summary"]["by_band"],
        "coverage_failures": register["summary"]["coverage_failures"],
        "unresolved_names": list(assembled.unresolved),
        "unassigned": len(binding.unassigned),
        "authority": dict(authority),
        "cbom_valid": not problems,
        "cbom_problems": problems,
        "bridges": [list(b.members) for b in roadmap.bridges],
        "waves": len(roadmap.waves),
        "infeasible": len(roadmap.infeasible),
        "systems": sorted(systems),
    }
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "cbom.cdx.json").write_text(json.dumps(cbom, indent=2, sort_keys=True))
        (out / "risk-register.json").write_text(json.dumps(register, indent=2, sort_keys=True))
        (out / "findings.sarif").write_text(json.dumps(sarif, indent=2, sort_keys=True))
        (out / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True, default=str)
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "demo")
    args = parser.parse_args()
    summary = build_demo(args.out)
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    if not summary["cbom_valid"]:
        print("FAIL: the demo CBOM is not valid", file=sys.stderr)
        return 1
    print(f"\nwrote {args.out}/ (CBOM validated against CycloneDX 1.7)")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
