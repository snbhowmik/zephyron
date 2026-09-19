"""`POST /policy/simulate` - re-score a stored scan against a candidate policy,
with no re-scan. T-075.

Pure recomputation over already-reconciled assets: this is what makes moving the
`Z` slider a sub-second round trip (`ARCH.md §12`, FR-650). Nothing is written;
the scan's own stored scores and policy snapshot are untouched, so a simulation
can never change what a past scan said.

Overrides are `{policy_path: new_value}` on a node's `value` (for example
`scoring.mosca.imminent_within_years` or `z_scenarios.default`). A path that does
not exist, a container, or a node with no `value` is refused, and so is a value of
a different type: a typo must not silently simulate the unchanged policy.
"""

from __future__ import annotations

import copy
import time
from collections import Counter
from datetime import date
from typing import Any

from qavach_core.model.enums import CryptoFunction, FindingClass, MigrationAuthority
from qavach_core.model.identity import AssetIdentity, IdentityKind
from qavach_core.model.locus import locus_from_dict
from qavach_core.model.system import System
from qavach_core.pipeline import AssembleKnowledge
from qavach_core.policy import PolicyError, PolicySnapshot
from qavach_core.risk import AssetRiskInput, ScoreMemo, score_asset
from qavach_core.risk.classify import classify
from qavach_storage import Repository
from sqlalchemy.orm import Session

HEURISTIC_NOTICE = (
    "Simulated scores use the same planning heuristics as real ones (Y, EV thresholds); "
    "they are not measurements."
)


def apply_overrides(base: PolicySnapshot, overrides: dict[str, Any]) -> PolicySnapshot:
    """`path` overrides a node's `value`; `path#field` overrides another field of
    the node (e.g. `z_scenarios.scenarios.nominal#crqc_year`, which is what the
    Mosca explorer's Z slider sets). Both are validated: the path must exist, it
    must be a node (not a container), the field must already exist, and the new
    value must have the old value's type."""
    documents = copy.deepcopy(dict(base.documents))
    for target, new_value in overrides.items():
        path, _, field = target.partition("#")
        field = field or "value"
        node = base.node(path)  # raises PolicyError for a missing path / a container
        if field not in node.fields:
            raise PolicyError(f"{path!r} has no `{field}` to override")
        old = node.fields[field]
        numeric = (int, float)
        if isinstance(old, bool) or isinstance(new_value, bool):
            ok = isinstance(old, bool) and isinstance(new_value, bool)
        elif isinstance(old, numeric):
            ok = isinstance(new_value, numeric)
        else:
            ok = isinstance(new_value, type(old))
        if not ok:
            raise PolicyError(
                f"{target!r}: expected a {type(old).__name__}, got {type(new_value).__name__}"
            )
        cursor: Any = documents
        for part in path.split("."):
            cursor = cursor[part]
        cursor[field] = new_value
    return PolicySnapshot.from_documents(documents)


def simulate(
    session: Session,
    scan_id: str,
    *,
    overrides: dict[str, Any],
    z_scenario: str | None,
    knowledge: AssembleKnowledge,
    top: int = 20,
) -> dict[str, Any]:
    repo = Repository(session)
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise KeyError(scan_id)
    baseline_policy = repo.policy_snapshot(scan_id)
    candidate = apply_overrides(baseline_policy, overrides)
    scenario = z_scenario or str(candidate.value("z_scenarios.default"))
    candidate.node(f"z_scenarios.scenarios.{scenario}")  # PolicyError if unknown
    as_of = date.fromisoformat(scan.as_of)

    systems_list, _ = repo.load_systems()
    systems: dict[str, System] = {s.id: s for s in systems_list}
    rows = repo.simulation_rows(scan_id)
    stored = repo.stored_bands(scan_id)

    start = time.perf_counter()
    memo = ScoreMemo()
    baseline_bands: Counter[str] = Counter()
    candidate_bands: Counter[str] = Counter()
    transitions: Counter[str] = Counter()
    movers: list[tuple[float, dict[str, Any]]] = []
    changed = 0
    scored = 0

    for row in rows:
        family = row["family"]
        finding = FindingClass(row["finding_class"])
        also_qv = (
            finding is FindingClass.CLASSICAL_WEAK
            and classify(
                family, row["parameter_set"], rules=knowledge.rules
            ).also_quantum_vulnerable
        )
        loci = tuple(locus_from_dict(x) for x in row["loci"])
        for system_id in row["systems"] or [None]:
            key = (row["id"], system_id or "")
            if key not in stored:
                continue
            result = score_asset(
                AssetRiskInput(
                    identity=AssetIdentity(
                        kind=IdentityKind(row["identity_kind"]), key=row["identity_key"]
                    ),
                    finding_class=finding,
                    also_quantum_vulnerable=also_qv,
                    function=CryptoFunction(row["function"]) if row["function"] else None,
                    authority=MigrationAuthority(row["migration_authority"]),
                    loci=loci,
                    system=systems.get(system_id) if system_id else None,
                ),
                policy=candidate,
                as_of=as_of,
                scenario=scenario,
                explain=False,
                memo=memo,
            )
            old_band, old_outcome, old_gap = stored[key]
            scored += 1
            baseline_bands[old_band] += 1
            candidate_bands[result.band.value] += 1
            if (old_band, old_outcome) != (result.band.value, result.outcome):
                changed += 1
                transitions[f"{old_band} -> {result.band.value}"] += 1
            new_gap = result.mosca.gap_years if result.mosca else None
            # stored gaps are rounded to 6 dp (register_entry); compare like with like
            if (
                old_gap is not None
                and new_gap is not None
                and round(old_gap, 6) != round(new_gap, 6)
            ):
                movers.append(
                    (
                        abs(new_gap - old_gap),
                        {
                            "asset_id": row["id"],
                            "family": family,
                            "system_id": system_id,
                            "band": {"from": old_band, "to": result.band.value},
                            "gap_years": {"from": round(old_gap, 3), "to": round(new_gap, 3)},
                        },
                    )
                )
    movers.sort(key=lambda m: -m[0])
    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

    return {
        "scan_id": scan_id,
        "baseline_policy_snapshot_id": baseline_policy.snapshot_id,
        "candidate_policy_snapshot_id": candidate.snapshot_id,
        "z_scenario": {"baseline": scan.z_scenario, "candidate": scenario},
        "overrides": overrides,
        "scored": scored,
        "changed": changed,
        "bands": {
            "baseline": dict(sorted(baseline_bands.items())),
            "candidate": dict(sorted(candidate_bands.items())),
        },
        "transitions": dict(sorted(transitions.items())),
        "top_movers": [m for _, m in movers[:top]],
        "scoring_ms": elapsed_ms,
        "heuristics_notice": HEURISTIC_NOTICE,
    }
