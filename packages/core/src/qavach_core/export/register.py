"""The Crypto Risk Register. T-092 / ARCH.md 10.

Everything QAVACH *concludes* - scores, Mosca inputs and outputs, the CARAF
outcome, the recommendation, the roadmap position, and the explanation behind
each - lives here, keyed by the CBOM's `bom-ref`s (invariant I5). The CBOM stays
a clean standards artefact; this is the document that carries the opinions,
with the schema at `docs/schema/risk-register-1.0.json`.

Two rules shape the summary (`PRD.md` I8, ARCH.md 7.4a):

* **`unknown` is counted separately in every aggregate and reported as a
  coverage failure**, never folded into a "safe" count;
* **denominators are always shown** (`total`), so a count cannot be read out of
  context. A bare violation count that can exceed the asset count is a bug.

Every heuristic-derived value carries `heuristic: true` through its
explanation; the register also states the policy snapshot id and the Z
scenario, so any number in it can be reproduced (NFR-09).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from qavach_core.export.cbom import bom_ref
from qavach_core.model.asset import CryptoAsset
from qavach_core.model.enums import ConfidenceTier, CryptoFunction, FindingClass
from qavach_core.recommend import Recommendation
from qavach_core.risk import AssetRiskScore
from qavach_core.roadmap import Roadmap

REGISTER_VERSION = "1.0"
HEURISTIC_NOTICE = (
    "Y (migration time), the expected-value thresholds, retention defaults and the "
    "ephemeral-artefact cut-off are planning heuristics, uncalibrated; they are not measurements."
)


@dataclass(frozen=True, slots=True)
class RegisterInput:
    asset: CryptoAsset
    score: AssetRiskScore
    recommendation: Recommendation | None = None


def unit_id(system_id: str, function: CryptoFunction | None) -> str:
    """The roadmap's migration unit: a `(System, CryptoFunction)` pair."""
    return f"{system_id}:{function.value if function else 'unknown'}"


def plain(value: Any) -> Any:
    """Recursively turns dataclasses, enums, dates and sets into JSON types,
    deterministically (sets sorted, dataclass fields in declaration order)."""
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((plain(v) for v in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def register_entry(item: RegisterInput, roadmap: Roadmap | None = None) -> dict[str, Any]:
    """One register entry: everything QAVACH concludes about one (asset, system)."""
    asset, score = item.asset, item.score
    entry: dict[str, Any] = {
        "bom_ref": bom_ref(asset.identity),
        "system_id": score.system_id,
        "finding_class": asset.finding_class.value,
        "migration_authority": asset.migration_authority.value,
        "authority_basis": asset.authority_basis,
        "band": score.band.value,
        "outcome": score.outcome,
        "reason": score.reason,
        "disputed": asset.disputed,
        "capability_only": asset.concluded_from <= ConfidenceTier.DEPENDENCY,
        "mosca": None,
        "expected_value": None,
        "z_effective": None,
        "recommendation": None,
        "roadmap": None,
        "explanations": [e.to_dict() for e in score.explanations()],
    }
    if score.mosca is not None and score.z is not None and score.y is not None:
        entry["mosca"] = {
            "x_conf_years": score.mosca.x_conf,
            "x_integ_years": score.mosca.x_integ,
            "y_years": score.y.years,
            "y_is_heuristic": True,
            "z_years": round(score.mosca.z_years, 6),
            "gap_years": None if score.mosca.gap_years is None else round(score.mosca.gap_years, 6),
            "mitigation": score.mosca.mitigation,
            "note": score.mosca.note,
        }
        entry["z_effective"] = {
            "date": score.z.z_date.isoformat(),
            "bound_by": score.z.bound_by,
            "binding": score.z.binding,
            "scenario": score.z.scenario,
        }
    if score.ev is not None:
        entry["expected_value"] = {
            "ev": round(score.ev.ev, 6),
            "criticality": score.ev.criticality,
            "sensitivity": score.ev.sensitivity,
            "exposure": score.ev.exposure,
            "gap_factor": round(score.ev.gap_factor, 6),
        }
    if item.recommendation is not None:
        entry["recommendation"] = plain(item.recommendation)
    if roadmap is not None and score.system_id is not None:
        scheduled = roadmap.schedule.get(unit_id(score.system_id, asset.function))
        if scheduled is not None:
            entry["roadmap"] = plain(scheduled)
    return entry


def build_register(
    items: Iterable[RegisterInput],
    *,
    cbom: Mapping[str, Any],
    policy_snapshot_id: str,
    z_scenario: str,
    as_of: date,
    generated_at: datetime,
    roadmap: Roadmap | None = None,
) -> dict[str, Any]:
    ordered = sorted(items, key=lambda i: (bom_ref(i.asset.identity), i.score.system_id or ""))
    return assemble_register(
        [register_entry(i, roadmap) for i in ordered],
        roadmap_doc=roadmap_document(roadmap),
        cbom=cbom,
        policy_snapshot_id=policy_snapshot_id,
        z_scenario=z_scenario,
        as_of=as_of,
        generated_at=generated_at,
    )


def roadmap_document(roadmap: Roadmap | None) -> dict[str, Any] | None:
    if roadmap is None:
        return None
    return {
        "waves": plain(roadmap.waves),
        "bridges": plain(roadmap.bridges),
        "vendor_dependencies": plain(roadmap.vendor_dependencies),
        "named_blockers": plain(roadmap.named_blockers),
        "infeasible": plain(roadmap.infeasible),
        "excluded_trust_anchors": roadmap.excluded_trust_anchors,
        "triage": list(roadmap.triage),
        "notes": list(roadmap.notes),
    }


def assemble_register(
    entries: list[dict[str, Any]],
    *,
    roadmap_doc: dict[str, Any] | None,
    cbom: Mapping[str, Any],
    policy_snapshot_id: str,
    z_scenario: str,
    as_of: date,
    generated_at: datetime,
) -> dict[str, Any]:
    """The register from already-built entries: what an export does when it has
    loaded stored scores rather than live ones. `entries` must be pre-sorted."""
    total = len(entries)
    by_class = Counter(e["finding_class"] for e in entries)
    by_band = Counter(e["band"] for e in entries)
    unknown = by_class.get(FindingClass.UNKNOWN.value, 0)
    return {
        "register_version": REGISTER_VERSION,
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "as_of": as_of.isoformat(),
        "heuristics_notice": HEURISTIC_NOTICE,
        "policy": {"snapshot_id": policy_snapshot_id, "z_scenario": z_scenario},
        "cbom": {
            "serial_number": cbom.get("serialNumber"),
            "spec_version": cbom.get("specVersion"),
        },
        "summary": {
            "total": total,
            "by_finding_class": dict(sorted(by_class.items())),
            "by_band": dict(sorted(by_band.items())),
            "coverage_failures": unknown,
            "coverage_failures_capability_only": sum(
                1
                for e in entries
                if e["finding_class"] == FindingClass.UNKNOWN.value and e["capability_only"]
            ),
            "coverage_failure_note": (
                "Assets that could not be classified are a coverage failure, not a risk "
                "verdict, and are never counted as safe. `capability_only` entries rest on "
                "dependency-level evidence (a library that CAN do this), not observed usage."
            ),
            "unassigned": sum(1 for e in entries if e["system_id"] is None),
        },
        "entries": entries,
        "roadmap": roadmap_doc,
    }
