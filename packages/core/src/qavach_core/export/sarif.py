"""SARIF 2.1.0 export and CI gating. T-096.

Findings a pipeline can act on, and a `--fail-on` decision that is explicit
about what fails the build. Severity follows the finding classes (I1):

* `overdue` quantum-vulnerable and `classical-weak` -> `error` (broken now or
  already late);
* `imminent` -> `warning`;
* `coverage-gap` (unclassified) -> `note`: a coverage failure is worth seeing
  and gating on, but it is not a risk verdict (I8);
* Grover-affected, quantum-safe and comfortably `planned` assets produce no
  result - informational classes must not become CI noise.

`fail_on` names finding classes and/or bands (`quantum-vulnerable`,
`classical-weak`, `overdue`, `unknown`, ...). Gating on `unknown` lets a team
refuse a pipeline that cannot see what it is shipping.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from qavach_core.export.cbom import bom_ref, location_of
from qavach_core.export.register import RegisterInput
from qavach_core.model.asset import CryptoAsset
from qavach_core.model.enums import FindingClass
from qavach_core.risk import UrgencyBand

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_RULES = {
    "QAVACH001": ("quantum-vulnerable", "Quantum-vulnerable cryptography"),
    "QAVACH002": ("classical-weak", "Classically weak cryptography"),
    "QAVACH003": ("unknown", "Cryptography that could not be classified (coverage gap)"),
}
FAIL_ON_TOKENS = frozenset({fc.value for fc in FindingClass} | {b.value for b in UrgencyBand})


def _result_for(item: RegisterInput) -> tuple[str, str, str] | None:
    return _verdict(item.asset.finding_class, item.score.band, item.score.reason)


def _verdict(fc: FindingClass, band: UrgencyBand, reason: str) -> tuple[str, str, str] | None:
    if fc is FindingClass.UNKNOWN or band is UrgencyBand.COVERAGE_GAP:
        return "QAVACH003", "note", reason
    if fc is FindingClass.CLASSICAL_WEAK:
        return "QAVACH002", "error", "classically weak: replace now (not a quantum finding)"
    if fc is FindingClass.QUANTUM_VULNERABLE:
        if band is UrgencyBand.OVERDUE:
            return "QAVACH001", "error", f"quantum-vulnerable and overdue: {reason}"
        if band is UrgencyBand.IMMINENT:
            return "QAVACH001", "warning", f"quantum-vulnerable, imminent: {reason}"
    return None


def _location(asset: CryptoAsset) -> list[dict[str, Any]]:
    locations = []
    for occ in asset.occurrences[:1]:
        uri, line, _ = location_of(occ.locus)
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if line:
            physical["region"] = {"startLine": line}
        locations.append({"physicalLocation": physical})
    return locations


def _document(results: list[dict[str, Any]], qavach_version: str) -> dict[str, Any]:
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "QAVACH",
                        "version": qavach_version,
                        "rules": [
                            {"id": rid, "name": name, "shortDescription": {"text": text}}
                            for rid, (name, text) in _RULES.items()
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def _result(asset: CryptoAsset, verdict: tuple[str, str, str]) -> dict[str, Any]:
    rule_id, level, message = verdict
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"{asset.algorithm_family}: {message}"},
        "locations": _location(asset),
        "properties": {"bom-ref": bom_ref(asset.identity)},
    }


def build_sarif(items: Iterable[RegisterInput], *, qavach_version: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for item in sorted(items, key=lambda i: (bom_ref(i.asset.identity), i.score.system_id or "")):
        verdict = _result_for(item)
        if verdict is not None:
            results.append(_result(item.asset, verdict))
    return _document(results, qavach_version)


def build_sarif_from_entries(
    entries: Iterable[Mapping[str, Any]],
    assets: Iterable[CryptoAsset],
    *,
    qavach_version: str,
) -> dict[str, Any]:
    """The same document from *stored* register entries (what the API holds after
    a scan) plus the assets they refer to - identical output to `build_sarif` for
    the same scan. An entry whose asset is missing is skipped: no location, no
    result, and never a crash."""
    by_ref = {bom_ref(a.identity): a for a in assets}
    results: list[dict[str, Any]] = []
    for entry in sorted(entries, key=lambda e: (e["bom_ref"], e.get("system_id") or "")):
        asset = by_ref.get(entry["bom_ref"])
        if asset is None:
            continue
        verdict = _verdict(
            FindingClass(entry["finding_class"]), UrgencyBand(entry["band"]), entry["reason"]
        )
        if verdict is not None:
            results.append(_result(asset, verdict))
    return _document(results, qavach_version)


def evaluate_fail_on_entries(
    entries: Iterable[Mapping[str, Any]], fail_on: Iterable[str]
) -> tuple[bool, list[str]]:
    """`evaluate_fail_on` over stored entries."""
    wanted = set(fail_on)
    bad = wanted - FAIL_ON_TOKENS
    if bad:
        raise ValueError(f"unknown --fail-on value(s) {sorted(bad)}; use {sorted(FAIL_ON_TOKENS)}")
    reasons = [
        f"{e['bom_ref']} matches {sorted({e['finding_class'], e['band']} & wanted)}"
        for e in entries
        if {e["finding_class"], e["band"]} & wanted
    ]
    return bool(reasons), reasons


def evaluate_fail_on(
    items: Sequence[RegisterInput], fail_on: Iterable[str]
) -> tuple[bool, list[str]]:
    """`(should_fail, reasons)`. An unknown token is an error, not a silent pass:
    a typo in a CI gate must not disable the gate."""
    wanted = set(fail_on)
    bad = wanted - FAIL_ON_TOKENS
    if bad:
        raise ValueError(f"unknown --fail-on value(s) {sorted(bad)}; use {sorted(FAIL_ON_TOKENS)}")
    reasons: list[str] = []
    for item in items:
        hits = {item.asset.finding_class.value, item.score.band.value} & wanted
        if hits:
            reasons.append(
                f"{bom_ref(item.asset.identity)} ({item.asset.algorithm_family}) "
                f"matches {sorted(hits)}"
            )
    return bool(reasons), reasons
