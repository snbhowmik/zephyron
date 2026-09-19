"""T-109 - scan-to-scan drift. Pure: register entries in, a diff out."""

from __future__ import annotations

from typing import Any

from qavach_core.pipeline import diff_entries


def entry(ref: str, fc: str = "quantum-vulnerable", band: str = "planned", **over: Any) -> dict:
    return {
        "bom_ref": ref,
        "system_id": "s1",
        "finding_class": fc,
        "band": band,
        "outcome": "migrate",
        "migration_authority": "self",
        "disputed": False,
    } | over


def test_identical_scans_have_no_drift() -> None:
    entries = [entry("a"), entry("b", "quantum-safe", "not-applicable")]
    drift = diff_entries(entries, entries)
    assert drift.summary()["unchanged"] == 2
    assert not drift.added and not drift.removed and not drift.changed


def test_added_and_removed_are_keyed_by_asset_and_system() -> None:
    old = [entry("a"), entry("b")]
    new = [entry("a"), entry("c", "classical-weak", "overdue"), entry("a", system_id="s2")]
    drift = diff_entries(old, new)
    assert {e["bom_ref"] for e in drift.removed} == {"b"}
    assert {(e["bom_ref"], e["system_id"]) for e in drift.added} == {("c", "s1"), ("a", "s2")}
    # a new quantum-vulnerable or classical-weak finding is a new risk either way
    assert drift.summary()["added_risky"] == 2
    quiet = diff_entries([], [entry("g", "grover-affected", "not-applicable")])
    assert quiet.summary()["added_risky"] == 0  # informational, I1


def test_a_band_moving_toward_overdue_is_worsened_and_the_reverse_improved() -> None:
    drift = diff_entries([entry("a", band="planned")], [entry("a", band="overdue")])
    assert drift.changed[0].direction == "worsened"
    assert drift.changed[0].fields["band"] == ("planned", "overdue")
    back = diff_entries([entry("a", band="overdue")], [entry("a", band="imminent")])
    assert back.changed[0].direction == "improved"


def test_becoming_quantum_safe_is_an_improvement_but_unknown_never_is() -> None:
    fixed = diff_entries(
        [entry("a", band="planned")], [entry("a", "quantum-safe", "not-applicable")]
    )
    assert fixed.changed[0].direction == "improved"
    # I8: an asset that became UNKNOWN did not get safer - we lost sight of it.
    lost = diff_entries(
        [entry("a", band="overdue")], [entry("a", "unknown", "coverage-gap", outcome="")]
    )
    assert lost.changed[0].direction == "coverage"
    assert lost.summary()["improved"] == 0 and lost.summary()["coverage_changes"] == 1


def test_a_new_unknown_is_counted_as_a_coverage_failure_not_a_risk() -> None:
    drift = diff_entries([], [entry("u", "unknown", "coverage-gap")])
    s = drift.summary()
    assert s["added_coverage_failures"] == 1 and s["added_risky"] == 0


def test_a_non_band_change_is_reported_as_changed_not_worse() -> None:
    drift = diff_entries([entry("a")], [entry("a", disputed=True)])
    assert drift.changed[0].direction == "changed"
    assert drift.changed[0].fields == {"disputed": (False, True)}


def test_output_order_is_deterministic() -> None:
    a = diff_entries([], [entry("z"), entry("a"), entry("m")])
    b = diff_entries([], [entry("m"), entry("z"), entry("a")])
    assert [e["bom_ref"] for e in a.added] == ["a", "m", "z"] == [e["bom_ref"] for e in b.added]
