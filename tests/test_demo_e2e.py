"""The whole stack on REAL recorded scanner output (T-024 corpus): assemble ->
bind -> score -> recommend -> roadmap -> export, with the CBOM validated against
the official CycloneDX 1.7 schema. These assertions are read off the real run."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/demo.py")
assert _spec and _spec.loader
import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)


@pytest.fixture(scope="module")
def out(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("demo")
    demo.build_demo(directory)
    return directory


@pytest.fixture(scope="module")
def summary(out: Path) -> dict:  # type: ignore[type-arg]
    return json.loads((out / "summary.json").read_text())


def test_the_real_recorded_output_exports_a_schema_valid_cbom_with_no_risk_data(
    summary: dict,
) -> None:  # type: ignore[type-arg]
    assert summary["cbom_valid"] is True and summary["cbom_problems"] == []


def test_conservation_no_scanner_claim_is_lost_between_collector_and_asset(summary: dict) -> None:  # type: ignore[type-arg]
    assert summary["claims_in"] == summary["occurrences_out"] > 50


def test_I4_reconciliation_merges_across_tools(out: Path) -> None:
    cbom = json.loads((out / "cbom.cdx.json").read_text())
    md5 = [c for c in cbom["components"] if c["name"].startswith("MD5")]
    assert len(md5) == 1  # OQ-18: cdxgen + cbomkit + Opengrep -> one asset
    collectors = {
        o["additionalContext"].split("collector=")[1].split()[0]
        for o in md5[0]["evidence"]["occurrences"]
    }
    assert len(collectors) >= 3


def test_every_scanner_contributed_to_the_inventory(out: Path) -> None:
    cbom = json.loads((out / "cbom.cdx.json").read_text())
    tools = {t["name"] for t in cbom["metadata"]["tools"]["components"]}
    assert {
        "source_scan.cdxgen",
        "source_scan.cbomkit",
        "source_scan.opengrep",
        "sbom.syft",
        "runtime.tracebom",
    } <= tools


def test_the_four_finding_classes_and_unknown_are_all_reported_separately(summary: dict) -> None:  # type: ignore[type-arg]
    classes = summary["by_finding_class"]
    assert {"quantum-vulnerable", "classical-weak", "grover-affected", "quantum-safe"} <= set(
        classes
    )
    assert summary["coverage_failures"] == classes.get("unknown", 0)


def test_I8_the_register_splits_coverage_failures_by_evidence_kind(out: Path) -> None:
    register = json.loads((out / "risk-register.json").read_text())
    s = register["summary"]
    assert 0 < s["coverage_failures_capability_only"] <= s["coverage_failures"]
    assert sum(s["by_finding_class"].values()) == s["total"]


def test_no_asset_is_left_unassigned_when_the_scan_target_is_bound(summary: dict) -> None:  # type: ignore[type-arg]
    assert summary["unassigned"] == 0


def test_a_mutual_dependency_between_two_systems_surfaces_as_hybrid_bridges(summary: dict) -> None:  # type: ignore[type-arg]
    assert summary["bridges"], (
        "the demo dataset must contain a hybrid-bridge cycle (Phase 7 exit criterion)"
    )
    assert all(len(members) == 2 for members in summary["bridges"])


def test_the_register_ties_back_to_the_cbom(out: Path) -> None:
    cbom = json.loads((out / "cbom.cdx.json").read_text())
    register = json.loads((out / "risk-register.json").read_text())
    assert {e["bom_ref"] for e in register["entries"]} == {c["bom-ref"] for c in cbom["components"]}
    assert register["cbom"]["serial_number"] == cbom["serialNumber"]


def test_the_demo_is_reproducible_byte_for_byte(out: Path, tmp_path: Path) -> None:
    demo.build_demo(tmp_path)
    for name in ("cbom.cdx.json", "risk-register.json", "findings.sarif"):
        assert (tmp_path / name).read_bytes() == (out / name).read_bytes()


def test_the_sarif_gates_on_what_the_real_run_found(out: Path) -> None:
    sarif = json.loads((out / "findings.sarif").read_text())
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert "error" in levels and sarif["version"] == "2.1.0"


def test_I2_the_planted_root_ca_and_tls_leaf_share_an_algorithm_but_not_an_urgency(
    out: Path,
) -> None:
    """T-120 / OQ-20: the demonstration the whole risk model exists to make. Same
    RSA-2048, opposite Mosca inputs, and they stay two assets."""
    register = json.loads((out / "risk-register.json").read_text())
    cbom = json.loads((out / "cbom.cdx.json").read_text())
    names = {
        c["bom-ref"]: c["name"]
        for c in cbom["components"]
        if c["cryptoProperties"]["assetType"] == "certificate"
    }
    assert len(names) == 2
    by_role = {}
    for e in register["entries"]:
        if e["bom_ref"] in names and e["system_id"] == "payments-core":
            by_role["root" if "Root" in names[e["bom_ref"]] else "leaf"] = e
    root, leaf = by_role["root"], by_role["leaf"]
    assert root["mosca"]["x_integ_years"] > 15 and leaf["mosca"]["x_integ_years"] == 0
    assert root["mosca"]["gap_years"] > 0 > leaf["mosca"]["gap_years"]
    assert root["band"] == "overdue"
