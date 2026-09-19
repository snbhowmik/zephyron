"""T-090..T-098 - CBOM export (schema-valid, no risk data: invariant I5), the
Risk Register, SARIF gating, and detached signing."""

from __future__ import annotations

import copy
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from qavach_core.export import (
    DOCUMENTED_PROPERTIES,
    FAIL_ON_TOKENS,
    bom_ref,
    build_cbom,
    build_sarif,
    cbom_violations,
    evaluate_fail_on,
    generate_signer,
    sign_export,
    verify_export,
)
from qavach_core.model.enums import FindingClass

ROOT = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("schema_check", ROOT / "scripts/schema_check.py")
assert _spec and _spec.loader
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

CBOM, REGISTER, ITEMS = sc.sample_documents()
CBOM_VALIDATOR = sc.cbom_validator()
REGISTER_VALIDATOR = sc.register_validator()


# ---- T-090 / T-091: schema validity and I5 ----


def test_the_cbom_validates_against_the_official_cyclonedx_1_7_schema_offline() -> None:
    assert sc.errors_of(CBOM_VALIDATOR, CBOM) == []
    assert CBOM["specVersion"] == "1.7" and len(CBOM["components"]) == 9


def test_the_schema_actually_rejects_an_invalid_document() -> None:
    bad = copy.deepcopy(CBOM)
    bad["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "not-a-primitive"
    assert sc.errors_of(CBOM_VALIDATOR, bad)


def test_I5_the_cbom_contains_no_risk_data_anywhere() -> None:
    assert cbom_violations(CBOM) == []
    text = json.dumps(CBOM).lower()
    for word in (
        "mosca",
        "caraf",
        "urgency",
        "roadmap",
        "expected_value",
        "z_effective",
        "outcome",
    ):
        assert word not in text, word


def test_I5_the_register_is_where_the_risk_data_lives() -> None:
    text = json.dumps(REGISTER).lower()
    for word in ("mosca", "band", "outcome", "z_effective", "expected_value"):
        assert word in text, word


@pytest.mark.parametrize(
    "prop",
    [
        {"name": "qavach:risk-score", "value": "9"},
        {"name": "qavach:notes", "value": "undocumented"},
        {"name": "acme:mosca-gap", "value": "3"},
        {"name": "vendor:priority", "value": "high"},
        {"name": "x:recommendation", "value": "migrate"},
    ],
)
def test_the_purity_check_rejects_risk_vocabulary_and_undocumented_properties(
    prop: dict[str, str],
) -> None:
    polluted = copy.deepcopy(CBOM)
    polluted["components"][0]["properties"].append(prop)
    assert cbom_violations(polluted)


def test_a_purl_on_a_cryptographic_asset_is_rejected() -> None:
    polluted = copy.deepcopy(CBOM)
    polluted["components"][0]["purl"] = "pkg:generic/rsa@2048"
    assert any("purl" in v for v in cbom_violations(polluted))
    assert not any("purl" in c for c in CBOM["components"])


def test_only_the_documented_qavach_properties_are_ever_emitted() -> None:
    names = {
        p["name"]
        for section in (CBOM["metadata"], *CBOM["components"])
        for p in section.get("properties", [])
        if p["name"].startswith("qavach:")
    }
    assert names <= DOCUMENTED_PROPERTIES and names


def test_the_documented_set_matches_docs_custom_properties_md_in_both_directions() -> None:
    assert sc.documented_in_markdown() == set(DOCUMENTED_PROPERTIES)


def test_the_schema_check_script_passes_and_would_fail_on_pollution() -> None:
    assert sc.run_checks() == []


# ---- mapping correctness ----


def _component(family: str, param: str | None = None):  # type: ignore[no-untyped-def]
    for c in CBOM["components"]:
        if c["name"] == (f"{family}-{param}" if param else family):
            return c
    raise AssertionError(family)


def test_bom_refs_are_unique_deterministic_and_derived_from_identity() -> None:
    refs = [c["bom-ref"] for c in CBOM["components"]]
    assert len(refs) == len(set(refs))
    assert refs == sorted(refs)
    for item in ITEMS:
        assert bom_ref(item.asset.identity) in refs


def test_occurrences_map_to_evidence_with_line_numbers_from_source_and_file_loci() -> None:
    rsa = _component("RSASSA-PKCS1", "2048")
    occ = {o["location"]: o for o in rsa["evidence"]["occurrences"]}
    assert occ["src/Auth.java"]["line"] == 42
    assert "pay.acme.in:443" in occ and "line" not in occ["pay.acme.in:443"]
    assert "protocol=tls" in occ["pay.acme.in:443"]["additionalContext"]
    md5 = _component("MD5")
    assert md5["evidence"]["occurrences"][0]["line"] == 6  # FileLocus.offset carries the line


def test_provenance_maps_to_identity_methods_with_the_schema_technique_vocabulary() -> None:
    rsa = _component("RSASSA-PKCS1", "2048")
    identity = rsa["evidence"]["identity"][0]
    assert identity["field"] == "name" and identity["confidence"] == 1.0  # concluded from RUNTIME
    techniques = {m["technique"] for m in identity["methods"]}
    assert techniques == {"instrumentation", "ast-fingerprint"}
    tool_refs = {t["bom-ref"] for t in CBOM["metadata"]["tools"]["components"]}
    assert set(identity["tools"]) <= tool_refs


def test_a_family_the_registry_does_not_list_is_omitted_rather_than_breaking_the_schema() -> None:
    unk = _component("Vendor-Proprietary-Cipher")
    assert "algorithmFamily" not in unk["cryptoProperties"]["algorithmProperties"]
    assert sc.errors_of(CBOM_VALIDATOR, CBOM) == []


def test_functions_and_primitives_follow_the_asset_function() -> None:
    assert (
        _component("ML-KEM", "768")["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
    )
    aes_gcm = _component("AES", "256")["cryptoProperties"]["algorithmProperties"]
    assert aes_gcm["primitive"] == "ae" and aes_gcm["mode"] == "gcm"
    assert (
        _component("AES", "128")["cryptoProperties"]["algorithmProperties"]["primitive"]
        == "block-cipher"
    )


def test_the_export_is_deterministic_and_the_serial_number_tracks_content() -> None:
    kwargs = dict(
        timestamp=datetime(2026, 9, 20, 9, 0, tzinfo=UTC),
        qavach_version="0.1.0",
        known_families=sc.known_families(),
    )
    a = build_cbom(sc.sample_assets(), **kwargs)
    b = build_cbom(list(reversed(sc.sample_assets())), **kwargs)
    assert a == b and json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    c = build_cbom(sc.sample_assets()[:-1], **kwargs)
    assert c["serialNumber"] != a["serialNumber"]


def test_scope_is_recorded_and_is_a_query_over_the_reconciled_set() -> None:
    system_scope = build_cbom(
        sc.sample_assets()[:3],
        timestamp=datetime(2026, 9, 20, tzinfo=UTC),
        qavach_version="0.1.0",
        scope="system",
        known_families=sc.known_families(),
    )
    assert {"name": "qavach:scope", "value": "system"} in system_scope["metadata"]["properties"]
    assert len(system_scope["components"]) == 3


# ---- T-092: the Risk Register ----


def test_the_register_validates_against_its_json_schema() -> None:
    assert sc.errors_of(REGISTER_VALIDATOR, REGISTER) == []


def test_every_register_entry_references_a_cbom_component_and_vice_versa() -> None:
    refs = {c["bom-ref"] for c in CBOM["components"]}
    assert {e["bom_ref"] for e in REGISTER["entries"]} == refs


def test_I8_unknown_is_counted_separately_as_a_coverage_failure_never_as_safe() -> None:
    s = REGISTER["summary"]
    assert s["coverage_failures"] == 1 == s["by_finding_class"]["unknown"]
    assert (
        s["total"] == 9 and sum(s["by_finding_class"].values()) == s["total"]
    )  # denominator shown
    unknown = next(e for e in REGISTER["entries"] if e["finding_class"] == "unknown")
    assert unknown["band"] == "coverage-gap" and unknown["outcome"] is None


def test_every_entry_has_a_reason_and_scored_ones_carry_cited_explanations() -> None:
    for e in REGISTER["entries"]:
        assert e["reason"].strip()
        for x in e["explanations"]:
            assert all(p["basis"] for p in x["policy"])


def test_the_register_states_its_policy_snapshot_scenario_and_heuristics() -> None:
    assert (
        len(REGISTER["policy"]["snapshot_id"]) == 64
        and REGISTER["policy"]["z_scenario"] == "nominal"
    )
    assert (
        "heuristics" in REGISTER["heuristics_notice"]
        or "heuristic" in REGISTER["heuristics_notice"]
    )
    scored = next(e for e in REGISTER["entries"] if e["mosca"])
    assert scored["mosca"]["y_is_heuristic"] is True


def test_the_register_is_deterministic() -> None:
    _, again, _ = sc.sample_documents()
    assert json.dumps(again, sort_keys=True) == json.dumps(REGISTER, sort_keys=True)


def test_the_register_schema_rejects_a_missing_reason_and_a_bad_snapshot_id() -> None:
    bad = copy.deepcopy(REGISTER)
    del bad["entries"][0]["reason"]
    assert sc.errors_of(REGISTER_VALIDATOR, bad)
    bad2 = copy.deepcopy(REGISTER)
    bad2["policy"]["snapshot_id"] = "nope"
    assert sc.errors_of(REGISTER_VALIDATOR, bad2)


# ---- T-096: SARIF and --fail-on ----


def test_sarif_levels_follow_the_finding_classes_and_omit_informational_ones() -> None:
    sarif = build_sarif(ITEMS, qavach_version="0.1.0")
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    by_rule = {r["ruleId"] for r in results}
    assert by_rule <= {"QAVACH001", "QAVACH002", "QAVACH003"}
    assert {r["level"] for r in results if r["ruleId"] == "QAVACH002"} == {"error"}
    assert {r["level"] for r in results if r["ruleId"] == "QAVACH003"} == {"note"}
    grover_or_safe = {
        bom_ref(i.asset.identity)
        for i in ITEMS
        if i.asset.finding_class in (FindingClass.GROVER_AFFECTED, FindingClass.QUANTUM_SAFE)
    }
    assert not grover_or_safe & {r["properties"]["bom-ref"] for r in results}


def test_sarif_results_carry_a_location_and_the_bom_ref() -> None:
    for r in build_sarif(ITEMS, qavach_version="0.1.0")["runs"][0]["results"]:
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert r["properties"]["bom-ref"].startswith("crypto/algo/")


def test_fail_on_gates_by_class_or_band_and_explains_why() -> None:
    fail, reasons = evaluate_fail_on(ITEMS, ["classical-weak"])
    assert fail and len(reasons) == 2 and all("classical-weak" in r for r in reasons)
    assert evaluate_fail_on(ITEMS, ["overdue"])[0]
    assert evaluate_fail_on([], ["quantum-vulnerable"]) == (False, [])


def test_I8_a_pipeline_can_gate_on_unclassified_assets() -> None:
    fail, reasons = evaluate_fail_on(ITEMS, ["unknown"])
    assert fail and len(reasons) == 1


def test_a_typo_in_fail_on_is_an_error_not_a_silently_disabled_gate() -> None:
    with pytest.raises(ValueError, match="unknown --fail-on"):
        evaluate_fail_on(ITEMS, ["quantum-vulnrable"])
    assert "quantum-vulnerable" in FAIL_ON_TOKENS


def test_a_clean_estate_passes_the_gate() -> None:
    safe = [i for i in ITEMS if i.asset.finding_class is FindingClass.QUANTUM_SAFE]
    assert evaluate_fail_on(safe, ["quantum-vulnerable", "classical-weak", "unknown"]) == (
        False,
        [],
    )


# ---- T-097: detached signatures ----


DATA = json.dumps(CBOM, sort_keys=True).encode()


def test_an_ml_dsa_65_signature_verifies_and_leaves_the_cbom_untouched() -> None:
    key = generate_signer()
    envelope = sign_export(DATA, key, key_id="k1")
    assert envelope["algorithm"] == "ML-DSA-65" and envelope["standard"] == "FIPS 204"
    assert envelope["limitation"] is None
    assert verify_export(DATA, envelope)
    assert (
        sc.errors_of(CBOM_VALIDATOR, json.loads(DATA)) == []
    )  # export unchanged, still schema-valid


def test_tampering_truncation_and_substitution_all_fail_verification() -> None:
    envelope = sign_export(DATA, generate_signer())
    assert not verify_export(DATA + b" ", envelope)
    assert not verify_export(DATA[:-1], envelope)
    assert not verify_export(DATA.replace(b"RSASSA", b"RSAXXX", 1), envelope)
    other = sign_export(DATA, generate_signer())
    forged = {**envelope, "public_key": other["public_key"]}
    assert not verify_export(DATA, forged)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.pop("signature"),
        lambda e: e.__setitem__("signature", "!!!not base64!!!"),
        lambda e: e.__setitem__("algorithm", "ROT13"),
        lambda e: e.__setitem__("format", "other/1"),
        lambda e: e.__setitem__("public_key", ""),
        lambda e: e.__setitem__("signed_bytes", -1),
    ],
)
def test_a_hostile_envelope_never_raises_and_never_verifies(mutate) -> None:  # type: ignore[no-untyped-def]
    envelope = sign_export(DATA, generate_signer())
    mutate(envelope)
    assert verify_export(DATA, envelope) is False


def test_the_ed25519_fallback_states_its_limitation_instead_of_downgrading_silently() -> None:
    key = generate_signer(prefer="Ed25519")
    envelope = sign_export(DATA, key)
    assert envelope["algorithm"] == "Ed25519"
    assert "quantum-vulnerable" in envelope["limitation"] and verify_export(DATA, envelope)


def test_the_ml_dsa_signature_has_the_fips_204_size() -> None:
    import base64

    envelope = sign_export(DATA, generate_signer())
    assert len(base64.b64decode(envelope["signature"])) == 3309  # matches performance.yaml
    assert len(base64.b64decode(envelope["public_key"])) == 1952


# ---- T-093: the CycloneDX 1.6 downgrade ----


def test_the_1_6_downgrade_validates_against_the_official_1_6_schema_offline() -> None:
    from qavach_core.export import downgrade_to_1_6

    doc, losses = downgrade_to_1_6(CBOM)
    assert doc["specVersion"] == "1.6"
    assert sc.errors_of(sc.cbom_1_6_validator(), doc) == []
    assert cbom_violations(doc) == []
    assert doc["serialNumber"] != CBOM["serialNumber"]  # it is a different document


def test_every_field_lost_in_the_downgrade_is_listed_never_dropped_silently() -> None:
    from qavach_core.export import downgrade_to_1_6

    doc, losses = downgrade_to_1_6(CBOM)
    dropped = [
        c["name"]
        for c in CBOM["components"]
        if "algorithmFamily" in c["cryptoProperties"]["algorithmProperties"]
    ]
    assert len(losses) == len(dropped) == 8  # all but the unlisted-family asset
    assert all("algorithmFamily" in x for x in losses)
    assert all(
        "algorithmFamily" not in c["cryptoProperties"]["algorithmProperties"]
        for c in doc["components"]
    )
    assert {"name": "qavach:downgraded-from", "value": "1.7"} in doc["metadata"]["properties"]


def test_the_downgrade_does_not_mutate_the_original() -> None:
    from qavach_core.export import downgrade_to_1_6

    before = json.dumps(CBOM, sort_keys=True)
    downgrade_to_1_6(CBOM)
    assert json.dumps(CBOM, sort_keys=True) == before
    assert CBOM["specVersion"] == "1.7"


def test_the_1_7_document_is_not_valid_as_1_6_which_is_why_the_downgrade_exists() -> None:
    as_16 = copy.deepcopy(CBOM)
    as_16["specVersion"] = "1.6"
    assert sc.errors_of(sc.cbom_1_6_validator(), as_16)  # algorithmFamily is not a 1.6 property
