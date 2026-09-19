"""T-080..T-083 - PQC knowledge (FR-410 status guards, freshness, no invented
figures) and the recommendation engine."""

from __future__ import annotations

import copy
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml
from qavach_core.model.enums import CryptoFunction, FindingClass
from qavach_core.recommend import Constraints, KnowledgeError, PqcKnowledge, recommend

ROOT = Path(__file__).parent.parent.parent
ALT = yaml.safe_load((ROOT / "config/knowledge/pqc_alternatives.yaml").read_text())
PERF = yaml.safe_load((ROOT / "config/knowledge/performance.yaml").read_text())
K = PqcKnowledge.from_documents(ALT, PERF)
QV, CW, GR = (
    FindingClass.QUANTUM_VULNERABLE,
    FindingClass.CLASSICAL_WEAK,
    FindingClass.GROVER_AFFECTED,
)


def _rec(fc=QV, function=CryptoFunction.KEY_AGREEMENT, family="ECDH", also=False, **constraints):  # type: ignore[no-untyped-def]
    return recommend(
        finding_class=fc,
        also_quantum_vulnerable=also,
        function=function,
        algorithm_family=family,
        knowledge=K,
        constraints=Constraints(**constraints),
    )


# ---- T-080: the status truth (FR-410) ----


def test_the_standardisation_statuses_are_exactly_as_verified_on_2026_09_20() -> None:
    a = K.alternatives
    for key in ("ml-kem-768", "ml-dsa-65", "slh-dsa"):
        assert a[key].status == "final" and str(a[key].status_date) == "2024-08-13"
    assert a["lms-xmss"].status == "final" and a["lms-xmss"].standard == "NIST SP 800-208"
    assert a["hqc"].status == "selected-not-published" and str(a["hqc"].status_date) == "2025-03-11"
    assert a["fn-dsa"].status == "in-development" and a["fn-dsa"].standard == "FIPS 206"


def test_FR410_hqc_and_fn_dsa_are_never_usable_as_a_recommendation() -> None:
    assert not K.alternatives["hqc"].usable_as_recommendation
    assert not K.alternatives["fn-dsa"].usable_as_recommendation


@pytest.mark.parametrize("status", ["selected-not-published", "in-development"])
def test_FR410_a_data_edit_cannot_make_a_non_final_algorithm_recommendable(status: str) -> None:
    docs = copy.deepcopy(ALT)
    docs["alternatives"]["hqc"]["status"] = status
    docs["alternatives"]["hqc"]["usable_as_recommendation"] = True
    with pytest.raises(KnowledgeError, match="FR-410"):
        PqcKnowledge.from_documents(docs, PERF)


def test_every_entry_has_a_source_and_either_a_verification_date_or_a_reason() -> None:
    for alt in K.alternatives.values():
        assert alt.source_url.startswith("https://")
        assert alt.verified_on is not None or alt.unverified_reason


def test_an_unverified_entry_must_say_why() -> None:
    docs = copy.deepcopy(ALT)
    docs["alternatives"]["hqc"]["verified_on"] = None
    with pytest.raises(KnowledgeError, match="unverified_reason"):
        PqcKnowledge.from_documents(docs, PERF)


def test_a_missing_source_url_is_rejected() -> None:
    docs = copy.deepcopy(ALT)
    del docs["alternatives"]["hqc"]["source_url"]
    with pytest.raises(KnowledgeError, match="source_url"):
        PqcKnowledge.from_documents(docs, PERF)


# ---- T-081: freshness ----


def test_the_shipped_knowledge_is_fresh_on_the_day_it_was_verified() -> None:
    assert K.stale(date(2026, 9, 20)) == []


def test_an_entry_becomes_stale_after_180_days() -> None:
    assert K.stale(date(2026, 9, 20) + timedelta(days=180)) == []
    stale = K.stale(date(2026, 9, 20) + timedelta(days=181))
    assert "alternatives.ml-kem-768" in {name for name, _ in stale}
    assert all(age > 180 for _, age in stale)


def test_a_verified_on_in_the_future_is_flagged_not_trusted() -> None:
    assert K.stale(date(2026, 1, 1))  # every entry claims 2026-09-20 > today


def test_unverified_entries_are_listed_but_do_not_count_as_stale() -> None:
    assert "hybrid_guidance.national-security" in K.unverified()
    assert "hybrid_guidance.national-security" not in {n for n, _ in K.stale(date(2030, 1, 1))}


def test_the_freshness_script_fails_when_stale_and_passes_when_fresh() -> None:
    import subprocess
    import sys

    def run(day: str) -> int:
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/check_knowledge_freshness.py"), "--today", day],
            capture_output=True,
        ).returncode

    assert run("2026-09-21") == 0
    assert run("2027-06-01") == 1


# ---- T-083: no invented figures ----


def test_pqc_sizes_match_the_fips_parameter_tables() -> None:
    p = K.performance
    assert (
        p["kem.ML-KEM-768"].figures["public_key_bytes"],
        p["kem.ML-KEM-768"].figures["ciphertext_bytes"],
    ) == (1184, 1088)
    assert p["signature.ML-DSA-65"].figures["signature_bytes"] == 3309
    assert p["signature.SLH-DSA-SHA2-128s"].figures["signature_bytes"] == 7856
    assert p["signature.SLH-DSA-SHA2-256f"].figures["signature_bytes"] == 49856


def test_every_row_cites_a_source_and_a_basis() -> None:
    assert K.performance and all(
        r.source_url.startswith("https://") and r.basis for r in K.performance.values()
    )


def test_no_timing_is_invented_they_are_all_null_until_measured() -> None:
    timings = [v for r in K.performance.values() for k, v in r.figures.items() if k.endswith("_us")]
    assert timings and all(v is None for v in timings)


def test_a_timing_without_a_measurement_platform_is_rejected() -> None:
    docs = copy.deepcopy(PERF)
    docs["kem"]["ML-KEM-768"]["keygen_us"] = 42
    with pytest.raises(KnowledgeError, match="where it was measured"):
        PqcKnowledge.from_documents(ALT, docs)
    docs["kem"]["ML-KEM-768"]["measured_on"] = "test rig"
    PqcKnowledge.from_documents(ALT, docs)


def test_derived_tls_hybrid_figures_are_consistent_with_the_component_sizes() -> None:
    hybrid = PERF["tls_hybrid_key_share"]["X25519MLKEM768"]
    kem = K.performance
    assert (
        hybrid["client_key_share_bytes"] == 32 + kem["kem.ML-KEM-768"].figures["public_key_bytes"]
    )
    assert (
        hybrid["server_key_share_bytes"] == 32 + kem["kem.ML-KEM-768"].figures["ciphertext_bytes"]
    )


# ---- T-082: the engine ----


def test_key_establishment_gets_ml_kem_768_with_its_status_and_source() -> None:
    r = _rec()
    assert r.kind == "pqc" and r.primary is not None
    assert r.primary.name == "ML-KEM-768" and "Final (FIPS 203" in r.primary.status_text
    assert r.primary.verified_on == "2026-09-20" and r.primary.source_url.startswith(
        "https://csrc.nist.gov"
    )


def test_signing_gets_ml_dsa_65_and_the_lattice_diversity_option_is_slh_dsa() -> None:
    r = _rec(function=CryptoFunction.SIGNATURE, family="ECDSA", want_lattice_diversity=True)
    assert r.primary is not None and r.primary.name == "ML-DSA-65"
    assert [a.name for a in r.also_consider] == ["SLH-DSA"]


def test_firmware_signing_with_stateful_acceptable_gets_lms_xmss_with_the_state_warning() -> None:
    r = _rec(
        function=CryptoFunction.SIGNATURE,
        family="RSASSA-PKCS1",
        firmware_or_boot_signing=True,
        stateful_signatures_acceptable=True,
    )
    assert (
        r.primary is not None
        and r.primary.name == "LMS / XMSS"
        and "STATEFUL" in (r.primary.note or "")
    )


def test_firmware_signing_where_stateful_is_not_acceptable_stays_on_ml_dsa() -> None:
    r = _rec(
        function=CryptoFunction.SIGNATURE, family="RSASSA-PKCS1", firmware_or_boot_signing=True
    )
    assert r.primary is not None and r.primary.name == "ML-DSA-65"


def test_FR410_hqc_and_fn_dsa_only_ever_appear_as_watch_items_with_their_real_status() -> None:
    kem = _rec()
    assert [w.name for w in kem.watch] == ["HQC"]
    assert "Not a compliance claim" in kem.watch[0].status_text
    sig = _rec(function=CryptoFunction.SIGNATURE, family="ECDSA", signature_size_constrained=True)
    assert [w.name for w in sig.watch] == ["FN-DSA (Falcon)"]
    assert "not a published standard" in sig.watch[0].status_text
    for r in (kem, sig):
        assert r.primary is not None and r.primary.status == "final"
        assert all(a.status == "final" for a in r.also_consider)


def test_FR410_property_the_primary_is_final_for_every_quantum_vulnerable_combination() -> None:
    for function in (
        CryptoFunction.KEY_AGREEMENT,
        CryptoFunction.KEY_ENCAPSULATION,
        CryptoFunction.ENCRYPTION,
        CryptoFunction.SIGNATURE,
    ):
        for nss in (False, True):
            for size in (False, True):
                r = _rec(
                    function=function,
                    regimes=frozenset({"nss"} if nss else set()),
                    signature_size_constrained=size,
                    tls_in_transit=True,
                )
                assert r.applicable and r.primary is not None and r.primary.status == "final"
                assert r.primary.source_url and r.primary.status_text


def test_general_tls_transition_recommends_the_hybrid_group_citing_rfc_10024() -> None:
    r = _rec(tls_in_transit=True)
    assert [h.position for h in r.hybrid] == ["hybrid"] and r.hybrid[
        0
    ].recommend == "X25519MLKEM768"
    assert "RFC 10024" in r.hybrid[0].reason and r.hybrid[0].verified


def test_a_national_security_regime_states_its_position_pure_pqc_and_flags_it_unverified() -> None:
    r = _rec(tls_in_transit=True, regimes=frozenset({"nss"}))
    assert r.primary is not None and r.primary.name == "ML-KEM-1024"
    assert [h.position for h in r.hybrid] == [
        "pure-pqc"
    ]  # the regime's position wins over generic hybrid
    assert not r.hybrid[0].verified and "could not be retrieved" in (
        r.hybrid[0].unverified_reason or ""
    )


def test_the_size_cost_is_quantified_from_the_table_not_described_in_adjectives() -> None:
    r = _rec(function=CryptoFunction.SIGNATURE, family="ECDSA", signature_size_constrained=True)
    assert r.size_cost is not None
    assert (r.size_cost.incumbent_signature_bytes, r.size_cost.replacement_signature_bytes) == (
        64,
        3309,
    )
    assert r.size_cost.ratio == pytest.approx(51.7, abs=0.1)
    assert any(h.position == "flag-size-cost" for h in r.hybrid)


def test_archival_confidentiality_says_the_pqc_half_must_carry_the_weight() -> None:
    r = _rec(long_term_archival_confidentiality=True)
    assert any(h.position == "pqc-must-carry" for h in r.hybrid)


def test_I1_grover_is_information_never_a_migration() -> None:
    r = _rec(GR, function=CryptoFunction.ENCRYPTION, family="AES")
    assert r.kind == "informational" and r.primary is None
    assert "never a migrate-now finding" in r.reason


def test_I1_a_classically_weak_asset_gets_its_classical_fix_and_is_not_called_quantum() -> None:
    r = _rec(CW, function=CryptoFunction.HASH, family="MD5")
    assert r.kind == "classical-fix" and r.primary is None
    assert r.classical_fix is not None and "SHA-256" in r.classical_fix
    assert any("not a quantum finding" in n for n in r.notes)


def test_a_weak_asset_that_is_also_quantum_vulnerable_gets_both_the_fix_note_and_a_pqc_answer() -> (
    None
):
    r = _rec(CW, function=CryptoFunction.SIGNATURE, family="RSASSA-PKCS1", also=True)
    assert r.kind == "pqc" and r.primary is not None
    assert any("Broken today" in n for n in r.notes)


def test_quantum_safe_needs_nothing_and_unknown_cannot_be_advised() -> None:
    assert _rec(FindingClass.QUANTUM_SAFE).kind == "none"
    u = _rec(FindingClass.UNKNOWN)
    assert u.kind == "cannot-advise" and not u.applicable and "I8" in u.reason


def test_an_unknown_function_is_not_guessed_at() -> None:
    r = _rec(function=None)
    assert r.kind == "cannot-advise" and r.primary is None


def test_a_mac_or_hash_is_not_changed_by_shor() -> None:
    assert _rec(function=CryptoFunction.HASH, family="SHA-2").kind == "none"
