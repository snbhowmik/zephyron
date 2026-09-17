"""T-016b, A-13 — the data-quality queue. Regression fixtures are the
exact numbers IDEATION.md §2.2b documents from a shipping competitor's
dashboard: 0-bit (34 assets), 2450-bit (1), 281-bit (1) "RSA" keys, and
'SHA reference in sublime_text...' captured as an algorithm name.
"""

from __future__ import annotations

import pytest
from qavach_core.normalize.quality import check_filename_shaped_name, check_modulus_plausibility

# --- IDEATION.md §2.2b's exact documented failure modes ---


def test_zero_bit_rsa_key_is_flagged() -> None:
    """0-bit (34 assets) in the competitor's own chart — IDEATION.md §2.2b:
    'almost certainly Ed25519 and PQC certificates being forced into an
    integer field that does not apply to them.'"""
    issue = check_modulus_plausibility("RSASSA-PKCS1", "0")
    assert issue is not None
    assert issue.kind == "zero_bit_key"


@pytest.mark.parametrize("implausible_bits", ["2450", "281"])
def test_nonsense_rsa_bit_lengths_are_flagged(implausible_bits: str) -> None:
    """'There is no 2450-bit or 281-bit RSA key. Those are parse
    artefacts.' (IDEATION.md §2.2b) — the exact two numbers named."""
    issue = check_modulus_plausibility("RSASSA-PKCS1", implausible_bits)
    assert issue is not None
    assert issue.kind == "implausible_modulus"


@pytest.mark.parametrize("real_but_weak_bits", ["512", "768", "1024"])
def test_weak_but_real_rsa_sizes_are_not_flagged_as_a_data_quality_issue(
    real_but_weak_bits: str,
) -> None:
    """512/768-bit RSA genuinely existed historically (ancient, weak, but
    real) — IDEATION.md §2.2b lists them in the same distribution as the
    nonsense values without calling them parse artefacts. Classifying them
    as CLASSICAL_WEAK is classify.py's job (T-015), not this one's — a
    weak key is not a data-quality problem."""
    assert check_modulus_plausibility("RSASSA-PKCS1", real_but_weak_bits) is None


@pytest.mark.parametrize("modern_bits", ["2048", "3072", "4096"])
def test_modern_rsa_sizes_are_plausible(modern_bits: str) -> None:
    assert check_modulus_plausibility("RSASSA-PKCS1", modern_bits) is None


def test_non_bit_length_parameter_sets_are_not_checked() -> None:
    """ML-DSA's parameter sets are names ("44", "65", "87" — which happen
    to be numeric strings but are NOT bit-lengths) vs SLH-DSA's
    ("SHA2-128s") — a family this table has no bit-length opinion on must
    not be checked at all, not silently flagged as implausible."""
    assert check_modulus_plausibility("SLH-DSA", "SHA2-128s") is None
    assert check_modulus_plausibility("ML-KEM", "768") is None  # not in PLAUSIBLE_MODULUS_BITS


def test_missing_parameter_set_is_not_a_data_quality_issue() -> None:
    """Absence is not the same as a bad value (ARCH.md §4.2's "never
    render 0 for not applicable" spirit) — an algorithm with no
    parameter_set at all (e.g. Ed25519 with no RSA-style bit-length) is
    not itself a quality problem."""
    assert check_modulus_plausibility("RSASSA-PKCS1", None) is None


# --- Filename-shaped names (IDEATION.md §2.2c) ---


def test_filename_captured_as_algorithm_name_is_flagged() -> None:
    """'SHA reference in sublime_text_build_4107_x64_setup.exe' rated NONE
    in the competitor's inventory — the filename leaked into what should
    have been an algorithm-name field."""
    issue = check_filename_shaped_name("sublime_text_build_4107_x64_setup.exe")
    assert issue is not None
    assert issue.kind == "filename_shaped_name"


@pytest.mark.parametrize(
    "path_like",
    [
        "Git-2.32.0-64-bit.exe",
        "some/nested/path/lib.so",
        r"C:\Windows\System32\crypt32.dll",
        "app.jar",
    ],
)
def test_various_filename_and_path_shapes_are_flagged(path_like: str) -> None:
    assert check_filename_shaped_name(path_like) is not None


@pytest.mark.parametrize("real_name", ["RSA", "ML-KEM-768", "AES-256-GCM", "SHA-256"])
def test_real_algorithm_names_are_not_flagged(real_name: str) -> None:
    assert check_filename_shaped_name(real_name) is None


def test_none_name_is_not_flagged() -> None:
    assert check_filename_shaped_name(None) is None
