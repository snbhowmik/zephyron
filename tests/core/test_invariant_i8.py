"""T-015a — invariant I8 (CLAUDE.md §2): UNKNOWN is a finding class and
never renders as safe. No aggregation/UI layer exists yet to test this
against directly, so this locks in the foundational contract those future
layers must build on.
"""

from __future__ import annotations

import pytest
from qavach_core.model.enums import FindingClass
from qavach_core.risk.classify import (
    FINDING_CLASS_TOKEN,
    aggregate_by_finding_class,
    is_safe_finding_class,
)


def test_every_finding_class_has_a_token() -> None:
    assert set(FINDING_CLASS_TOKEN) == set(FindingClass)


def test_unknown_token_is_never_the_safe_token() -> None:
    assert (
        FINDING_CLASS_TOKEN[FindingClass.UNKNOWN] != FINDING_CLASS_TOKEN[FindingClass.QUANTUM_SAFE]
    )
    assert FINDING_CLASS_TOKEN[FindingClass.UNKNOWN] != "safe"


def test_only_quantum_safe_is_safe() -> None:
    for fc in FindingClass:
        expected = fc is FindingClass.QUANTUM_SAFE
        assert is_safe_finding_class(fc) == expected


def test_unknown_is_never_safe() -> None:
    assert not is_safe_finding_class(FindingClass.UNKNOWN)


def test_grover_affected_is_informational_not_safe() -> None:
    """GROVER_AFFECTED is "never rendered as migrate now" (invariant I1)
    but that does not make it "safe" either — it is its own category."""
    assert not is_safe_finding_class(FindingClass.GROVER_AFFECTED)
    assert FINDING_CLASS_TOKEN[FindingClass.GROVER_AFFECTED] != "safe"


@pytest.mark.parametrize("unknown_count", [0, 1, 5, 134])
def test_unknown_assets_never_contribute_to_the_safe_bucket(unknown_count: int) -> None:
    """Direct regression test for the competitor failure mode IDEATION.md
    §2.2c documents: 134 unknown-bit keys coloured as safe."""
    finding_classes = [FindingClass.UNKNOWN] * unknown_count + [FindingClass.QUANTUM_SAFE] * 10
    counts = aggregate_by_finding_class(finding_classes)
    assert counts[FindingClass.UNKNOWN] == unknown_count
    assert counts[FindingClass.QUANTUM_SAFE] == 10  # never inflated by the UNKNOWN assets


def test_aggregate_always_includes_every_class_even_at_zero() -> None:
    """An aggregate over an empty or all-safe asset set must not silently
    omit UNKNOWN's key — a coverage failure of zero is still reportable,
    an absent key is not."""
    counts = aggregate_by_finding_class([])
    assert counts[FindingClass.UNKNOWN] == 0
    assert set(counts) == set(FindingClass)
