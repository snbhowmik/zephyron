"""T-063 - Y, a labelled planning heuristic."""

from __future__ import annotations

import pytest
from _policy import real_policy
from qavach_core.model.enums import MigrationAuthority
from qavach_core.model.locus import FileLocus, HsmLocus, NetworkLocus, SourceLocus
from qavach_core.risk import EffortFacts, estimate_y

POLICY = real_policy()
SRC = SourceLocus(repo="r", commit="c", path="a.py", start_line=1, end_line=1)


def _y(loci, **kw):  # type: ignore[no-untyped-def]
    kw.setdefault("authority", MigrationAuthority.SELF)
    kw.setdefault("occurrence_count", len(loci))
    return estimate_y(loci, policy=POLICY, **kw)


def test_a_plain_source_change_is_the_base_effort() -> None:
    e = _y([SRC])
    assert e.years == 0.25 and e.applied == () and e.base_locus_kind == "source"


def test_every_estimate_is_labelled_a_heuristic() -> None:
    assert _y([SRC]).explanation.heuristic is True


def test_base_is_the_max_over_loci_not_the_sum() -> None:
    e = _y([SRC, NetworkLocus(host="h", port=443, sni=None, protocol="tls")])
    assert e.base_years == 0.5 and e.base_locus_kind == "network"


def test_an_hsm_locus_is_hardware_bound_automatically() -> None:
    e = _y([HsmLocus(module_path="/lib/x.so", slot_ref="0")])
    assert ("hardware_bound", 5.0) in e.applied and e.years == 1.0 * 5.0


def test_a_vendor_asset_takes_the_saas_multiplier() -> None:
    assert _y([SRC], authority=MigrationAuthority.VENDOR).years == 0.25 * 6.0


def test_multipliers_compose() -> None:
    e = _y([SRC], facts=EffortFacts(library_without_pqc=True, wire_format_change=True))
    assert e.years == pytest.approx(0.25 * 3.0 * 2.5)
    assert {n for n, _ in e.applied} == {"library_without_pqc", "wire_format_change"}


def test_occurrence_count_over_the_threshold_multiplies() -> None:
    assert _y([SRC], occurrence_count=50).years == 0.25
    assert _y([SRC], occurrence_count=51).years == 0.25 * 1.5


def test_a_factor_that_is_not_known_is_not_applied_and_the_explanation_says_which_were() -> None:
    e = _y([FileLocus(path="/a", offset=0)], facts=EffortFacts(high_handshake_frequency=True))
    assert e.explanation.inputs["known_factors"] == ["high_handshake_frequency"]
    assert any("x1.5 high_handshake_frequency" in s for s in e.explanation.steps)


def test_every_applied_multiplier_cites_its_basis() -> None:
    e = _y([SRC], authority=MigrationAuthority.VENDOR, facts=EffortFacts(library_without_pqc=True))
    cited = {p.path: p.basis for p in e.explanation.policy}
    assert cited["migration_effort.multipliers.third_party_saas"]
    assert cited["migration_effort.multipliers.library_without_pqc"]


def test_no_loci_is_an_error_not_a_zero() -> None:
    with pytest.raises(ValueError):
        _y([])
