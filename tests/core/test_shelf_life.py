"""T-061 - X per function class. The property tests here are the invariant-I2
guard: HNDL is confidentiality-only, and a long-lived signer outranks an
ephemeral one."""

from __future__ import annotations

import itertools

import pytest
from _policy import make_system, real_policy
from qavach_core.model.enums import CryptoFunction
from qavach_core.risk import derive_from_consumers, shelf_life_years

POLICY = real_policy()
CONFIDENTIALITY = [
    CryptoFunction.KEY_ENCAPSULATION,
    CryptoFunction.KEY_AGREEMENT,
    CryptoFunction.ENCRYPTION,
]
AUTHENTICITY = [CryptoFunction.SIGNATURE, CryptoFunction.MAC, CryptoFunction.HASH]


@pytest.mark.parametrize("function", CONFIDENTIALITY)
@pytest.mark.parametrize("retention", [0.0, 1.0, 7.0, 25.0])
def test_confidentiality_x_is_the_data_retention(
    function: CryptoFunction, retention: float
) -> None:
    s = shelf_life_years(function, system=make_system(retention_years=retention), policy=POLICY)
    assert (s.x_conf, s.x_integ, s.basis, s.complete) == (
        retention,
        0.0,
        "hndl:data-retention",
        True,
    )


@pytest.mark.parametrize("function", AUTHENTICITY)
def test_hndl_never_applies_to_signatures_macs_or_hashes(function: CryptoFunction) -> None:
    """Even with enormous data retention, an authenticity function has no
    confidentiality shelf life (I2)."""
    s = shelf_life_years(
        function,
        system=make_system(retention_years=99.0),
        policy=POLICY,
        artefact_lifetime_years=20,
    )
    assert s.x_conf == 0.0


@pytest.mark.parametrize("function", AUTHENTICITY)
def test_ephemeral_artefacts_have_zero_shelf_life(function: CryptoFunction) -> None:
    for lifetime in (None, 0.0, 90 / 365, 1.0):  # 1.0 is the threshold, inclusive
        s = shelf_life_years(
            function,
            system=make_system(retention_years=25),
            policy=POLICY,
            artefact_lifetime_years=lifetime,
        )
        assert (s.x_conf, s.x_integ, s.basis) == (0.0, 0.0, "authenticity:ephemeral"), lifetime


@pytest.mark.parametrize("function", AUTHENTICITY)
def test_long_lived_artefacts_take_their_trust_lifetime(function: CryptoFunction) -> None:
    s = shelf_life_years(function, system=make_system(), policy=POLICY, artefact_lifetime_years=20)
    assert (s.x_conf, s.x_integ, s.basis) == (0.0, 20, "tnfl:long-lived-artefact")


def test_I2_property_a_long_lived_signer_always_outranks_an_ephemeral_one() -> None:
    """For the same function and system, X is strictly larger for any
    long-lived lifetime than for any ephemeral one - across a grid of
    retentions and lifetimes - and non-decreasing in the lifetime."""
    for retention, function in itertools.product([0, 1, 5, 25], AUTHENTICITY):
        system = make_system(retention_years=retention)
        ephemeral = max(
            shelf_life_years(function, system=system, policy=POLICY, artefact_lifetime_years=life).x
            for life in (None, 0.0, 0.25, 1.0)
        )
        previous = ephemeral
        for lifetime in (1.01, 2, 5, 10, 25, 40):
            x = shelf_life_years(
                function, system=system, policy=POLICY, artefact_lifetime_years=lifetime
            ).x
            assert x > ephemeral
            assert x >= previous
            previous = x


def test_archival_artefacts_take_retention_as_their_lifetime() -> None:
    """RFC 3161 timestamps / audit logs: the caller passes retention, so the
    ephemeral exemption does not swallow them (ARCH.md 7.2)."""
    s = shelf_life_years(
        CryptoFunction.SIGNATURE,
        system=make_system(retention_years=10),
        policy=POLICY,
        artefact_lifetime_years=10,
    )
    assert s.x_integ == 10


def test_a_derived_key_inherits_the_maximum_of_its_consumers_upward_only() -> None:
    conf = shelf_life_years(
        CryptoFunction.ENCRYPTION, system=make_system(retention_years=8), policy=POLICY
    )
    sig = shelf_life_years(
        CryptoFunction.SIGNATURE, system=make_system(), policy=POLICY, artefact_lifetime_years=15
    )
    derived = derive_from_consumers([conf, sig], policy=POLICY)
    assert (derived.x_conf, derived.x_integ) == (8, 15)
    child = shelf_life_years(
        CryptoFunction.ENCRYPTION, system=make_system(retention_years=1), policy=POLICY
    )
    assert child.x_conf == 1  # a child inherits NOTHING from its parent


def test_a_derived_key_with_no_known_consumer_is_a_coverage_gap_not_zero_risk() -> None:
    s = shelf_life_years(CryptoFunction.KDF, system=make_system(), policy=POLICY)
    assert s.x == 0 and s.complete is False and s.basis == "derived:no-known-consumers"


def test_an_unknown_function_is_scored_at_its_worst_plausible_reading() -> None:
    s = shelf_life_years(
        None, system=make_system(retention_years=12), policy=POLICY, artefact_lifetime_years=3
    )
    assert (s.x_conf, s.x_integ, s.complete) == (12, 3, False)


def test_the_explanation_carries_its_inputs_and_the_cited_threshold() -> None:
    s = shelf_life_years(CryptoFunction.SIGNATURE, system=make_system(), policy=POLICY)
    d = s.explanation.to_dict()
    assert d["inputs"]["function"] == "signature"
    assert d["policy"][0]["path"] == "scoring.mosca.ephemeral_artefact_max_years"
    assert d["policy"][0]["basis"]
