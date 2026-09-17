"""T-016a — MigrationAuthority derivation (ARCH.md §4.1, invariant I9)."""

from __future__ import annotations

from qavach_core.model.enums import MigrationAuthority
from qavach_core.reconcile.authority import AuthorityContext, derive_migration_authority


def test_public_root_chain_with_all_third_party_loci_is_external_trust_anchor() -> None:
    """T-016a's required property test, ARCH.md §4.1's own worked example:
    IDEATION.md §2.2d — Sectigo RSA Code Signing CA, found only inside two
    downloaded installers. A cert chaining to a public root whose every
    locus is third-party software must never enter the roadmap (only SELF
    units do, ARCH.md §9.2 step 0)."""
    context = AuthorityContext(chains_to_public_root=True, all_loci_third_party=True)
    authority, basis = derive_migration_authority(context)
    assert authority == MigrationAuthority.EXTERNAL_TRUST_ANCHOR
    assert authority != MigrationAuthority.SELF  # the property T-016a actually cares about
    assert "public root" in basis


def test_public_root_chain_but_operator_owned_locus_is_not_external_trust_anchor() -> None:
    """The compound condition matters — chaining to a public root alone
    (e.g. an operator's own leaf cert issued by a public CA) is not
    automatically EXTERNAL_TRUST_ANCHOR; every locus must ALSO be
    third-party. An operator's own leaf cert, deployed in their own repo,
    is still theirs to migrate."""
    context = AuthorityContext(chains_to_public_root=True, all_loci_third_party=False)
    authority, _ = derive_migration_authority(context)
    assert authority != MigrationAuthority.EXTERNAL_TRUST_ANCHOR


def test_oem_firmware_is_vendor() -> None:
    context = AuthorityContext(is_oem_firmware_or_unoperated_saas=True)
    authority, basis = derive_migration_authority(context)
    assert authority == MigrationAuthority.VENDOR
    assert "OEM firmware" in basis or "SaaS" in basis


def test_npci_regime_is_regulator_gated() -> None:
    context = AuthorityContext(system_regulatory_regimes=frozenset({"npci"}))
    authority, basis = derive_migration_authority(context)
    assert authority == MigrationAuthority.REGULATOR_GATED
    assert "npci" in basis


def test_uidai_and_cca_regimes_are_regulator_gated() -> None:
    for regime in ("uidai", "cca-india-pki"):
        context = AuthorityContext(system_regulatory_regimes=frozenset({regime}))
        authority, _ = derive_migration_authority(context)
        assert authority == MigrationAuthority.REGULATOR_GATED


def test_unrelated_regulatory_regime_is_not_regulator_gated() -> None:
    """Only the three regimes ARCH.md §4.1 names externally specify the
    crypto. Some other regulatory tag (e.g. a generic "sebi-re" compliance
    flag) does not, by itself, mean the operator can't change the crypto."""
    context = AuthorityContext(system_regulatory_regimes=frozenset({"sebi-re"}))
    authority, _ = derive_migration_authority(context)
    assert authority != MigrationAuthority.REGULATOR_GATED


def test_operator_owned_locus_is_self() -> None:
    context = AuthorityContext(locus_in_operator_owned_context=True)
    authority, basis = derive_migration_authority(context)
    assert authority == MigrationAuthority.SELF
    assert "operator's own" in basis


def test_no_signal_at_all_is_unknown_never_defaults_to_self() -> None:
    """ARCH.md §4.1: UNKNOWN is the triage queue and "never defaults to
    SELF" — an asset with no derivation signal must not be silently
    assumed to be the operator's own."""
    context = AuthorityContext()
    authority, _ = derive_migration_authority(context)
    assert authority == MigrationAuthority.UNKNOWN
    assert authority != MigrationAuthority.SELF


def test_precedence_external_trust_anchor_beats_self_when_both_signalled() -> None:
    """ARCH.md §4.1 lists EXTERNAL_TRUST_ANCHOR's rule first — a
    (deliberately contradictory) context signalling both must resolve to
    the more specific compound condition, not the later, broader one."""
    context = AuthorityContext(
        chains_to_public_root=True,
        all_loci_third_party=True,
        locus_in_operator_owned_context=True,
    )
    authority, _ = derive_migration_authority(context)
    assert authority == MigrationAuthority.EXTERNAL_TRUST_ANCHOR
