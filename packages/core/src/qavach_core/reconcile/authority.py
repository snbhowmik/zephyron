"""ARCH.md §4.1 — MigrationAuthority derivation (invariant I9). T-016a.

Placement note: ARCH.md §4.1 sits under "## 4. Canonical data model", not
under "## 6. Layer 3 — Reconciliation" — but the derivation logic itself
(given raw evidence about an asset, derive a canonical property) is the
same shape of work as reconciliation's identity/confidence-precedence
functions, and ARCH.md assigns no other home. Placed in `reconcile/` as a
judgement call, not a documented ARCH.md decision — see `NOTE.md §7`.

Only the rules ARCH.md §4.1 actually states are implemented. Deriving
"does this locus count as third-party" or "is this a regulator-specified
regime" from raw Locus/System data is NOT specified anywhere in ARCH.md —
this function takes those as already-decided boolean/set inputs rather
than inventing a heuristic ARCH.md never described.
"""

from __future__ import annotations

from dataclasses import dataclass

from qavach_core.model.enums import MigrationAuthority

# ARCH.md §4.1 names these three explicitly: NPCI, UIDAI, CCA (India PKI).
# Not config-driven (unlike classification_rules.yaml) because this list is
# short, cited directly in ARCH.md's own prose, and not something an
# operator tunes — expand it here, with a comment, if that changes.
EXTERNALLY_SPECIFIED_CRYPTO_REGIMES = frozenset({"npci", "uidai", "cca-india-pki"})


@dataclass(frozen=True, slots=True)
class AuthorityContext:
    """Pre-decided facts about one asset, per ARCH.md §4.1's four rules.
    Whether a locus "counts as third-party" or a cert "chains to a public
    root" is reconciliation/collector-layer knowledge this function does
    not derive itself."""

    chains_to_public_root: bool = False
    all_loci_third_party: bool = False
    is_oem_firmware_or_unoperated_saas: bool = False
    system_regulatory_regimes: frozenset[str] = frozenset()
    locus_in_operator_owned_context: bool = False


def derive_migration_authority(context: AuthorityContext) -> tuple[MigrationAuthority, str]:
    """Returns (authority, authority_basis) — CryptoAsset carries both
    (ARCH.md §4). Checked in ARCH.md §4.1's own listed order, most specific
    compound condition first."""
    if context.chains_to_public_root and context.all_loci_third_party:
        return (
            MigrationAuthority.EXTERNAL_TRUST_ANCHOR,
            "issuer chains to a public root and every locus is third-party software",
        )

    if context.is_oem_firmware_or_unoperated_saas:
        return (
            MigrationAuthority.VENDOR,
            "locus is an OEM firmware image or a SaaS endpoint we do not operate",
        )

    gating_regimes = context.system_regulatory_regimes & EXTERNALLY_SPECIFIED_CRYPTO_REGIMES
    if gating_regimes:
        return (
            MigrationAuthority.REGULATOR_GATED,
            f"system regulatory regime(s) {sorted(gating_regimes)} specify the crypto externally",
        )

    if context.locus_in_operator_owned_context:
        return (
            MigrationAuthority.SELF,
            "locus is in the operator's own repo, keystore, config or cloud account",
        )

    return (MigrationAuthority.UNKNOWN, "no derivation rule matched — triage queue")
