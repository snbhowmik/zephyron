"""Identity keys, merge, confidence precedence, dispute marking (ARCH.md
§6), plus MigrationAuthority derivation (ARCH.md §4.1, T-016a — see that
module's docstring for the file-placement judgement call). Only authority
derivation is implemented so far; identity/merge/dispute are Phase 2."""

from __future__ import annotations

from qavach_core.reconcile.authority import (
    EXTERNALLY_SPECIFIED_CRYPTO_REGIMES,
    AuthorityContext,
    derive_migration_authority,
)
from qavach_core.reconcile.identity import IdentityClaim, asset_identity
from qavach_core.reconcile.merge import (
    ConcludedAttribute,
    MergeResult,
    OccurrenceClaim,
    group_by_identity,
    merge,
    merge_all,
)

__all__ = [
    "EXTERNALLY_SPECIFIED_CRYPTO_REGIMES",
    "AuthorityContext",
    "ConcludedAttribute",
    "IdentityClaim",
    "MergeResult",
    "OccurrenceClaim",
    "asset_identity",
    "derive_migration_authority",
    "group_by_identity",
    "merge",
    "merge_all",
]
