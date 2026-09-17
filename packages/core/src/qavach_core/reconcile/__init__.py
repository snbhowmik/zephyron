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

__all__ = [
    "EXTERNALLY_SPECIFIED_CRYPTO_REGIMES",
    "AuthorityContext",
    "derive_migration_authority",
]
