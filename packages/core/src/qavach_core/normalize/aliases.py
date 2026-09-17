"""ARCH.md §5.2 step 3 — QAVACH's own overlay for spellings tools actually
emit that the vendored registry doesn't recognise verbatim, and (found
during T-011/T-012) the OID→family table the vendored registry does not
provide for algorithm families.

This module defines the shape only. The actual curated data —
`config/knowledge/aliases.yaml`, "first 60 aliases covering what the tools
actually emit" — is T-013's job, loaded elsewhere (I/O stays outside
`packages/core`, CLAUDE.md §2) and passed in as an already-parsed dict via
`AliasTable.from_dict()`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AliasTarget:
    family: str
    parameter_set: str | None = None


@dataclass(frozen=True, slots=True)
class AliasTable:
    by_oid: Mapping[str, AliasTarget]
    by_name: Mapping[str, AliasTarget]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> AliasTable:
        """Expected shape (config/knowledge/aliases.yaml, T-013):

        ```yaml
        oids:
          "2.16.840.1.101.3.4.4.2": { family: ML-KEM, parameter_set: "768" }
        names:
          Kyber768: { family: ML-KEM, parameter_set: "768" }
          EC: { family: ECDSA }
        ```
        """

        def _targets(section: Mapping[str, Any]) -> dict[str, AliasTarget]:
            return {
                key: AliasTarget(family=v["family"], parameter_set=v.get("parameter_set"))
                for key, v in section.items()
            }

        return AliasTable(
            by_oid=_targets(data.get("oids", {})),
            by_name=_targets(data.get("names", {})),
        )
