"""ARCH.md §2.2 `sbom.syft`'s purl -> cryptographic capability mapping.
T-033.

`config/knowledge/crypto_libraries.yaml` (the real, curated file — 45
libraries covering Java/Python/Go/JS, `TASK.md` T-034) is loaded into a
`CryptoLibraryMapping` via `from_entries`. This module only defines the
schema and the lookup; `tests/collectors/test_crypto_libraries_yaml.py`
re-verifies the real file's own exit criteria on every test run (at least
40 entries, all four ecosystems present, no duplicate package keys, and —
the one that actually catches a typo — every `provides` name resolves
through `qavach_core.normalize.resolve_algorithm`, not just looks
plausible). This module's own unit tests use a small hand-written fixture
instead, this repo's established pattern for keeping schema/logic tests
independent of the real data file's size (see
`tests/core/test_cbom_normalisation.py`'s hand-written CBOM documents,
`NOTE.md`'s T-014 entry).

**Capability, not usage** (`TASK.md` T-034's own requirement): an entry
says what a library *can do* — the algorithm families it implements or
exposes — never whether the scanned codebase actually calls into that
capability. That distinction is exactly why this tier sits at
`ConfidenceTier.DEPENDENCY` (`ARCH.md §2.2`'s table) rather than something
implying a runtime/AST-observed certainty: "you depend on a library that
provides AES" is real, useful evidence, but weaker than "this file calls
AES directly."
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from packageurl import PackageURL


@dataclass(frozen=True, slots=True)
class CryptoLibraryEntry:
    purl_type: str
    """purl `type` component — `pypi`, `maven`, `golang`, `npm`, ..."""
    name: str
    namespace: str | None
    provides: tuple[str, ...]
    """Algorithm family names — the same vocabulary `qavach_core.
    normalize.resolve_algorithm` resolves against (e.g. `"AES"`, `"RSA"`,
    `"SHA-256"`), not a family this module invents its own spelling for."""


class CryptoLibraryMapping:
    def __init__(self, entries: Iterable[CryptoLibraryEntry]) -> None:
        self._by_key: dict[tuple[str, str | None, str], tuple[str, ...]] = {
            (e.purl_type, e.namespace, e.name): e.provides for e in entries
        }

    @classmethod
    def from_entries(cls, raw_entries: list[dict[str, object]]) -> CryptoLibraryMapping:
        """Builds from the parsed form of `crypto_libraries.yaml`'s
        top-level `libraries:` list — each entry `{type, name, namespace?,
        provides: [...]}`."""
        entries = [
            CryptoLibraryEntry(
                purl_type=str(raw["type"]),
                name=str(raw["name"]),
                namespace=str(raw["namespace"]) if raw.get("namespace") else None,
                provides=tuple(str(p) for p in cast("list[object]", raw["provides"])),
            )
            for raw in raw_entries
        ]
        return cls(entries)

    def lookup(self, purl: PackageURL) -> tuple[str, ...] | None:
        return self._by_key.get((purl.type, purl.namespace, purl.name))
