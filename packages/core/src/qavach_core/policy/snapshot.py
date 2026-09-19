"""Policy documents as an immutable, cited, hashable snapshot. T-060, T-068.

Two rules are enforced here, at load time, so no scoring code has to remember
them:

1. **Nothing uncited.** Every value lives inside a *node* - a mapping with a
   non-empty `basis` string - and a container may hold only containers or
   nodes. A bare number in a policy file is rejected with its path. This is
   what lets every score explain where each of its numbers came from
   (`ARCH.md §7`, FR-360) instead of asserting them.
2. **Scores use the snapshot, never the live files** (T-068). The snapshot is
   a frozen value with a canonical JSON form and a SHA-256 `snapshot_id`;
   scoring functions take it as an argument and have no other route to policy.
   The same assets plus the same snapshot therefore give byte-identical
   scores on any machine (NFR-09), and a stored scan can be re-scored later
   against exactly the policy it ran under.

Pure: takes already-parsed dicts (`yaml.safe_load` output), performs no I/O.
`datetime.date` values, which YAML produces for bare dates, are canonicalised
to ISO strings so the snapshot is JSON-serialisable and stable.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Cited:
    """One policy node: its fields plus the citation that justifies them."""

    path: str
    fields: Mapping[str, Any]
    basis: str

    @property
    def value(self) -> Any:
        if "value" not in self.fields:
            raise PolicyError(f"policy node {self.path!r} has no `value` field")
        return self.fields["value"]


def _canonical(value: Any, path: str) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _canonical(v, f"{path}.{k}") for k, v in value.items()}
    if isinstance(value, (list, tuple, frozenset, set)):
        items = [_canonical(v, path) for v in value]
        return sorted(items, key=repr) if isinstance(value, (frozenset, set)) else items
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise PolicyError(f"unsupported value of type {type(value).__name__} at {path!r}")


def _validate(node: Mapping[str, Any], path: str) -> None:
    if "basis" in node:
        basis = node["basis"]
        if not isinstance(basis, str) or not basis.strip():
            raise PolicyError(f"{path}: `basis` must be a non-empty citation string")
        return
    if not node:
        raise PolicyError(f"{path}: empty policy container")
    for key, child in node.items():
        if not isinstance(child, Mapping):
            raise PolicyError(
                f"{path}.{key}: uncited value - every policy value must sit in a node "
                "with a `basis`"
            )
        _validate(child, f"{path}.{key}")


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    documents: Mapping[str, Any]
    _nodes: dict[str, Cited] = field(default_factory=dict, compare=False, repr=False)
    """Memoised `node()` lookups. Scoring consults the same few dozen paths for
    every asset; the snapshot is immutable, so caching cannot go stale."""

    @staticmethod
    def from_documents(documents: Mapping[str, Mapping[str, Any]]) -> PolicySnapshot:
        canonical = {str(name): _canonical(doc, str(name)) for name, doc in documents.items()}
        for name, doc in canonical.items():
            if not isinstance(doc, dict):
                raise PolicyError(f"{name}: a policy document must be a mapping")
            _validate(doc, name)
        return PolicySnapshot(documents=canonical)

    def _walk(self, path: str) -> Any:
        current: Any = self.documents
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                raise PolicyError(f"no policy entry at {path!r}")
            current = current[part]
        return current

    def node(self, path: str) -> Cited:
        cached = self._nodes.get(path)
        if cached is not None:
            return cached
        found = self._walk(path)
        if not isinstance(found, Mapping) or "basis" not in found:
            raise PolicyError(f"{path!r} is a container, not a cited node")
        node_fields = {k: v for k, v in found.items() if k != "basis"}
        cited = Cited(path=path, fields=node_fields, basis=str(found["basis"]))
        self._nodes[path] = cited
        return cited

    def value(self, path: str) -> Any:
        return self.node(path).value

    def nodes(self, path: str) -> dict[str, Cited]:
        """Every cited node directly under the container at `path`."""
        container = self._walk(path)
        if not isinstance(container, Mapping):
            raise PolicyError(f"{path!r} is not a container")
        return {name: self.node(f"{path}.{name}") for name in container}

    def iter_nodes(self) -> Iterator[Cited]:
        def visit(prefix: str, current: Mapping[str, Any]) -> Iterator[Cited]:
            for key, child in current.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if "basis" in child:
                    yield self.node(path)
                else:
                    yield from visit(path, child)

        yield from visit("", self.documents)

    def canonical_json(self) -> str:
        return json.dumps(self.documents, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @property
    def snapshot_id(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("ascii")).hexdigest()

    @staticmethod
    def from_json(text: str) -> PolicySnapshot:
        loaded = json.loads(text)
        if not isinstance(loaded, dict):
            raise PolicyError("a policy snapshot must be a JSON object")
        return PolicySnapshot.from_documents(loaded)
