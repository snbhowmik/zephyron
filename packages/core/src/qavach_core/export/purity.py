"""Invariant I5, made checkable. T-091.

`cbom_violations` inspects a built CBOM (a plain dict) and reports everything
that must never be in it. Schema validation (jsonschema, offline against the
vendored 1.7 schema) is done by `scripts/schema_check.py` and the tests - it
needs the schema files, and this module stays pure - but schema validity alone
is not I5: a document can be perfectly valid CycloneDX and still be polluted with
risk data, because `properties[]` accepts any name. So this check is separate:

* every `qavach:` property must be in the closed, documented set;
* no property *name* may carry risk vocabulary, whatever its namespace;
* no `cryptographic-asset` component may carry a `purl`.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from qavach_core.export.cbom import DOCUMENTED_PROPERTIES

_RISK_WORDS = re.compile(
    r"(risk|mosca|urgency|caraf|roadmap|outcome|expected[-_ ]?value|shelf[-_ ]?life|"
    r"quantum[-_ ]?vulnerable|score|priority|criticality|recommend)",
    re.IGNORECASE,
)


def _properties(node: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if key == "properties" and isinstance(value, list):
                for i, prop in enumerate(value):
                    if isinstance(prop, Mapping) and "name" in prop:
                        yield f"{path}.properties[{i}]", str(prop["name"])
            else:
                yield from _properties(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _properties(item, f"{path}[{i}]")


def cbom_violations(
    bom: Mapping[str, Any], documented: frozenset[str] = DOCUMENTED_PROPERTIES
) -> list[str]:
    problems: list[str] = []
    for where, name in _properties(bom, "$"):
        if name.startswith("qavach:") and name not in documented:
            problems.append(f"{where}: undocumented property {name!r}")
        if _RISK_WORDS.search(name):
            problems.append(f"{where}: property name {name!r} carries risk vocabulary (I5)")
    for i, component in enumerate(bom.get("components", [])):
        if component.get("type") == "cryptographic-asset" and "purl" in component:
            problems.append(f"$.components[{i}]: a cryptographic-asset must not carry a purl")
    return problems
