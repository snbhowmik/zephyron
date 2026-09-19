"""System import, validation and retention inference. T-050, T-052, T-053.

A `System` is the business unit humans migrate, budget for and own; assets are
what scanners find (`ARCH.md §4`). This module turns an operator's systems
file into validated `System`s plus a **clear error report** - every problem is
returned with its row and field rather than the first one aborting the import,
and a bad row is *excluded*, never half-imported.

Pure: it takes already-read rows (`parse_system_rows`) or CSV *text*
(`parse_systems_csv`, stdlib `csv` on a string). Reading the file is the
caller's job (`packages/core` has no I/O).

Decisions worth knowing (each recorded in NOTE.md):

* `internet_facing` is **required**. A blank would default to "internal", which
  lowers the expected value and under-reports risk - the wrong way to fail.
* `retention_years` may be blank: it is then inferred from the data class
  (T-052), `retention_inferred=True`, and an `info` issue names the inference so
  the surface can show it. The defaults are planning heuristics, not regulatory
  retention periods.
* `depends_on` must name systems that exist in the file (T-053); a dangling or
  self reference is an error on that row, and exclusion cascades until stable.
  Cycles are deliberately **not** errors here - a cycle is a finding the roadmap
  turns into a hybrid-bridge requirement (`ARCH.md §9.3`).
* Binding columns (`repos`, `images`, `endpoints`, `cloud_accounts`, `hosts`)
  are kept separate from `System` (which `ARCH.md §4` fixes) as
  `SystemBindings`, consumed by `context.binding`.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from qavach_core.model.system import DataClass, System
from qavach_core.policy import PolicyError, PolicySnapshot

REQUIRED_COLUMNS = ("id", "name", "owner", "criticality", "data_classification", "internet_facing")
OPTIONAL_COLUMNS = (
    "retention_years",
    "regulatory_regimes",
    "depends_on",
    "repos",
    "images",
    "endpoints",
    "cloud_accounts",
    "hosts",
)
_KNOWN = frozenset(REQUIRED_COLUMNS + OPTIONAL_COLUMNS)
_TRUE = frozenset({"true", "yes", "y", "1"})
_FALSE = frozenset({"false", "no", "n", "0"})
_LIST_SEPARATORS = (";", "|")


@dataclass(frozen=True, slots=True)
class ImportIssue:
    row: int
    """1-based data row (the header is row 0); 0 for file-level problems."""
    field: str | None
    message: str
    severity: str = "error"
    """`error` (row excluded), `warning` (imported, worth a look) or `info`."""


@dataclass(frozen=True, slots=True)
class SystemBindings:
    repos: frozenset[str] = frozenset()
    images: frozenset[str] = frozenset()
    endpoints: frozenset[str] = frozenset()
    cloud_accounts: frozenset[str] = frozenset()
    hosts: frozenset[str] = frozenset()


@dataclass(slots=True)
class SystemImport:
    systems: tuple[System, ...] = ()
    bindings: dict[str, SystemBindings] = field(default_factory=dict)
    issues: tuple[ImportIssue, ...] = ()

    @property
    def errors(self) -> tuple[ImportIssue, ...]:
        return tuple(i for i in self.issues if i.severity == "error")

    @property
    def ok(self) -> bool:
        return not self.errors


def infer_retention(data_class: DataClass, policy: PolicySnapshot) -> tuple[float, str]:
    """T-052. Returns `(years, basis)`; the basis is the policy citation, so the
    UI can show exactly why a number was assumed."""
    node = policy.node(f"retention_defaults.years_by_data_class.{data_class.value}")
    return float(node.value), node.basis


def _split(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [str(v) for v in value]
    else:
        text = str(value)
        for sep in _LIST_SEPARATORS[1:]:
            text = text.replace(sep, _LIST_SEPARATORS[0])
        items = text.split(_LIST_SEPARATORS[0])
    return [i.strip() for i in items if i.strip()]


def _text(row: Mapping[str, Any], key: str) -> str:
    value = row.get(key)
    return "" if value is None else str(value).strip()


def _parse_bool(text: str) -> bool | None:
    lowered = text.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    return None


def _parse_row(
    number: int, row: Mapping[str, Any], policy: PolicySnapshot
) -> tuple[System | None, SystemBindings | None, list[ImportIssue]]:
    issues: list[ImportIssue] = []

    def error(field_name: str, message: str) -> None:
        issues.append(ImportIssue(number, field_name, message))

    for column in REQUIRED_COLUMNS:
        if not _text(row, column):
            error(column, f"{column} is required")

    criticality = 0
    raw_crit = _text(row, "criticality")
    if raw_crit:
        try:
            criticality = int(raw_crit)
            if not 1 <= criticality <= 5:
                raise ValueError
        except ValueError:
            error("criticality", f"criticality must be an integer 1..5, got {raw_crit!r}")

    data_class: DataClass | None = None
    raw_class = _text(row, "data_classification").lower()
    if raw_class:
        try:
            data_class = DataClass(raw_class)
        except ValueError:
            allowed = ", ".join(c.value for c in DataClass)
            error(
                "data_classification",
                f"unknown data classification {raw_class!r}; use one of: {allowed}",
            )

    internet_facing = False
    raw_facing = _text(row, "internet_facing")
    if raw_facing:
        parsed = _parse_bool(raw_facing)
        if parsed is None:
            error("internet_facing", f"internet_facing must be true/false, got {raw_facing!r}")
        else:
            internet_facing = parsed

    retention = 0.0
    inferred = False
    raw_retention = _text(row, "retention_years")
    if raw_retention:
        try:
            retention = float(raw_retention)
            if retention < 0:
                raise ValueError
        except ValueError:
            error(
                "retention_years", f"retention_years must be a number >= 0, got {raw_retention!r}"
            )
    elif data_class is not None:
        try:
            retention, basis = infer_retention(data_class, policy)
            inferred = True
            issues.append(
                ImportIssue(
                    number,
                    "retention_years",
                    f"retention not supplied: inferred {retention:g} years from data class "
                    f"{data_class.value!r} ({basis})",
                    "info",
                )
            )
        except PolicyError as exc:
            error("retention_years", f"retention not supplied and could not be inferred: {exc}")

    if any(i.severity == "error" for i in issues) or data_class is None:
        return None, None, issues

    system = System(
        id=_text(row, "id"),
        name=_text(row, "name"),
        owner=_text(row, "owner"),
        criticality=criticality,
        data_classification=data_class,
        retention_years=retention,
        retention_inferred=inferred,
        internet_facing=internet_facing,
        regulatory_regimes=frozenset(r.lower() for r in _split(row.get("regulatory_regimes"))),
        depends_on=frozenset(_split(row.get("depends_on"))),
    )
    bindings = SystemBindings(
        repos=frozenset(_split(row.get("repos"))),
        images=frozenset(_split(row.get("images"))),
        endpoints=frozenset(_split(row.get("endpoints"))),
        cloud_accounts=frozenset(_split(row.get("cloud_accounts"))),
        hosts=frozenset(_split(row.get("hosts"))),
    )
    return system, bindings, issues


def parse_system_rows(rows: Iterable[Mapping[str, Any]], policy: PolicySnapshot) -> SystemImport:
    issues: list[ImportIssue] = []
    parsed: dict[str, tuple[int, System, SystemBindings]] = {}
    seen_columns: set[str] = set()

    for number, row in enumerate(rows, start=1):
        seen_columns.update(str(k) for k in row)
        system, bindings, row_issues = _parse_row(number, row, policy)
        issues.extend(row_issues)
        if system is None or bindings is None:
            continue
        if system.id in parsed:
            issues.append(
                ImportIssue(
                    number,
                    "id",
                    f"duplicate system id {system.id!r} (first seen on row {parsed[system.id][0]})",
                )
            )
            continue
        parsed[system.id] = (number, system, bindings)

    for column in sorted(seen_columns - _KNOWN):
        issues.append(ImportIssue(0, column, f"unknown column {column!r} was ignored", "warning"))

    # T-053: dependencies must exist. Excluding a row can orphan its dependents,
    # so repeat until nothing changes.
    changed = True
    while changed:
        changed = False
        for system_id, (number, system, _bindings) in list(parsed.items()):
            problems = []
            if system_id in system.depends_on:
                problems.append("a system cannot depend on itself")
            missing = sorted(d for d in system.depends_on if d != system_id and d not in parsed)
            if missing:
                problems.append(f"depends on unknown system(s): {', '.join(missing)}")
            if problems:
                issues.append(ImportIssue(number, "depends_on", "; ".join(problems)))
                del parsed[system_id]
                changed = True

    issues.sort(key=lambda i: (i.row, i.field or "", i.severity, i.message))
    return SystemImport(
        systems=tuple(s for _, s, _ in parsed.values()),
        bindings={sid: b for sid, (_, _, b) in parsed.items()},
        issues=tuple(issues),
    )


def parse_systems_csv(text: str, policy: PolicySnapshot) -> SystemImport:
    reader = csv.DictReader(io.StringIO(text))
    header = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in REQUIRED_COLUMNS if c not in header]
    if missing:
        return SystemImport(
            issues=(ImportIssue(0, None, f"missing required column(s): {', '.join(missing)}"),)
        )
    rows = [
        {(k or "").strip(): v for k, v in row.items() if k is not None}
        for row in reader
        if any((v or "").strip() for v in row.values() if isinstance(v, str))
    ]
    return parse_system_rows(rows, policy)


def system_dependency_edges(systems: Iterable[System]) -> tuple[tuple[str, str], ...]:
    """T-053: `(system, depends_on)` pairs, sorted, for the roadmap DAG. Edges to
    systems not in `systems` are kept - the importer has already rejected them;
    a caller passing a partial set sees the dangling edge rather than losing it."""
    return tuple(sorted((s.id, d) for s in systems for d in s.depends_on))
