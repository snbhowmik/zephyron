"""Enforces packages/core's purity — CLAUDE.md §2, §3; T-004.

`packages/core` must have ZERO I/O and ZERO framework imports, and must
import nothing from `packages/collectors`. A test that just tries
`import qavach_core` and checks for an ImportError would NOT catch a
violation here: this is a shared workspace venv (T-001), so FastAPI,
SQLAlchemy etc. are genuinely installed (for sibling packages) and a stray
`import fastapi` inside qavach_core would succeed at runtime. The only way
to actually enforce the boundary is static AST inspection of every import
statement in every core source file, independent of what happens to be
installed.

Design: default-deny. Every import is classified as one of:
  - "self"              importing qavach_core's own submodules — always fine
  - "relative"           `from . import x` / `from .model import y` — always fine
  - "stdlib-pure"         standard library, not an I/O module — fine
  - "stdlib-io"           standard library, but a genuine I/O module — FORBIDDEN
  - "allowed-third-party" explicitly allowlisted below — fine
  - "forbidden"           everything else (FastAPI, SQLAlchemy, requests,
                          boto3, qavach_collectors, qavach_storage, ...) —
                          FORBIDDEN

The allowlist starts empty because `packages/core/pyproject.toml` declares
zero dependencies (T-001). Add an entry here ONLY alongside a matching
pyproject.toml dependency and a line in NOTE.md explaining why a pure
function needs it.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CORE_SRC = REPO_ROOT / "packages" / "core" / "src"
CORE_PACKAGE_NAME = "qavach_core"

# Standard-library modules that are genuine I/O — network, process, or a
# database — despite shipping in the stdlib. CLAUDE.md's "ZERO I/O" is about
# what the code DOES, not whether pip had to install it.
STDLIB_IO_MODULES = {
    "socket",
    "ssl",
    "subprocess",
    "multiprocessing",
    "asyncio",
    "sqlite3",
    "urllib",
    "http",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
}

# Third-party imports explicitly permitted inside packages/core. Empty by
# design — see module docstring.
ALLOWED_THIRD_PARTY: frozenset[str] = frozenset()

_STDLIB = set(sys.stdlib_module_names) | set(sys.builtin_module_names)


@dataclass(frozen=True)
class ImportSite:
    module: str
    lineno: int


def _import_sites(tree: ast.Module) -> list[ImportSite]:
    """Every absolute top-level module name a file imports, with its line.

    Relative imports (`from . import x`, `node.level > 0`) are always
    intra-package and are skipped entirely — they can only ever resolve to
    something already inside qavach_core.
    """
    sites: list[ImportSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                sites.append(ImportSite(alias.name.split(".")[0], node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue
            if node.module:
                sites.append(ImportSite(node.module.split(".")[0], node.lineno))
    return sites


def classify(module: str) -> str:
    if module == CORE_PACKAGE_NAME:
        return "self"
    if module in _STDLIB:
        return "stdlib-io" if module in STDLIB_IO_MODULES else "stdlib-pure"
    if module in ALLOWED_THIRD_PARTY:
        return "allowed-third-party"
    return "forbidden"


def _core_source_files() -> list[Path]:
    if not CORE_SRC.exists():
        pytest.fail(f"{CORE_SRC} does not exist — is packages/core scaffolded (T-001)?")
    files = sorted(CORE_SRC.rglob("*.py"))
    if not files:
        pytest.fail(f"{CORE_SRC} contains no .py files — nothing to check.")
    return files


# --- The real check, run against whatever is actually in packages/core ---


def test_core_has_no_forbidden_imports() -> None:
    violations: list[str] = []
    for path in _core_source_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        rel = path.relative_to(REPO_ROOT)
        for site in _import_sites(tree):
            verdict = classify(site.module)
            if verdict in ("forbidden", "stdlib-io"):
                reason = (
                    "not on the allowlist"
                    if verdict == "forbidden"
                    else "a standard-library I/O module"
                )
                violations.append(f"{rel}:{site.lineno}: imports {site.module!r} ({reason})")

    assert not violations, (
        "packages/core must have ZERO I/O and ZERO framework imports, and "
        "import nothing outside itself + the stdlib (CLAUDE.md §2, §3):\n" + "\n".join(violations)
    )


def test_core_imports_nothing_from_collectors() -> None:
    """Named separately from the generic check above because CLAUDE.md §2
    calls this out explicitly, and a reader searching test output for
    "collectors" should find a test named for exactly that, not have to
    infer it from the generic forbidden-imports message."""
    violations: list[str] = []
    for path in _core_source_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        rel = path.relative_to(REPO_ROOT)
        for site in _import_sites(tree):
            if site.module.startswith("qavach_collectors"):
                violations.append(f"{rel}:{site.lineno}")

    assert not violations, "packages/core must not import anything from collectors/:\n" + "\n".join(
        violations
    )


# --- Prove the detection logic itself actually works, independent of what
# packages/core happens to contain right now (still just __init__.py stubs
# before T-010). Without this, both tests above pass vacuously on an empty
# tree and prove nothing. ---


@pytest.mark.parametrize(
    ("source", "expected_verdict"),
    [
        ("import fastapi", "forbidden"),
        ("from sqlalchemy import Column", "forbidden"),
        ("import requests", "forbidden"),
        ("import boto3", "forbidden"),
        ("from qavach_collectors.tls import scan", "forbidden"),
        ("from qavach_storage.models import Base", "forbidden"),
        ("import subprocess", "stdlib-io"),
        ("import socket", "stdlib-io"),
        ("import asyncio", "stdlib-io"),
        ("import dataclasses", "stdlib-pure"),
        ("import enum", "stdlib-pure"),
        ("from __future__ import annotations", "stdlib-pure"),
        ("from qavach_core.model import CryptoAsset", "self"),
        ("import qavach_core", "self"),
    ],
)
def test_classification_logic(source: str, expected_verdict: str) -> None:
    tree = ast.parse(source)
    sites = _import_sites(tree)
    assert sites, f"test bug: {source!r} produced no import sites"
    verdicts = {classify(site.module) for site in sites}
    assert verdicts == {expected_verdict}, (
        f"{source!r} classified as {verdicts}, expected {{{expected_verdict!r}}}"
    )


def test_relative_imports_are_always_skipped() -> None:
    tree = ast.parse("from . import model\nfrom .normalize import registry\nfrom ..core import x")
    assert _import_sites(tree) == []
