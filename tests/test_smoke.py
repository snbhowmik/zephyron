"""Baseline sanity check for `make test-unit` — CLAUDE.md §5."""

import sys


def test_python_version() -> None:
    assert sys.version_info >= (3, 12)
