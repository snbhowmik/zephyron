"""T-031b — the resource-limited parsing worker (`ARCH.md §3a`,
'Containment for hostile input, without a container'). Runs the *real*
subprocess re-exec path (`[sys.executable, -m, qavach_agent,
_parse-worker, ...]`), against real fixture parse functions in
`_fixture_parsers.py`, with real, tight `resource.setrlimit` values — this
proves the containment actually holds, not just that the right subprocess
arguments were built."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from qavach_agent import WorkerLimits, run_in_worker

_FIXTURES_DIR = str(Path(__file__).parent)


def _worker_env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": _FIXTURES_DIR}


_WORKER_ARGV = [sys.executable, "-m", "qavach_agent"]

# Tight, fast-failing limits so these tests don't sit around for the
# module's 5s/15s production defaults.
_TEST_LIMITS = WorkerLimits(
    cpu_seconds=1,
    address_space_bytes=64 * 1024 * 1024,
    max_output_bytes=1024 * 1024,
    wall_clock_seconds=3.0,
)


def _run(parse_entrypoint: str, data: bytes = b"hello") -> object:
    return run_in_worker(
        parse_entrypoint=parse_entrypoint,
        file_bytes=data,
        limits=_TEST_LIMITS,
        worker_argv=_WORKER_ARGV,
        env=_worker_env(),
    )


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_a_well_behaved_parser_returns_real_claims() -> None:
    result = _run("_fixture_parsers:parse_ok", data=b"twelve bytes")
    assert result.ok
    assert result.claims_json == [{"name": "RSA", "size_bytes": 12}]
    assert result.error is None


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_a_crashing_parser_is_contained_not_raised() -> None:
    """ARCH.md §3a step 5: 'On any breach... kill the worker, mark the
    occurrence partial... One crafted keystore never hangs or crashes the
    agent.' A parser exception must never propagate to the caller."""
    result = _run("_fixture_parsers:parse_that_raises")
    assert not result.ok
    assert result.claims_json == []
    assert "simulated malformed keystore" in result.error


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_wall_clock_timeout_kills_a_blocked_worker() -> None:
    """A parser that blocks without burning CPU (`time.sleep`) is caught by
    the *supervisor's* wall-clock timeout, not `RLIMIT_CPU` — proving the
    two containment mechanisms are actually independent, per ARCH.md §3a
    step 2's 'Plus a hard wall-clock timeout at the supervisor level.'"""
    result = _run("_fixture_parsers:parse_that_sleeps_forever")
    assert not result.ok
    assert "timeout" in result.error


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_rlimit_cpu_kills_a_cpu_bound_infinite_loop() -> None:
    """A pure CPU busy-loop is killed by `RLIMIT_CPU` (SIGXCPU) well before
    the wall-clock timeout, since `cpu_seconds=1 < wall_clock_seconds=3` in
    `_TEST_LIMITS` — proving the CPU limit is actually enforced by the
    kernel, not just passed as an unused constructor argument."""
    result = _run("_fixture_parsers:parse_that_burns_cpu_forever")
    assert not result.ok
    # Killed by SIGXCPU -> negative returncode reported in the worker-exit
    # message, distinguishing this from the wall-clock path above.
    assert "timeout" not in result.error


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_rlimit_as_kills_an_oversized_allocation() -> None:
    """A crude decompression-bomb stand-in (a 2 GiB allocation) is refused
    by `RLIMIT_AS` (64 MiB in `_TEST_LIMITS`) — the allocation itself fails
    inside the child rather than actually consuming 2 GiB of host memory."""
    result = _run("_fixture_parsers:parse_that_allocates_too_much")
    assert not result.ok


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_malformed_entrypoint_is_reported_not_raised() -> None:
    result = _run("not-a-valid-entrypoint")
    assert not result.ok


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
def test_nonexistent_module_is_reported_not_raised() -> None:
    result = _run("no_such_module_at_all:parse_ok")
    assert not result.ok


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_* is POSIX-only")
@pytest.mark.skipif(os.getuid() == 0, reason="this assertion needs a non-root process")
def test_drop_to_uid_without_cap_setuid_is_reported_not_raised() -> None:
    """ARCH.md §3a step 3's privilege-drop is only meaningful when the
    calling process holds CAP_SETUID; this development environment does
    not (confirmed: plain unprivileged uid, `parser_worker.py`'s
    `WorkerLimits.drop_to_uid` docstring). This test proves the *failure*
    path is contained the same way every other breach is — a `preexec_fn`
    error must come back as `WorkerResult(ok=False)`, never an uncaught
    `OSError` escaping into the caller — not that a real uid switch
    happened, which nothing in this session can exercise."""
    limits = WorkerLimits(
        cpu_seconds=_TEST_LIMITS.cpu_seconds,
        address_space_bytes=_TEST_LIMITS.address_space_bytes,
        max_output_bytes=_TEST_LIMITS.max_output_bytes,
        wall_clock_seconds=_TEST_LIMITS.wall_clock_seconds,
        drop_to_uid=65534,
        drop_to_gid=65534,
    )
    result = run_in_worker(
        parse_entrypoint="_fixture_parsers:parse_ok",
        file_bytes=b"data",
        limits=limits,
        worker_argv=_WORKER_ARGV,
        env=_worker_env(),
    )
    assert not result.ok
    assert result.error is not None
