"""Real parse-entrypoint targets for T-031b's worker tests. No real
agent-side collector parse function exists yet (tls.store etc. are still
open Phase 3 tasks), so these stand in for one — each is dynamically
imported and called by `parser_worker.parse_worker_main` exactly the way a
real collector's parse function eventually will be, proving the worker
supervisor's containment mechanics rather than any particular parser."""

from __future__ import annotations

import time


def parse_ok(data: bytes) -> list[dict[str, object]]:
    return [{"name": "RSA", "size_bytes": len(data)}]


def parse_that_raises(data: bytes) -> list[dict[str, object]]:
    raise ValueError("simulated malformed keystore")


def parse_that_sleeps_forever(data: bytes) -> list[dict[str, object]]:
    """Blocks without consuming CPU time — exercises the wall-clock
    timeout specifically, not `RLIMIT_CPU`."""
    time.sleep(120)
    return []


def parse_that_burns_cpu_forever(data: bytes) -> list[dict[str, object]]:
    """Busy-loops, consuming real CPU time — exercises `RLIMIT_CPU`
    (SIGXCPU) rather than the wall-clock timeout."""
    total = 0
    while True:
        total += 1


def parse_that_allocates_too_much(data: bytes) -> list[dict[str, object]]:
    """A crude stand-in for a decompression bomb — exercises
    `RLIMIT_AS`."""
    huge = bytearray(2 * 1024 * 1024 * 1024)  # 2 GiB
    return [{"allocated": len(huge)}]
