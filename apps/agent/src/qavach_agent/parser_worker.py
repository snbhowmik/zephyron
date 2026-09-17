"""ARCH.md §3a 'Containment for hostile input, without a container'. T-031b.

The agent has no container, so a malformed keystore (zip-slip, a
decompression bomb, or an outright parser crash in `cryptography`/`pyjks`/
`zipfile`) is contained the way GRR Rapid Response, osquery and Velociraptor
each independently converged on: parse the file in a short-lived,
resource-limited subprocess, never inline in the agent's main process.

Because the agent ships as a frozen single-file binary with no Python
interpreter on the host (`ARCH.md §3a`), the worker cannot be a fresh
`python3` process — it is the *same* frozen executable, re-invoked with a
hidden internal subcommand (`_parse-worker`, wired in `__main__.py`) that
reads the fetched file's bytes from stdin, calls one named parse
entrypoint, and writes JSON claims to stdout. Under PyInstaller,
`sys.executable` resolves to the frozen binary itself (`sys.frozen`), so
this self-re-exec works on a host with nothing else installed.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkerLimits:
    """ARCH.md §3a step 2: 'Apply resource.setrlimit: CPU time,
    address-space size, output size. Plus a hard wall-clock timeout at the
    supervisor level.'"""

    cpu_seconds: int = 5
    address_space_bytes: int = 256 * 1024 * 1024
    max_output_bytes: int = 10 * 1024 * 1024
    wall_clock_seconds: float = 15.0
    drop_to_uid: int | None = None
    drop_to_gid: int | None = None
    """ARCH.md §3a step 3: 'Drop the worker to the most restricted account
    the agent's own low-privilege service account can reach — no
    supplementary groups.' Left `None` by default because it is only
    meaningful when the agent process itself holds `CAP_SETUID` (i.e. is
    currently running with *more* privilege than the target account) —
    most deployments run the agent as its own already-scoped low-privilege
    service account per ARCH.md §3a's own hard rule, with nothing lower to
    drop to without root to begin with. **Not exercised end-to-end by this
    session's tests**: dropping to a different uid requires the calling
    process to have `CAP_SETUID`, which a non-root development environment
    does not have (confirmed live: `os.getuid()` is a plain unprivileged
    1000 here) — the code path exists and is unit-tested for its own
    ordering, but nobody has watched it actually flip a real process's
    uid. Revisit under a real deployment or a root-capable CI runner."""


@dataclass(frozen=True, slots=True)
class WorkerResult:
    ok: bool
    claims_json: list[dict[str, object]]
    error: str | None = None


def _drop_privileges(
    uid: int, gid: int
) -> None:  # pragma: no cover — requires root, runs in the child
    import os

    os.setgroups([])  # "no supplementary groups" — ARCH.md §3a step 3
    os.setgid(gid)
    os.setuid(uid)


def _set_resource_limits(limits: WorkerLimits) -> None:  # pragma: no cover — runs in the child
    import resource

    if limits.drop_to_uid is not None and limits.drop_to_gid is not None:
        _drop_privileges(limits.drop_to_uid, limits.drop_to_gid)
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (limits.address_space_bytes, limits.address_space_bytes))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_output_bytes, limits.max_output_bytes))


def _default_worker_argv() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "qavach_agent"]


def run_in_worker(
    *,
    parse_entrypoint: str,
    file_bytes: bytes,
    limits: WorkerLimits | None = None,
    worker_argv: list[str] | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> WorkerResult:
    """Runs `parse_entrypoint` (a `"module:function"` dotted path) against
    `file_bytes` in a resource-limited child process — ARCH.md §3a steps
    1-4. Never raises for a parser crash, a resource-limit breach or a
    timeout; those all come back as `WorkerResult(ok=False, ...)` for the
    caller to mark the occurrence `partial` (step 5) and continue with the
    rest of the batch — the same "failure is isolated" property `SECURITY.
    md §3` requires of the sandboxed-subprocess path, applied here without
    a container. `worker_argv` defaults to re-invoking this same process
    (`sys.executable`, frozen-binary-aware); tests override it only to
    point at fixture parse functions, never to skip the resource limits
    themselves. `cwd`/`env` are passed straight through to the child — a
    real deployment can use them to further restrict what the worker can
    see (e.g. an empty `PATH`); tests use `env` to put a fixture module on
    `PYTHONPATH`."""
    argv = worker_argv if worker_argv is not None else _default_worker_argv()
    limits = limits or WorkerLimits()

    preexec_fn = None
    if sys.platform != "win32":  # RLIMIT_* is POSIX-only — see NOTE.md's Windows gap
        preexec_fn = lambda: _set_resource_limits(limits)  # noqa: E731

    try:
        proc = subprocess.run(
            [*argv, "_parse-worker", parse_entrypoint],
            input=file_bytes,
            capture_output=True,
            timeout=limits.wall_clock_seconds,
            preexec_fn=preexec_fn,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return WorkerResult(ok=False, claims_json=[], error="wall-clock timeout exceeded")
    except (OSError, subprocess.SubprocessError) as exc:
        # A `preexec_fn` failure (e.g. `drop_to_uid` set without the
        # CAP_SETUID to honour it) re-raises in the parent as either the
        # original `OSError` subclass or a generic `SubprocessError` —
        # confirmed live, both are possible depending on how the child's
        # exception type is recognised. Either way this is a breach of
        # this function's own "never raises" contract if left uncaught, so
        # it is treated exactly like any other containment failure.
        return WorkerResult(ok=False, claims_json=[], error=f"worker could not start: {exc}")

    if proc.returncode != 0:
        stderr_tail = proc.stderr.decode(errors="replace")[:500]
        return WorkerResult(
            ok=False, claims_json=[], error=f"worker exited {proc.returncode}: {stderr_tail}"
        )

    try:
        claims = json.loads(proc.stdout.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return WorkerResult(ok=False, claims_json=[], error=f"worker produced invalid JSON: {exc}")

    if not isinstance(claims, list):
        return WorkerResult(ok=False, claims_json=[], error="worker output was not a JSON list")

    return WorkerResult(ok=True, claims_json=claims)


def parse_worker_main(parse_entrypoint: str) -> int:
    """The `_parse-worker` hidden subcommand's body (wired in
    `__main__.py`): reads file bytes from stdin, imports and calls the
    named parse function, writes JSON claims to stdout. Any exception here
    is caught and reported as a non-zero exit with a stderr message —
    `run_in_worker` already treats non-zero exit as a partial result, so a
    parser crashing on hostile input is exactly the contained, reported
    failure this module exists to produce instead of taking the agent's
    main process down with it."""
    module_name, _, func_name = parse_entrypoint.partition(":")
    if not module_name or not func_name:
        print(f"malformed parse entrypoint: {parse_entrypoint!r}", file=sys.stderr)
        return 2
    try:
        module = importlib.import_module(module_name)
        parse_fn = getattr(module, func_name)
        file_bytes = sys.stdin.buffer.read()
        claims = parse_fn(file_bytes)
        sys.stdout.buffer.write(json.dumps(claims).encode())
        sys.stdout.buffer.flush()
        return 0
    except Exception as exc:  # noqa: BLE001 — hostile input, anything can go wrong here
        print(f"parse entrypoint {parse_entrypoint!r} raised: {exc!r}", file=sys.stderr)
        return 1
