"""SECURITY.md §3 / ARCH.md §3 — the sandbox. T-031.

Every collector with `requires_sandbox = True` runs in a fresh container per
job, built from the exact flags `SECURITY.md §3` specifies. There is no
bypass flag and no "trusted target" mode: `build_sandbox_args` cannot express
one, and `run_sandboxed` cannot be called without going through it.

Lifecycle note: output crosses the boundary as the container's **stdout**,
captured with `docker logs` after the container exits, before it is removed
(`SECURITY.md §3`). `/work` is a `noexec,nosuid,nodev` tmpfs the scanner may
use as scratch space, but it is not the retrieval channel — verified live in
T-031 that it cannot be: a tmpfs mount is torn down the moment its container
*stops*, not when it is `rm`'d, so `docker cp <container>:/work/x -` 404s
against an already-exited container even with the container object still
present. `docker logs` has no such gap, because the log driver captures the
stream continuously while the process runs, independent of the filesystem.
A collector whose scanner writes a file instead of printing to stdout needs
a command that ends by printing it, e.g. `scanner -o /work/bom.json && cat
/work/bom.json`.

This runner does `create` -> `start` -> `wait` (with the orchestrator-level
timeout `SECURITY.md §3` requires) -> `logs` -> `rm -f`, always, in a
`finally`. The worker never reads any path inside the container; `docker
logs` is the only channel data crosses on.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


class ImageNotPinnedError(ValueError):
    """SECURITY.md §3: 'Pinned by digest... A tag is a mutable pointer to
    code we will execute with a filesystem mounted.'"""


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """The inputs to one sandboxed collector run. Every field maps directly
    to a flag in `SECURITY.md §3`'s block — nothing here is a knob that
    weakens the posture; `requires_network` and `allow_build_resolution` are
    the two explicit, named exceptions the doc itself carves out, and both
    default to the closed setting."""

    image_ref: str
    """Must be `<image>@sha256:<digest>` — never a tag."""
    target_mount: Path
    """Host path mounted read-only at `/target` inside the container."""
    command: tuple[str, ...]
    """`command[0]` always becomes `--entrypoint`, overriding whatever
    `ENTRYPOINT` the image itself bakes in — a scanner image with its own
    non-shell entrypoint (e.g. cdxgen's `ENTRYPOINT ["cdxgen"]`) would
    otherwise get `command` *appended* to it instead of replacing it,
    confirmed live to produce a broken, confused invocation. In practice
    every collector passes `("sh", "-c", "<script>")`. The script must end
    by printing exactly the collector's JSON output to stdout — that is
    the only channel `SandboxResult.output` is filled from."""
    requires_network: bool = False
    timeout_seconds: int = 900
    memory: str = "4g"
    cpus: str = "2"
    pids_limit: int = 512
    tmpfs_size: str = "2g"
    tmp_tmpfs_size: str = "512m"
    """A second, smaller tmpfs at `/tmp` — not in `SECURITY.md §3`'s
    literal flag block, added after a real collector (cdxgen's `cbom`,
    T-032) was found live to hardcode `/tmp/cdxgen-temp` for its own
    scratch cache regardless of `TMPDIR` (`os.tmpdir()`-respecting env
    vars were tried first and confirmed live not to redirect it), so
    `--read-only` alone breaks any such tool with `EROFS: read-only file
    system, mkdtemp '/tmp/...'`. Same security properties as `/work`
    (`noexec,nosuid,nodev`, ephemeral, ordinary ephemeral scratch space) —
    this does not weaken the sandbox, it just accepts that "the only
    writable path is `/work`" was an assumption a real scanner violated."""
    engine: str = "docker"
    """CLAUDE.md §4: Docker or Podman, kept swappable."""
    seccomp_profile: Path = Path("config/seccomp/scanner.json")
    extra_mounts: dict[str, str] = field(default_factory=dict)
    """`{host_path: container_path}`, always mounted `:ro`. For collectors
    that need a second read-only input (e.g. a credential file) beyond the
    scan target — never a write target; nothing mounted this way persists
    past the container's lifetime, same as `/work` and `/tmp`."""


@dataclass(frozen=True, slots=True)
class SandboxResult:
    exit_code: int | None
    """`None` when `timed_out` is True — the process was killed, not run to
    completion, so there is no real exit code to report."""
    output: bytes
    """The container's captured stdout."""
    stderr: bytes
    duration_seconds: float
    timed_out: bool

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.exit_code == 0


def _validate_pinned_by_digest(image_ref: str) -> None:
    if "@sha256:" not in image_ref:
        raise ImageNotPinnedError(
            f"{image_ref!r} is not pinned by digest — SECURITY.md §3 requires "
            "'<image>@sha256:...', never a mutable tag"
        )


def build_sandbox_args(config: SandboxConfig, *, container_name: str) -> list[str]:
    """Pure — builds a `docker create` argument list without running
    anything, so the exact security flags can be asserted on directly in a
    unit test without a container engine present. `run_sandboxed` is the
    only thing that has to actually touch Docker/Podman.

    `command[0]` is always sent as `--entrypoint`, with `command[1:]`
    appended as the CMD after the image ref. Without this, `command` is
    merely *appended* to whatever `ENTRYPOINT` the image itself bakes in —
    a real bug found live while building T-032's cdxgen adapter: the
    pinned `cdxgen` image has `ENTRYPOINT ["cdxgen"]`, so a config's
    `command=("sh", "-c", "...")` silently became the process `cdxgen sh
    -c "..."` (cdxgen receiving "sh"/"-c"/the script string as its own
    confused CLI arguments) rather than replacing the entrypoint with a
    shell at all. `busybox` (T-031's own test fixture) has no conflicting
    `ENTRYPOINT`, which is exactly why this stayed invisible until a
    collector target a real scanner image with one."""
    _validate_pinned_by_digest(config.image_ref)

    args = [config.engine, "create", "--name", container_name, "--entrypoint", config.command[0]]
    if not config.requires_network:
        args += ["--network=none"]
    args += [
        "--read-only",
        "--tmpfs",
        f"/work:rw,size={config.tmpfs_size},noexec,nosuid,nodev",
        "--tmpfs",
        f"/tmp:rw,size={config.tmp_tmpfs_size},noexec,nosuid,nodev",
        "--user",
        "65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={config.seccomp_profile}",
        "--pids-limit",
        str(config.pids_limit),
        "--memory",
        config.memory,
        "--memory-swap",
        config.memory,
        "--cpus",
        config.cpus,
        "-v",
        f"{config.target_mount}:/target:ro",
    ]
    for host_path, container_path in config.extra_mounts.items():
        args += ["-v", f"{host_path}:{container_path}:ro"]
    args += [config.image_ref, *config.command[1:]]
    return args


def run_sandboxed(config: SandboxConfig) -> SandboxResult:
    """Runs one collector to completion inside the sandbox described by
    `config`. Never raises for a scanner-side failure, crash, OOM-kill or
    timeout (`SECURITY.md §3`: 'Failure is isolated... it never fails [the
    scan] and never propagates an exception') — all of those come back as a
    `SandboxResult` with `ok=False` for the caller to turn into a
    `CollectorResult(partial=True, ...)`. It *does* raise `ImageNotPinnedError`
    before anything runs, and lets engine-invocation errors (the `docker`/
    `podman` binary missing, a malformed image ref) surface directly, since
    those are QAVACH configuration bugs, not scanner behaviour to isolate."""
    container_name = f"qavach-sandbox-{uuid.uuid4().hex[:12]}"
    create_args = build_sandbox_args(config, container_name=container_name)

    start = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    stdout = b""
    stderr = b""

    try:
        subprocess.run(create_args, capture_output=True, check=True)
        subprocess.run([config.engine, "start", container_name], capture_output=True, check=True)
        try:
            wait_proc = subprocess.run(
                [config.engine, "wait", container_name],
                capture_output=True,
                timeout=config.timeout_seconds,
                check=True,
            )
            exit_code = int(wait_proc.stdout.decode().strip())
        except subprocess.TimeoutExpired:
            timed_out = True
            subprocess.run(
                [config.engine, "kill", container_name], capture_output=True, check=False
            )

        logs_proc = subprocess.run(
            [config.engine, "logs", container_name], capture_output=True, check=False
        )
        stdout = logs_proc.stdout
        stderr = logs_proc.stderr
    finally:
        subprocess.run(
            [config.engine, "rm", "-f", container_name], capture_output=True, check=False
        )

    duration = time.monotonic() - start
    return SandboxResult(
        exit_code=exit_code,
        output=stdout,
        stderr=stderr,
        duration_seconds=duration,
        timed_out=timed_out,
    )
