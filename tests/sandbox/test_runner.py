"""T-031 — the sandbox runner. `SECURITY.md §3`'s block is the spec; every
flag asserted on here is copied from that block, not invented."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from qavach_sandbox import ImageNotPinnedError, SandboxConfig, build_sandbox_args, run_sandboxed

PINNED_IMAGE = (
    "ghcr.io/anchore/syft@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02"
)
# syft's image is fully distroless (no shell at all — confirmed live: `exec:
# "sh": executable file not found in $PATH`), so the mechanism tests below
# that need `sh -c "..."` to probe the sandbox's own behaviour (network,
# rootfs, uid, timeout) use a real, digest-pinned shell image instead. This
# is a test fixture standing in for "any scanner," not one of QAVACH's
# pinned scanners — `config/scanners.yaml` is unaffected.
SHELL_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"


def _config(**overrides: object) -> SandboxConfig:
    # Docker Desktop only bind-mounts host paths it has been told to share
    # with its VM (project/home directories by default) — a bare `/tmp`
    # 403s at `docker start` with "mounts denied" on this machine's engine,
    # confirmed live while writing these tests. Real collector runs will
    # mount an actual scan target under a QAVACH-controlled directory, which
    # is why a repo-relative scratch path is the representative choice here,
    # not just a workaround.
    scratch = Path(__file__).parent / ".scratch-target"
    scratch.mkdir(exist_ok=True)
    defaults: dict[str, object] = {
        "image_ref": SHELL_IMAGE,
        "target_mount": scratch,
        "command": ("sh", "-c", "true"),
    }
    defaults.update(overrides)
    return SandboxConfig(**defaults)  # type: ignore[arg-type]


# --- build_sandbox_args: pure, no engine required ---


def test_rejects_a_tag_instead_of_a_digest() -> None:
    with pytest.raises(ImageNotPinnedError):
        build_sandbox_args(_config(image_ref="ghcr.io/anchore/syft:latest"), container_name="x")


def test_network_none_by_default() -> None:
    args = build_sandbox_args(_config(), container_name="x")
    assert "--network=none" in args


def test_requires_network_omits_network_none() -> None:
    args = build_sandbox_args(_config(requires_network=True), container_name="x")
    assert "--network=none" not in args


def test_read_only_rootfs_and_tmpfs_work_dir() -> None:
    args = build_sandbox_args(_config(), container_name="x")
    assert "--read-only" in args
    assert "--tmpfs" in args
    tmpfs_idx = args.index("--tmpfs") + 1
    assert args[tmpfs_idx] == "/work:rw,size=2g,noexec,nosuid,nodev"


def test_tmp_also_gets_a_tmpfs() -> None:
    """T-032 finding: a real scanner (cdxgen's `cbom`) hardcodes
    `/tmp/cdxgen-temp` for its own scratch cache, ignoring `TMPDIR` —
    confirmed live — so `--read-only` alone breaks it with `EROFS`. `/tmp`
    gets the same `noexec,nosuid,nodev` tmpfs treatment as `/work`, just
    smaller by default."""
    args = build_sandbox_args(_config(), container_name="x")
    tmpfs_values = [args[i + 1] for i, a in enumerate(args) if a == "--tmpfs"]
    assert "/tmp:rw,size=512m,noexec,nosuid,nodev" in tmpfs_values


def test_runs_as_unprivileged_nobody_user() -> None:
    args = build_sandbox_args(_config(), container_name="x")
    user_idx = args.index("--user") + 1
    assert args[user_idx] == "65534:65534"


def test_drops_all_capabilities_and_blocks_privilege_escalation() -> None:
    args = build_sandbox_args(_config(), container_name="x")
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args


def test_applies_the_vendored_seccomp_profile() -> None:
    args = build_sandbox_args(_config(), container_name="x")
    assert any(a.startswith("--security-opt=seccomp=") and "scanner.json" in a for a in args)


def test_resource_limits_match_security_md() -> None:
    args = build_sandbox_args(_config(), container_name="x")
    assert args[args.index("--pids-limit") + 1] == "512"
    assert args[args.index("--memory") + 1] == "4g"
    assert args[args.index("--memory-swap") + 1] == "4g"
    assert args[args.index("--cpus") + 1] == "2"


def test_target_mounted_read_only() -> None:
    args = build_sandbox_args(_config(target_mount=Path("/scan/target-1")), container_name="x")
    assert "-v" in args
    mount_idx = args.index("-v") + 1
    assert args[mount_idx] == "/scan/target-1:/target:ro"


def test_extra_mounts_are_also_read_only() -> None:
    args = build_sandbox_args(
        _config(extra_mounts={"/host/cred": "/creds/token"}), container_name="x"
    )
    assert "/host/cred:/creds/token:ro" in args


def test_image_and_remaining_command_are_last() -> None:
    """`command[0]` goes to `--entrypoint`; only `command[1:]` trails the
    image ref as CMD."""
    args = build_sandbox_args(
        _config(image_ref=PINNED_IMAGE, command=("scan", "--flag")), container_name="x"
    )
    assert args[-2:] == [PINNED_IMAGE, "--flag"]


def test_command_first_element_becomes_the_entrypoint() -> None:
    """Real bug found live in T-032: without this, `command` is merely
    *appended* to whatever `ENTRYPOINT` the image bakes in — cdxgen's
    pinned image has `ENTRYPOINT ["cdxgen"]`, so `("sh", "-c", "...")`
    silently became the confused process `cdxgen sh -c "..."` instead of
    replacing the entrypoint with a shell."""
    args = build_sandbox_args(
        _config(command=("sh", "-c", "echo hi")),
        container_name="x",
    )
    entrypoint_idx = args.index("--entrypoint") + 1
    assert args[entrypoint_idx] == "sh"
    assert "-c" in args
    assert "echo hi" in args


def test_engine_is_swappable_to_podman() -> None:
    args = build_sandbox_args(_config(engine="podman"), container_name="x")
    assert args[0] == "podman"


# --- run_sandboxed: real Docker/Podman required ---

_ENGINE_AVAILABLE = shutil.which("docker") is not None or shutil.which("podman") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_real_container_runs_and_output_crosses_the_boundary() -> None:
    """Proves the create->start->wait->logs->rm lifecycle actually retrieves
    the container's stdout after it exits — the one thing that can't be
    verified by asserting on argument lists alone. (A `--tmpfs`-file variant
    of this test was tried first and found to be broken: `docker cp` 404s
    against a tmpfs path the instant the container stops, confirmed live —
    see the module docstring and `SECURITY.md §3`.)"""
    result = run_sandboxed(
        _config(
            command=("echo", '{"hello":"qavach"}'),
        )
    )
    assert result.ok, f"exit_code={result.exit_code} stderr={result.stderr!r}"
    assert result.output == b'{"hello":"qavach"}\n'
    assert not result.timed_out


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_real_container_has_no_network_by_default() -> None:
    """`--network=none` — a scanner cannot reach the internet unless its
    collector explicitly declares `requires_network = True`."""
    result = run_sandboxed(
        _config(
            command=(
                "sh",
                "-c",
                "wget -T 3 -q -O - https://example.com || echo '{\"blocked\":true}'",
            ),
        )
    )
    assert result.output == b'{"blocked":true}\n'


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_real_container_cannot_write_outside_tmpfs() -> None:
    """`--read-only` rootfs — only `/work` is writable."""
    result = run_sandboxed(
        _config(
            command=(
                "sh",
                "-c",
                "touch /etc/qavach-escape 2>/dev/null "
                "&& echo '{\"wrote\":true}' || echo '{\"wrote\":false}'",
            ),
        )
    )
    assert result.output == b'{"wrote":false}\n'


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_real_container_runs_as_non_root() -> None:
    result = run_sandboxed(_config(command=("id", "-u")))
    assert result.output.strip() == b"65534"


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_timeout_kills_a_hung_container_at_the_orchestrator_level() -> None:
    """`SECURITY.md §3`: 'Timeout enforced by the orchestrator, not by the
    container... A hung scanner is a failed collector, not a hung scan.'"""
    result = run_sandboxed(
        _config(
            command=("sh", "-c", "sleep 30"),
            timeout_seconds=2,
        )
    )
    assert result.timed_out
    assert result.exit_code is None
    assert not result.ok


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_crashed_scanner_is_empty_output_not_an_exception() -> None:
    """A scanner that crashes before printing anything degrades the
    collector's result; it must never raise out of the sandbox layer."""
    result = run_sandboxed(
        _config(command=("sh", "-c", "exit 1")),
    )
    assert result.exit_code == 1
    assert result.output == b""
    assert not result.ok
