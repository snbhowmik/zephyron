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


@pytest.mark.parametrize(
    "ref",
    [
        "ghcr.io/x/y@sha256:" + "a" * 64,
        "sha256:" + "b" * 64,  # a content-addressed local image ID
    ],
)
def test_accepts_registry_digests_and_bare_image_ids(ref: str) -> None:
    args = build_sandbox_args(_config(image_ref=ref), container_name="x")
    assert ref in args


@pytest.mark.parametrize(
    "ref",
    [
        "ghcr.io/x/y:latest",
        "ghcr.io/x/y@sha256:tooshort",
        "ghcr.io/x/y@sha256:" + "Z" * 64,  # not hex
        "ghcr.io/x/y@md5:" + "a" * 32,
        "@sha256:" + "a" * 64,  # no image name
        "sha256:tooshort",
    ],
)
def test_rejects_malformed_or_mutable_refs(ref: str) -> None:
    with pytest.raises(ImageNotPinnedError):
        build_sandbox_args(_config(image_ref=ref), container_name="x")


def test_secret_env_is_passed_by_name_only_never_by_value() -> None:
    """SECURITY.md §6: a secret must never appear in any argv — it would
    show in `ps`, `docker inspect` and the recorded tool invocation."""
    config = _config(secret_env={"QAVACH_AD_PASSWORD": "s3cr3t-value"})
    args = build_sandbox_args(config, container_name="x")
    assert "QAVACH_AD_PASSWORD" in args  # the bare name, no `=value`
    assert not any("s3cr3t-value" in a for a in args)


def test_home_defaults_to_the_writable_tmpfs_and_can_be_overridden() -> None:
    """uid 65534 has no home dir; tools that create `$HOME/.<app>` (theia,
    T-039) otherwise fail on the read-only root."""
    assert "HOME=/tmp" in build_sandbox_args(_config(), container_name="x")
    overridden = build_sandbox_args(_config(env={"HOME": "/work"}), container_name="x")
    assert "HOME=/work" in overridden and "HOME=/tmp" not in overridden


def test_plain_env_is_passed_by_value_but_secret_env_never_is() -> None:
    args = build_sandbox_args(
        _config(env={"MODE": "fast"}, secret_env={"TOKEN": "s3cret"}), container_name="x"
    )
    assert "MODE=fast" in args
    assert "TOKEN" in args and not any("s3cret" in a for a in args)


def test_secret_env_never_appears_in_the_config_repr() -> None:
    config = _config(secret_env={"QAVACH_AD_PASSWORD": "s3cr3t-value"})
    assert "s3cr3t-value" not in repr(config)


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


def test_no_target_mount_means_nothing_from_the_host_is_mounted() -> None:
    args = build_sandbox_args(_config(target_mount=None), container_name="x")
    assert "-v" not in args


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


@pytest.mark.integration
@pytest.mark.skipif(not _ENGINE_AVAILABLE, reason="no container engine on PATH")
def test_secret_env_reaches_the_container_without_being_in_argv() -> None:
    """The value is delivered (the process inside can read it) purely via
    the `docker` client's environment — the create-time argv only ever
    carried the *name*."""
    config = _config(
        command=("sh", "-c", "printenv QAVACH_TEST_SECRET"),
        secret_env={"QAVACH_TEST_SECRET": "delivered-by-name-only"},
    )
    assert not any(
        "delivered-by-name-only" in a for a in build_sandbox_args(config, container_name="x")
    )
    result = run_sandboxed(config)
    assert result.output.strip() == b"delivered-by-name-only"


def test_relative_target_mount_is_resolved_to_an_absolute_path() -> None:
    # Docker treats a relative `-v` source as a named volume, not a path.
    args = build_sandbox_args(
        SandboxConfig(
            image_ref="sha256:" + "a" * 64,
            target_mount=Path("some/relative/dir"),
            command=("true",),
        ),
        container_name="c",
    )
    mount = args[args.index("-v") + 1]
    assert mount == f"{Path('some/relative/dir').resolve()}:/target:ro"
    assert mount.startswith("/")


def _tmpfs(args: list[str], mount: str) -> str:
    return next(a for a in args if a.startswith(f"{mount}:"))


def test_tmp_is_noexec_by_default_and_exec_only_on_explicit_opt_in() -> None:
    def build(**kw: bool) -> list[str]:
        return build_sandbox_args(
            SandboxConfig(
                image_ref="sha256:" + "a" * 64, target_mount=None, command=("true",), **kw
            ),
            container_name="c",
        )

    assert ",noexec," in _tmpfs(build(), "/tmp")
    opted = build(tmp_exec=True)
    assert ",exec," in _tmpfs(opted, "/tmp") and ",noexec" not in _tmpfs(opted, "/tmp")
    assert "nosuid,nodev" in _tmpfs(opted, "/tmp")
    assert ",noexec," in _tmpfs(opted, "/work")  # /work never relaxes
    assert "--cap-drop=ALL" in opted and "--read-only" in opted
