"""T-122 - deliberate escape attempts against the real sandbox.

`test_runner.py` proves the *flags* are what `SECURITY.md §3` says. These prove
the *behaviour*: from inside a real container built by `build_sandbox_args`, each
test does what a hostile scanner or a hostile scan target would try, and asserts
the attempt fails. Each probe prints one `key=value` line so a failure names the
control that did not hold.
"""

# ruff: noqa: E501  (the probe scripts are one-line shell)
from __future__ import annotations

import os
import shutil

import pytest
from qavach_sandbox import run_sandboxed
from test_runner import _config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("docker") is None and shutil.which("podman") is None,
        reason="no container engine on PATH",
    ),
]


def probe(script: str, **config: object) -> dict[str, str]:
    result = run_sandboxed(_config(command=("sh", "-c", script), **config))
    assert not result.timed_out, "probe timed out"
    out: dict[str, str] = {}
    for line in result.output.decode(errors="replace").splitlines():
        key, _, value = line.partition("=")
        out[key] = value
    return out


def test_no_egress_by_address_dns_or_route() -> None:
    p = probe(
        "wget -T 3 -q -O /dev/null http://1.1.1.1/ && echo ip=reached || echo ip=blocked;"
        "wget -T 3 -q -O /dev/null http://example.com/ && echo dns=reached || echo dns=blocked;"
        "wget -T 3 -q -O /dev/null http://host.docker.internal/ && echo host=reached || echo host=blocked;"
        'n=0; for d in /sys/class/net/*; do [ "$(basename $d)" = lo ] && continue;'
        " grep -q '^up' $d/operstate && n=$((n+1)); done; echo up_ifaces=$n;"
        "echo default_route=$(grep -c '^[a-z0-9]*[[:space:]]*00000000' /proc/net/route)"
    )
    assert p["ip"] == p["dns"] == p["host"] == "blocked"
    # (unconfigured tunnel stubs like tunl0 exist in every netns; none may be up)
    assert p["up_ifaces"] == "0"
    assert p["default_route"] == "0"


def test_the_scan_target_is_read_only_and_cannot_be_modified_or_escaped_through() -> None:
    p = probe(
        "touch /target/planted 2>/dev/null && echo target_write=yes || echo target_write=no;"
        "rm -rf /target/* 2>/dev/null; echo rm_exit=$?;"
        "ln -s / /target/root 2>/dev/null && echo symlink=created || echo symlink=refused"
    )
    assert p["target_write"] == "no" and p["symlink"] == "refused"


def test_the_root_filesystem_is_read_only_and_tmpfs_cannot_execute() -> None:
    p = probe(
        "touch /etc/planted 2>/dev/null && echo rootfs_write=yes || echo rootfs_write=no;"
        "cp /bin/busybox /work/x 2>/dev/null; chmod +x /work/x 2>/dev/null;"
        "/work/x true 2>/dev/null && echo exec_tmpfs=yes || echo exec_tmpfs=no;"
        "cp /bin/busybox /tmp/x 2>/dev/null; chmod +x /tmp/x 2>/dev/null;"
        "/tmp/x true 2>/dev/null && echo exec_tmp=yes || echo exec_tmp=no"
    )
    assert p["rootfs_write"] == "no"
    assert p["exec_tmpfs"] == "no" and p["exec_tmp"] == "no"


def test_no_capabilities_no_new_privileges_and_seccomp_is_on() -> None:
    p = probe(
        "echo capeff=$(grep CapEff /proc/self/status | awk '{print $2}');"
        "echo capbnd=$(grep CapBnd /proc/self/status | awk '{print $2}');"
        "echo nnp=$(grep NoNewPrivs /proc/self/status | awk '{print $2}');"
        "echo seccomp=$(grep '^Seccomp:' /proc/self/status | awk '{print $2}');"
        "echo uid=$(id -u)"
    )
    assert p["capeff"] == p["capbnd"] == "0000000000000000"
    assert p["nnp"] == "1" and p["seccomp"] == "2" and p["uid"] == "65534"


def test_privileged_operations_are_refused() -> None:
    p = probe(
        "mkdir -p /work/m; mount -t tmpfs none /work/m 2>/dev/null && echo mount=yes || echo mount=no;"
        "unshare -U -r true 2>/dev/null && echo userns=yes || echo userns=no;"
        "chown 0:0 /work 2>/dev/null && echo chown=yes || echo chown=no;"
        "su root -c id 2>/dev/null && echo su=yes || echo su=no"
    )
    assert (p["mount"], p["userns"], p["chown"], p["su"]) == ("no", "no", "no", "no")


def test_the_host_is_not_reachable_through_the_filesystem() -> None:
    p = probe(
        "ls /var/run/docker.sock >/dev/null 2>&1 && echo docker_sock=yes || echo docker_sock=no;"
        "ls /run/docker.sock >/dev/null 2>&1 && echo run_sock=yes || echo run_sock=no;"
        "ls /host /hostfs /mnt/host >/dev/null 2>&1 && echo host_mount=yes || echo host_mount=no;"
        "ls /home/snbhowmik >/dev/null 2>&1 && echo home=yes || echo home=no;"
        "mount | grep -c ' /target ' | sed 's/^/target_mounts=/'"
    )
    assert (p["docker_sock"], p["run_sock"], p["host_mount"], p["home"]) == ("no",) * 4
    assert p["target_mounts"] == "1"


def test_the_hosts_environment_and_secrets_do_not_enter_the_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QAVACH_TEST_HOST_SECRET", "s3cr3t-value")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-value")
    p = probe("env | grep -c -E 's3cr3t-value|aws-secret-value' | sed 's/^/leaked=/'")
    assert p["leaked"] == "0"
    assert os.environ["QAVACH_TEST_HOST_SECRET"]  # the host still has it; only the box lacks it


def test_a_fork_bomb_is_stopped_by_the_pids_limit() -> None:
    """900 background processes against `--pids-limit 512`: the kernel refuses a
    fork mid-way, and busybox's shell exits on the failed fork - the bomb never
    completes. (A shell that survived would have printed `done`.)"""
    result = run_sandboxed(
        _config(
            command=(
                "sh",
                "-c",
                "i=0; while [ $i -lt 900 ]; do sleep 20 & i=$((i+1)); done; echo done",
            ),
            timeout_seconds=60,
        )
    )
    assert not result.timed_out
    assert b"done" not in result.output
    assert b"can't fork" in result.stderr and b"Resource temporarily unavailable" in result.stderr


def test_control_the_egress_probe_does_detect_egress_when_the_network_is_allowed() -> None:
    """A probe that cannot fail proves nothing. With `requires_network=True` (the
    one documented exception) the same probe must see the network, otherwise the
    'blocked' results above would be vacuous. Skipped when the host is offline."""
    p = probe(
        "wget -T 4 -q -O /dev/null http://1.1.1.1/ && echo ip=reached || echo ip=blocked",
        requires_network=True,
    )
    if p["ip"] != "reached":
        pytest.skip("host has no outbound network, so the control cannot run")
    assert p["ip"] == "reached"
