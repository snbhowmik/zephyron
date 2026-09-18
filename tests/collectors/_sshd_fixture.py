"""A real, unprivileged `sshd` on a loopback port, for T-042 tests."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SSHD = shutil.which("sshd") or "/usr/bin/sshd"
SSHD_AVAILABLE = (
    Path(SSHD).exists()
    and shutil.which("ssh-keygen") is not None
    and shutil.which("ssh-keyscan") is not None
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def run_sshd(tmp_path: Path, *, extra_config: str = "") -> Iterator[int]:
    keys = []
    for kind, args in (("ed25519", []), ("rsa", ["-b", "3072"])):
        key = tmp_path / f"host_{kind}"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", kind, *args, "-N", "", "-f", str(key)], check=True
        )
        keys.append(key)
    port = _free_port()
    config = tmp_path / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\n"
        + "".join(f"HostKey {k}\n" for k in keys)
        + f"PidFile {tmp_path / 'pid'}\n{extra_config}\n"
    )
    proc = subprocess.Popen(
        [SSHD, "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)
