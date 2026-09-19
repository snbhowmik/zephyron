"""CBOMkit-theia's `dir` command, run agent-side. T-036c / `NOTE.md` OQ-11.

Theia ships no binaries, so the agent carries one QAVACH built from the pinned
source (`docker/theia-build`, `make build-theia`): Go cross-compiles, and the
result is byte-reproducible (verified with a `--no-cache` rebuild). The
plugins that matter here are `certificates` (PEM/DER), `secrets` (private
keys), `opensslconf` (TLS protocol/cipher directives) and `problematicca`.

Runs as a host subprocess — like certfinder, agent-side collectors are not
sandboxed (`ARCH.md §2.3`) — so it gets the minimum: no stdin, a throwaway
`HOME` (theia writes a config directory under it; it must not touch the
operator's), a timeout, and an output-size cap before the JSON is parsed. Its
stderr log chatter is discarded. Theia is *additive* to certfinder, never a
replacement: any failure here degrades to a non-fatal note and the certfinder
result stands.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MAX_OUTPUT_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 300.0


class TheiaDirError(RuntimeError):
    pass


def run_theia_dir(binary: Path, directory: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="qavach-theia-home-") as home:
        env = {"HOME": home, "USERPROFILE": home, "PATH": ""}
        try:
            proc = subprocess.run(
                [str(binary), "dir", str(directory)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TheiaDirError(f"cbomkit-theia timed out after {TIMEOUT_SECONDS:.0f}s") from exc
        except OSError as exc:
            raise TheiaDirError(f"could not execute {binary}: {exc}") from exc
    if proc.returncode != 0:
        raise TheiaDirError(f"cbomkit-theia exited {proc.returncode}")
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        raise TheiaDirError("cbomkit-theia output exceeded the size cap")
    try:
        document = json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError) as exc:
        raise TheiaDirError(f"cbomkit-theia output was not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TheiaDirError("cbomkit-theia output was not a JSON object")
    return document
