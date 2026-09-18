"""Downloads and checksum-verifies the real, pinned certfinder binary
(`config/scanners.yaml`'s `agent_artifacts.tls.store.certfinder` entry)
for T-036's integration tests — the same binary the deployed agent would
actually run, not a stand-in."""

from __future__ import annotations

import hashlib
import platform
import stat
import urllib.request
from pathlib import Path

CERTFINDER_VERSION = "0.7.0"
CERTFINDER_LINUX_AMD64_SHA256 = "cb59af8f99efc34efce6fa2f918da54a79a44b8c5cae49f3e2de586ca5614a85"
CERTFINDER_URL = (
    f"https://github.com/krisiasty/certfinder/releases/download/"
    f"v{CERTFINDER_VERSION}/certfinder_{CERTFINDER_VERSION}_linux_amd64"
)

CACHE_PATH = Path(__file__).parent / ".cache" / f"certfinder-{CERTFINDER_VERSION}-linux-amd64"


class CertfinderUnavailableError(RuntimeError):
    pass


def ensure_certfinder_binary() -> Path:
    """Downloads once into a local cache (re-verified by checksum on
    every call, cheap for an already-cached file) and returns the
    executable path. Only supports linux/amd64 — the platform this test
    suite actually runs on; raises for anything else rather than silently
    skipping platform-specific behaviour differences."""
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise CertfinderUnavailableError(
            f"no pinned certfinder binary for {platform.system()}/{platform.machine()}"
        )

    if not CACHE_PATH.exists():
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            urllib.request.urlretrieve(CERTFINDER_URL, CACHE_PATH)  # noqa: S310 — pinned https URL
        except OSError as exc:
            raise CertfinderUnavailableError(f"could not download certfinder: {exc}") from exc

    digest = hashlib.sha256(CACHE_PATH.read_bytes()).hexdigest()
    if digest != CERTFINDER_LINUX_AMD64_SHA256:
        CACHE_PATH.unlink()
        raise CertfinderUnavailableError(
            f"certfinder checksum mismatch: got {digest}, expected {CERTFINDER_LINUX_AMD64_SHA256}"
        )

    CACHE_PATH.chmod(CACHE_PATH.stat().st_mode | stat.S_IEXEC)
    return CACHE_PATH
