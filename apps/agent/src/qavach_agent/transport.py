"""ARCH.md §3a Transport. T-031a.

'Mutual TLS. The agent presents the client certificate it received at
enrollment; it verifies the backend's certificate against a pinned CA rather
than trusting whatever is offered. There is no unauthenticated fallback
mode.' One configured backend URL — `SECURITY.md §5`'s no-telemetry clause
and `NFR-05`'s air-gap requirement, applied to a process that lives outside
QAVACH's own infrastructure: nothing built on `AgentTransport` can be
pointed at a second host.
"""

from __future__ import annotations

import ssl
import tempfile
from pathlib import Path
from types import TracebackType

import httpx

from qavach_agent.enrollment import AgentCredential
from qavach_agent.signing import SignedRequestAuth


class AgentTransport:
    """One mTLS-authenticated `httpx.Client` bound to exactly one backend
    URL. Use as a context manager: the client certificate, its private key
    and the pinned CA bundle are materialised to a private, `0600`,
    per-instance temp directory on enter and removed on exit — credential
    material is never left on disk longer than the transport that needs it
    is open. (Persisting the credential *between* agent runs, so it does not
    re-enroll on every poll, is the caller's concern — see `NOTE.md`'s
    at-rest protection follow-up.)"""

    def __init__(
        self, *, backend_url: str, credential: AgentCredential, timeout_seconds: float = 30.0
    ) -> None:
        self._backend_url = backend_url
        self._credential = credential
        self._timeout_seconds = timeout_seconds
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._client: httpx.Client | None = None

    def __enter__(self) -> httpx.Client:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="qavach-agent-")
        tmp_path = Path(self._tmpdir.name)
        key_path = tmp_path / "client.key"
        cert_path = tmp_path / "client.crt"
        ca_path = tmp_path / "ca.crt"

        key_path.write_bytes(self._credential.private_key_pem)
        key_path.chmod(0o600)
        cert_path.write_bytes(self._credential.client_cert_pem)
        ca_path.write_bytes(self._credential.ca_bundle_pem)

        ssl_context = ssl.create_default_context(cafile=str(ca_path))
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._client = httpx.Client(
            base_url=self._backend_url,
            verify=ssl_context,
            auth=SignedRequestAuth(self._credential.private_key_pem),
            timeout=self._timeout_seconds,
        )
        return self._client

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            self._client.close()
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
