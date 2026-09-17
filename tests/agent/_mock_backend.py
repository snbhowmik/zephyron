"""A real local mTLS backend double for T-031a's tests — not a mocked
`httpx` call, an actual TLS server on `localhost` implementing the three
`ARCH.md §12` agent endpoints well enough to exercise the agent's real
network code:

  POST /api/v1/agents/enroll        validates a bearer token, signs the
                                     submitted CSR with the test CA, returns
                                     a client certificate — no client cert
                                     required for this one call (ARCH.md
                                     §3a: enrollment precedes mTLS).
  GET  /api/v1/agents/{id}/spec     returns the next queued scan spec (or
                                     204 if the queue is empty); requires a
                                     verified client certificate.
  POST /api/v1/agents/{id}/results  records the posted body; requires a
                                     verified client certificate.

T-073a (Phase 6, not built) is the real backend. This is a test fixture
standing in for it, scoped to exactly what T-031a's agent code needs to
drive against something real.
"""

from __future__ import annotations

import json
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from _pki import TestCA, issue_server_cert, sign_csr


class MockBackendState:
    def __init__(self, *, expected_enrollment_token: str, ca: TestCA) -> None:
        self.expected_enrollment_token = expected_enrollment_token
        self.ca = ca
        self.next_agent_id_counter = 0
        self.spec_queue: list[dict[str, object] | None] = []
        """`None` entries mean "no work this poll" (204)."""
        self.posted_results: list[dict[str, object]] = []
        self.enroll_call_count = 0


class _Handler(BaseHTTPRequestHandler):
    server: _MockBackendServer

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002 — stdlib signature
        pass  # silence request logging; tests assert on state, not stdout

    def _client_cert_present(self) -> bool:
        cert = self.connection.getpeercert()  # type: ignore[attr-defined]
        return bool(cert)

    def _send_json(self, status: int, body: dict[str, object] | None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode("utf-8"))

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's naming
        state = self.server.state
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"
        payload = json.loads(raw_body) if raw_body else {}

        if self.path == "/api/v1/agents/enroll":
            state.enroll_call_count += 1
            if payload.get("enrollment_token") != state.expected_enrollment_token:
                self._send_json(403, {"error": "invalid or already-consumed enrollment token"})
                return
            client_cert_pem = sign_csr(state.ca, payload["csr_pem"].encode("ascii"))
            state.next_agent_id_counter += 1
            self._send_json(
                200,
                {
                    "agent_id": f"agent-{state.next_agent_id_counter}",
                    "client_cert_pem": client_cert_pem.decode("ascii"),
                    "ca_bundle_pem": state.ca.cert_pem.decode("ascii"),
                },
            )
            return

        if self.path.startswith("/api/v1/agents/") and self.path.endswith("/results"):
            if not self._client_cert_present():
                self._send_json(401, {"error": "client certificate required"})
                return
            state.posted_results.append(payload)
            self._send_json(200, {"accepted": True})
            return

        self._send_json(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        state = self.server.state
        if self.path.startswith("/api/v1/agents/") and self.path.endswith("/spec"):
            if not self._client_cert_present():
                self._send_json(401, {"error": "client certificate required"})
                return
            if not state.spec_queue:
                self.send_response(204)
                self.end_headers()
                return
            spec = state.spec_queue.pop(0)
            if spec is None:
                self.send_response(204)
                self.end_headers()
                return
            self._send_json(200, spec)
            return

        self._send_json(404, {"error": "not found"})


class _MockBackendServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: MockBackendState) -> None:
        super().__init__(address, _Handler)
        self.state = state


@contextmanager
def run_mock_backend(
    *, tmp_path: Path, ca: TestCA, expected_enrollment_token: str
) -> Iterator[tuple[str, MockBackendState]]:
    """Starts the mock backend on an ephemeral localhost port in a
    background thread. Yields `(base_url, state)` — `state` is the same
    object the handler mutates, so a test can inspect `posted_results` or
    push onto `spec_queue` directly."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    server_cert_pem, server_key_pem = issue_server_cert(ca, hostname="localhost")
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(server_cert_pem)
    key_path.write_bytes(server_key_pem)

    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca.cert_pem)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ssl_context.load_verify_locations(cafile=str(ca_path))
    ssl_context.verify_mode = ssl.CERT_OPTIONAL

    state = MockBackendState(expected_enrollment_token=expected_enrollment_token, ca=ca)
    server = _MockBackendServer(("localhost", 0), state)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    port = server.socket.getsockname()[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
