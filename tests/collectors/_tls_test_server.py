"""A real local TLS server for T-035's tests, built from a real
self-signed certificate (via `cryptography`, not shelled out to `openssl
req`) and served by the system's own `openssl s_server` — the same binary
`endpoint.py` shells out to for probing, so these tests exercise the
actual `openssl s_client` <-> `openssl s_server` interaction, not a mock.
"""

from __future__ import annotations

import datetime
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OPENSSL_AVAILABLE = shutil.which("openssl") is not None


@dataclass(frozen=True, slots=True)
class TestServer:
    port: int
    hostname: str
    cert_pem: bytes


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _generate_self_signed_cert(hostname: str, *, alt_names: list[str]) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in alt_names]), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


@contextmanager
def run_test_tls_server(
    *, tmp_path: Path, hostname: str = "qavach-test.local", groups: str | None = None
) -> Iterator[TestServer]:
    cert_pem, key_pem = _generate_self_signed_cert(
        hostname, alt_names=[hostname, "alt.qavach-test.local"]
    )
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    port = _free_port()
    command = [
        "openssl",
        "s_server",
        "-accept",
        str(port),
        "-cert",
        str(cert_path),
        "-key",
        str(key_path),
        "-www",
        "-naccept",
        "1000",
    ]
    if groups is not None:
        command += ["-groups", groups]

    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for_port("127.0.0.1", port, timeout=5.0)
        yield TestServer(port=port, hostname=hostname, cert_pem=cert_pem)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _wait_for_port(host: str, port: int, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.1)
    raise TimeoutError(f"server on {host}:{port} did not start in time: {last_error}")
