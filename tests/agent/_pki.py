"""Test-only PKI helpers for T-031a's agent tests. Builds a real, throwaway
CA and uses it to issue a real server certificate and to sign real CSRs
into real client certificates — this is what lets the enrollment/transport
tests exercise actual TLS handshakes (mutual auth included) against a local
server, rather than mocking `httpx` itself and only proving the agent calls
the right function names."""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID

_ONE_DAY = datetime.timedelta(days=1)


@dataclass(frozen=True, slots=True)
class TestCA:
    private_key: EllipticCurvePrivateKey
    certificate: x509.Certificate

    @property
    def cert_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def make_test_ca(common_name: str = "QAVACH Test CA") -> TestCA:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + _ONE_DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return TestCA(private_key=private_key, certificate=certificate)


def issue_server_cert(ca: TestCA, hostname: str = "localhost") -> tuple[bytes, bytes]:
    """Returns `(cert_pem, key_pem)` for a leaf certificate signed by `ca`,
    valid for `hostname` via SAN — what the mock backend presents."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + _ONE_DAY)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(ca.private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key_pem


def sign_csr(ca: TestCA, csr_pem: bytes) -> bytes:
    """What the mock `/api/v1/agents/enroll` handler does: signs a CSR the
    agent submitted into a real client certificate, the same operation
    T-073a's real backend will perform."""
    csr = x509.load_pem_x509_csr(csr_pem)
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + _ONE_DAY)
        .sign(ca.private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)
