"""The backend's certificate authority for agent credentials (ARCH.md §3a step 3).

The agent generates its own keypair and sends only a CSR, so the private key
never crosses the wire; this signs the CSR into a short-lived client
certificate. The CA private key lives in `QAVACH_AGENT_CA_DIR` (mode 0600, dir
0700) and is created on first use - a deployment that never enrols an agent never
creates one. It is a signing key for *client credentials only*: it is never
served, logged or placed in an export (SECURITY.md §6).

Only P-256 EC agent keys are accepted (what `qavach_agent.enrollment` generates
and what `qavach_agent.signing` verifies); anything else is refused at the CSR.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_VALID_DAYS = 3650
CLIENT_VALID_DAYS = 90


class CsrRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    certificate_pem: bytes
    fingerprint_sha256: str
    not_after: datetime


class AgentCA:
    def __init__(self, key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate) -> None:
        self._key = key
        self._certificate = certificate

    @property
    def bundle_pem(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    @classmethod
    def load_or_create(cls, directory: Path, now: datetime | None = None) -> AgentCA:
        now = now or datetime.now(UTC)
        key_path, cert_path = directory / "ca.key", directory / "ca.crt"
        if key_path.exists() and cert_path.exists():
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise ValueError(f"{key_path} is not an EC key")
            return cls(key, x509.load_pem_x509_certificate(cert_path.read_bytes()))
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QAVACH"),
                x509.NameAttribute(NameOID.COMMON_NAME, "QAVACH agent CA"),
            ]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        # write the key with 0600 from the start, never world-readable even briefly
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        return cls(key, certificate)

    def issue(self, csr_pem: bytes, agent_id: str, now: datetime) -> IssuedCredential:
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise CsrRejected("not a PEM certificate signing request") from exc
        if not csr.is_signature_valid:
            raise CsrRejected("the CSR's self-signature does not verify")
        public_key = csr.public_key()
        if not (
            isinstance(public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.curve, ec.SECP256R1)
        ):
            raise CsrRejected("agent keys must be EC P-256")
        not_after = now + timedelta(days=CLIENT_VALID_DAYS)
        # The subject is the *issued identity*; whatever CN the requester chose is
        # ignored so an agent cannot ask to be called something else.
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QAVACH agent"),
                        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                    ]
                )
            )
            .issuer_name(self._certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        return IssuedCredential(
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
            fingerprint_sha256=hashlib.sha256(
                certificate.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
            not_after=not_after,
        )
