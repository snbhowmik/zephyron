"""ARCH.md §2.2: 'QAVACH owns PKCS#7 parsing... on top' of certfinder.
T-036.

certfinder's own `--help` names PEM, DER, JKS, JCEKS and PKCS#12 — not
PKCS#7 (`.p7b`/`.p7c` `SignedData` bundles, a common way certificate
chains get distributed, especially on Windows/Java estates). Confirmed
live: `cryptography.hazmat.primitives.serialization.pkcs7.
load_der_pkcs7_certificates`/`load_pem_pkcs7_certificates` correctly
parse a real bundle generated with `openssl crl2pkcs7`. This module walks
a directory for `.p7b`/`.p7c` files and extracts every certificate they
contain, in the same `DiscoveredCertificate` shape `store.py` already
uses for certfinder's own output, so both sources feed one pipeline.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from qavach_collectors.tls.store import DiscoveredCertificate

PKCS7_EXTENSIONS = (".p7b", ".p7c")


def find_pkcs7_certificates(directory: Path) -> list[DiscoveredCertificate]:
    """Walks `directory` for `.p7b`/`.p7c` files and returns every
    certificate found inside each — never raises on an individual file
    that fails to parse (a non-PKCS#7 file with one of these extensions,
    or a truncated bundle); that file is simply skipped, matching
    certfinder's own approach of reporting real finds rather than failing
    a whole scan over one bad file."""
    discovered: list[DiscoveredCertificate] = []
    for path in directory.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in PKCS7_EXTENSIONS:
            continue
        for cert in _try_parse_pkcs7_file(path):
            discovered.append(_to_discovered_certificate(cert, path=str(path)))
    return discovered


def _try_parse_pkcs7_file(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    for loader in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            return loader(data)
        except ValueError:
            continue
    return []


def _to_discovered_certificate(cert: x509.Certificate, *, path: str) -> DiscoveredCertificate:
    pubkey = cert.public_key()
    algorithm: str | None
    bits: int | None = None
    curve: str | None = None
    if isinstance(pubkey, rsa.RSAPublicKey):
        algorithm, bits = "RSA", pubkey.key_size
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        algorithm, curve, bits = "ECDSA", pubkey.curve.name, pubkey.key_size
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        algorithm = "Ed25519"
    elif isinstance(pubkey, ed448.Ed448PublicKey):
        algorithm = "Ed448"
    elif isinstance(pubkey, dsa.DSAPublicKey):
        algorithm, bits = "DSA", pubkey.key_size
    else:
        algorithm = None

    spki_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_hasher = hashes.Hash(hashes.SHA256())
    spki_hasher.update(spki_bytes)

    fingerprint_hasher = hashes.Hash(hashes.SHA256())
    fingerprint_hasher.update(cert.public_bytes(serialization.Encoding.DER))

    return DiscoveredCertificate(
        path=path,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        public_key_curve=curve,
        signature_algorithm=cert.signature_algorithm_oid.dotted_string,
        sha256_fingerprint=fingerprint_hasher.finalize().hex(),
        spki_sha256=spki_hasher.finalize().hex(),
        self_signed=cert.subject == cert.issuer,
    )
