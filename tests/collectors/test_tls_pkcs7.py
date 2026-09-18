"""T-036 — `tls/pkcs7.py`, the gap certfinder itself doesn't cover
(confirmed live against its own `--help`: PEM/DER/JKS/JCEKS/PKCS#12, no
PKCS#7). Real bundles built with `cryptography`'s own PKCS#7 builder, not
shelled out to `openssl crl2pkcs7` (kept the test hermetic and free of an
external-tool dependency this specific module doesn't otherwise need)."""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from qavach_collectors.tls import find_pkcs7_certificates


def _self_signed_cert(common_name: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_finds_certificates_in_a_der_pkcs7_bundle(tmp_path: Path) -> None:
    cert, key = _self_signed_cert("pkcs7-der.test")
    bundle = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"")
        .add_signer(cert, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.DetachedSignature],
        )
    )
    (tmp_path / "bundle.p7b").write_bytes(bundle)

    found = find_pkcs7_certificates(tmp_path)
    assert len(found) == 1
    assert found[0].subject == "CN=pkcs7-der.test"
    assert found[0].public_key_algorithm == "RSA"
    assert found[0].self_signed is True


def test_finds_certificates_in_a_pem_pkcs7_bundle(tmp_path: Path) -> None:
    cert, key = _self_signed_cert("pkcs7-pem.test")
    bundle = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"")
        .add_signer(cert, key, hashes.SHA256())
        .sign(
            serialization.Encoding.PEM,
            [pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.DetachedSignature],
        )
    )
    (tmp_path / "bundle.p7c").write_bytes(bundle)

    found = find_pkcs7_certificates(tmp_path)
    assert len(found) == 1
    assert found[0].subject == "CN=pkcs7-pem.test"


def test_ignores_non_pkcs7_files_with_matching_extensions(tmp_path: Path) -> None:
    (tmp_path / "not-really-pkcs7.p7b").write_bytes(b"this is not a pkcs7 bundle at all")
    found = find_pkcs7_certificates(tmp_path)
    assert found == []


def test_ignores_files_without_pkcs7_extensions(tmp_path: Path) -> None:
    cert, key = _self_signed_cert("ignored.test")
    bundle = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"")
        .add_signer(cert, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.DetachedSignature],
        )
    )
    (tmp_path / "bundle.bin").write_bytes(bundle)
    found = find_pkcs7_certificates(tmp_path)
    assert found == []


def test_walks_subdirectories(tmp_path: Path) -> None:
    cert, key = _self_signed_cert("nested.test")
    bundle = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"")
        .add_signer(cert, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.DetachedSignature],
        )
    )
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (nested / "bundle.p7b").write_bytes(bundle)

    found = find_pkcs7_certificates(tmp_path)
    assert len(found) == 1
    assert found[0].subject == "CN=nested.test"
