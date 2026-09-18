"""T-036 — `tls.store`'s certfinder half. Pure parsing/mapping tests use
a hand-written fixture matching certfinder's *real* JSON schema (captured
live while building this collector — see the module docstring in
`store.py`); the integration test downloads and checksum-verifies the
actual pinned certfinder binary (`config/scanners.yaml`) and runs it
against real generated certificates and a real password-protected
keystore, proving both the resolved-certificate and the
undecryptable-keystore code paths against genuine tool output.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from _certfinder_fixture import CertfinderUnavailableError, ensure_certfinder_binary
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.tls import TlsStoreCollector, parse_certfinder_records, run_certfinder
from qavach_collectors.tls.store import _certificate_claims, _undecryptable_claim
from qavach_core.model import ConfidenceTier

REAL_SHAPED_RECORDS: list[dict[str, object]] = [
    {
        "path": "/etc/tomcat/server.pem",
        "index": 0,
        "subject": "CN=example.internal",
        "issuer": "CN=example.internal",
        "serial_number": "7905899a5136008dcf3c4b7e1034a3d1ccea2cf3",
        "is_ca": True,
        "self_signed": True,
        "sans": ["DNS:example.internal"],
        "public_key": {"algorithm": "RSA", "bits": 2048},
        "signature_algorithm": "SHA256-RSA",
        "fingerprints": {
            "sha1": "50671473a21f19d87e61e863137720d072d5feac",
            "sha256": "b5ff0a2d1012524469d3ba6eb340a4f6261ebaa95c3c3f71a196c7c69b157a23",
            "spki_sha256": "5a3b2d6ec5389f9581339a8dedb3b089e2c824852a69b7becf4b8c0dee516464",
        },
        "valid_from": "2026-09-18T22:24:00Z",
        "valid_to": "2026-09-19T22:24:00Z",
        "validity_status": "valid",
    },
    {
        "record_type": "pkcs12_encrypted_content",
        "path": "/etc/tomcat/keystore.jks",
        "pkcs12": {
            "status": "encrypted",
            "content_index": 1,
            "algorithm": "PBES2",
            "algorithm_oid": "1.2.840.113549.1.5.13",
            "bag_count": None,
        },
    },
]


def test_parses_a_resolved_certificate_record() -> None:
    certificates, undecryptable = parse_certfinder_records([REAL_SHAPED_RECORDS[0]])
    assert len(certificates) == 1
    assert undecryptable == []
    cert = certificates[0]
    assert cert.path == "/etc/tomcat/server.pem"
    assert cert.public_key_algorithm == "RSA"
    assert cert.public_key_bits == 2048
    assert cert.self_signed is True
    assert cert.spki_sha256 == "5a3b2d6ec5389f9581339a8dedb3b089e2c824852a69b7becf4b8c0dee516464"


def test_parses_an_undecryptable_keystore_record() -> None:
    certificates, undecryptable = parse_certfinder_records([REAL_SHAPED_RECORDS[1]])
    assert certificates == []
    assert len(undecryptable) == 1
    assert undecryptable[0].path == "/etc/tomcat/keystore.jks"


def test_parses_a_mixed_batch() -> None:
    certificates, undecryptable = parse_certfinder_records(REAL_SHAPED_RECORDS)
    assert len(certificates) == 1
    assert len(undecryptable) == 1


def test_collector_maps_resolved_certificate_to_a_raw_claim(tmp_path: Path) -> None:
    collector = TlsStoreCollector(certfinder_binary=Path("/does-not-need-to-exist-for-this-test"))
    certificates, _undecryptable = parse_certfinder_records([REAL_SHAPED_RECORDS[0]])
    claims = _certificate_claims(certificates[0], confidence=collector.default_confidence)
    assert len(claims) == 1
    assert claims[0].name == "RSA"
    assert claims[0].primitive == "signature"
    assert claims[0].parameter_set == "2048"
    assert claims[0].locus.path == "/etc/tomcat/server.pem"  # type: ignore[union-attr]


def test_undecryptable_keystore_maps_to_an_unnamed_claim() -> None:
    _certificates, undecryptable = parse_certfinder_records([REAL_SHAPED_RECORDS[1]])
    claim = _undecryptable_claim(undecryptable[0], confidence=ConfidenceTier.ARTEFACT)
    assert claim.name is None
    assert claim.oid is None
    assert claim.locus.path == "/etc/tomcat/keystore.jks"  # type: ignore[union-attr]


def test_supports_only_host_targets() -> None:
    collector = TlsStoreCollector(certfinder_binary=Path("/nonexistent"))
    assert collector.supports(Target(type=TargetType.HOST, ref="/etc/ssl"))
    assert not collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))


def test_certfinder_process_failure_is_reported_as_partial_not_raised(tmp_path: Path) -> None:
    fake_binary = tmp_path / "fake-certfinder-that-fails"
    fake_binary.write_text("#!/bin/sh\necho 'not json' >&1\nexit 1\n")
    fake_binary.chmod(0o755)

    collector = TlsStoreCollector(certfinder_binary=fake_binary)
    result = collector.collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="run-1")
    )
    assert result.partial
    assert result.claims == []


# --- Real integration: the actual pinned certfinder binary ---


@pytest.fixture(scope="module")
def certfinder_binary() -> Path:
    try:
        return ensure_certfinder_binary()
    except CertfinderUnavailableError as exc:
        pytest.skip(f"certfinder unavailable: {exc}")


@pytest.mark.integration
def test_real_certfinder_detects_a_real_certificate(
    certfinder_binary: Path, tmp_path: Path
) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "/dev/null",
            "-out",
            str(tmp_path / "server.pem"),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=qavach-test.internal",
        ],
        capture_output=True,
        check=True,
    )

    records = run_certfinder(certfinder_binary, tmp_path)
    certificates, undecryptable = parse_certfinder_records(records)

    assert undecryptable == []
    assert len(certificates) == 1
    assert certificates[0].subject == "CN=qavach-test.internal"
    assert certificates[0].public_key_algorithm == "RSA"
    assert certificates[0].public_key_bits == 2048
    assert len(certificates[0].sha256_fingerprint) == 64


@pytest.mark.integration
def test_real_certfinder_reports_an_encrypted_keystore_as_undecryptable(
    certfinder_binary: Path, tmp_path: Path
) -> None:
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-alias",
            "mykey",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "365",
            "-keystore",
            str(tmp_path / "keystore.jks"),
            "-storepass",
            "changeit",
            "-keypass",
            "changeit",
            "-dname",
            "CN=jks.internal",
        ],
        capture_output=True,
        check=True,
    )

    records = run_certfinder(certfinder_binary, tmp_path)
    _certificates, undecryptable = parse_certfinder_records(records)

    assert len(undecryptable) == 1
    assert undecryptable[0].path.endswith("keystore.jks")


@pytest.mark.integration
def test_real_collector_end_to_end(certfinder_binary: Path, tmp_path: Path) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "/dev/null",
            "-out",
            str(tmp_path / "server.pem"),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=qavach-collector-test.internal",
        ],
        capture_output=True,
        check=True,
    )

    collector = TlsStoreCollector(certfinder_binary=certfinder_binary)
    result = collector.collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="run-1")
    )

    assert not result.partial
    assert result.errors == []
    assert any(c.name == "RSA" for c in result.claims)
