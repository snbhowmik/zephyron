"""Request signing and the result wire format (T-073a)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from qavach_agent.runtime import deserialize_collector_result, serialize_collector_result
from qavach_agent.signing import MAX_SKEW_SECONDS, sign_request, verify_request
from qavach_collectors import CollectorResult, RawClaim, RawFormat, ToolIdentity
from qavach_core.model import ConfidenceTier, FileLocus

NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)


def credential() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """A real client certificate for a real key. `verify_request` checks the
    signature and validity, not the issuer (the backend looks the certificate up
    by agent id), so a self-signed one exercises the same code."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM)


def signed(key: ec.EllipticCurvePrivateKey, **over: object) -> dict[str, object]:
    args = {"method": "POST", "target": "/api/v1/agents/a/results", "body": b'{"x":1}'} | over
    ts = str(int(NOW.timestamp()))
    return {
        **args,
        "timestamp": ts,
        "signature_b64": sign_request(key, args["method"], args["target"], ts, args["body"]),  # type: ignore[arg-type]
    }


def test_a_signature_verifies_and_any_tampering_breaks_it() -> None:
    key, pem = credential()
    good = signed(key)
    assert verify_request(pem, now=NOW, **good)  # type: ignore[arg-type]
    for tampered in (
        {"body": b'{"x":2}'},
        {"target": "/api/v1/agents/b/results"},
        {"method": "GET"},
        {"timestamp": str(int(NOW.timestamp()) + 1)},
        {"signature_b64": "AAAA"},
        {"signature_b64": "not base64!!"},
    ):
        assert not verify_request(pem, now=NOW, **{**good, **tampered})  # type: ignore[arg-type]


def test_another_key_cannot_sign_for_this_credential() -> None:
    _, pem = credential()
    stranger = ec.generate_private_key(ec.SECP256R1())
    assert not verify_request(pem, now=NOW, **signed(stranger))  # type: ignore[arg-type]


def test_the_skew_window_and_certificate_validity_are_enforced() -> None:
    key, pem = credential()
    good = signed(key)
    edge = NOW + timedelta(seconds=MAX_SKEW_SECONDS)
    assert verify_request(pem, now=edge, **good)  # type: ignore[arg-type]
    assert not verify_request(pem, now=edge + timedelta(seconds=1), **good)  # type: ignore[arg-type]
    expired = NOW + timedelta(days=31)
    fresh = {
        **good,
        "timestamp": str(int(expired.timestamp())),
        "signature_b64": sign_request(
            key, "POST", "/api/v1/agents/a/results", str(int(expired.timestamp())), b'{"x":1}'
        ),
    }
    assert not verify_request(pem, now=expired, **fresh)  # type: ignore[arg-type]


def test_garbage_input_is_a_false_not_an_exception() -> None:
    assert not verify_request(
        b"not a cert",
        method="GET",
        target="/",
        timestamp="soon",
        body=b"",
        signature_b64="",
        now=NOW,
    )


def test_a_collector_result_survives_the_wire_round_trip() -> None:
    result = CollectorResult(
        raw=b"\x00\x01raw",
        raw_format=RawFormat.QAVACH_NATIVE,
        claims=[
            RawClaim(
                locus=FileLocus(path="/a.jks", offset=3),
                name="RSA",
                oid="1.2.840.113549.1.1.1",
                primitive="signature",
                parameter_set="2048",
                mode=None,
                padding="pss",
                detection_method="keystore",
                confidence=ConfidenceTier.PATTERN,
            )
        ],
        tool=ToolIdentity("tls.store", "1.0", ("a", "b"), 0, 1.5),
        errors=[],
        partial=True,
    )
    assert deserialize_collector_result(serialize_collector_result(result)) == result
