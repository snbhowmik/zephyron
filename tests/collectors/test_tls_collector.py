"""T-035 — `TlsEndpointCollector`, against the same real local
`openssl s_server` fixture, proving the full `Collector` protocol
pipeline: SSRF check, real handshake, real hybrid probe, mapped into
`RawClaim`s with the correct loci and algorithm names."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from _tls_test_server import OPENSSL_AVAILABLE, run_test_tls_server
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.tls import NetworkPolicy, TlsEndpointCollector

ROOT = Path(__file__).parent.parent.parent
pytestmark = pytest.mark.skipif(not OPENSSL_AVAILABLE, reason="no openssl on PATH")

_ALLOW_LOOPBACK_POLICY = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})


def test_supports_only_network_endpoint_targets() -> None:
    collector = TlsEndpointCollector(policy=_ALLOW_LOOPBACK_POLICY)
    assert collector.supports(Target(type=TargetType.NETWORK_ENDPOINT, ref="example.com:443"))
    assert not collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))


def test_collect_against_a_real_server_produces_certificate_and_hybrid_claims(
    tmp_path: Path,
) -> None:
    with run_test_tls_server(tmp_path=tmp_path, groups="X25519MLKEM768:X25519") as server:
        collector = TlsEndpointCollector(policy=_ALLOW_LOOPBACK_POLICY)
        result = collector.collect(
            Target(type=TargetType.NETWORK_ENDPOINT, ref=f"localhost:{server.port}"),
            RunContext(scan_run_id="run-1"),
        )

    assert not result.partial
    assert result.errors == []
    assert result.tool.exit_code == 0

    cert_claims = [c for c in result.claims if c.name == "RSA"]
    assert len(cert_claims) == 1
    assert cert_claims[0].primitive == "signature"
    assert cert_claims[0].parameter_set == "2048"
    assert cert_claims[0].locus.host == "localhost"  # type: ignore[union-attr]
    assert cert_claims[0].locus.port == server.port  # type: ignore[union-attr]
    assert cert_claims[0].confidence.name == "RUNTIME"

    hybrid_claims = [c for c in result.claims if c.name == "ML-KEM"]
    assert len(hybrid_claims) == 1
    assert hybrid_claims[0].parameter_set == "X25519MLKEM768"
    assert hybrid_claims[0].primitive == "kem"


def test_collect_against_a_classical_only_server_produces_no_hybrid_claim(tmp_path: Path) -> None:
    with run_test_tls_server(tmp_path=tmp_path, groups="X25519:secp256r1") as server:
        collector = TlsEndpointCollector(policy=_ALLOW_LOOPBACK_POLICY)
        result = collector.collect(
            Target(type=TargetType.NETWORK_ENDPOINT, ref=f"localhost:{server.port}"),
            RunContext(scan_run_id="run-1"),
        )

    assert not result.partial
    assert not any(c.name == "ML-KEM" for c in result.claims)
    assert any(c.name == "RSA" for c in result.claims)


def test_ssrf_denial_is_reported_as_partial_not_raised() -> None:
    """The production denylist rejecting a target must degrade the
    collector's result, per every other collector's own contract — never
    propagate as an uncaught exception."""
    real_policy = NetworkPolicy.from_dict(
        yaml.safe_load((ROOT / "config" / "security" / "network_policy.yaml").read_text())
    )
    collector = TlsEndpointCollector(policy=real_policy)
    result = collector.collect(
        Target(type=TargetType.NETWORK_ENDPOINT, ref="localhost:443"),
        RunContext(scan_run_id="run-1"),
    )
    assert result.partial
    assert result.claims == []
    assert result.errors[0].fatal


def test_malformed_target_ref_is_reported_as_partial_not_raised() -> None:
    collector = TlsEndpointCollector(policy=_ALLOW_LOOPBACK_POLICY)
    result = collector.collect(
        Target(type=TargetType.NETWORK_ENDPOINT, ref="not-a-host-port"),
        RunContext(scan_run_id="run-1"),
    )
    assert result.partial
    assert "not a valid host:port" in result.errors[0].message
