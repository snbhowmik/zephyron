"""T-035 — `tls/endpoint.py`, against a real local `openssl s_server`
fixture (`_tls_test_server.py`), not a mock: proves `openssl s_client`
parsing actually extracts the real certificate chain, protocol version,
cipher suite and hybrid-group negotiation this collector depends on.

`resolve_and_validate` is exercised via `localhost` (always resolves to
`127.0.0.1`/`::1` without any live network dependency) with a
test-specific policy that allows loopback — the *production* default
policy's denial of loopback is `test_tls_ssrf.py`'s job, not this file's.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from _tls_test_server import OPENSSL_AVAILABLE, run_test_tls_server
from qavach_collectors.tls import (
    NetworkPolicy,
    SsrfDeniedError,
    parse_certificate_pem,
    perform_handshake,
    probe_endpoint,
    probe_hybrid_groups,
    resolve_and_validate,
)

ROOT = Path(__file__).parent.parent.parent

_ALLOW_LOOPBACK_POLICY = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})

pytestmark = pytest.mark.skipif(not OPENSSL_AVAILABLE, reason="no openssl on PATH")


def test_parse_certificate_pem_extracts_real_fields(tmp_path: Path) -> None:
    with run_test_tls_server(tmp_path=tmp_path) as server:
        info = parse_certificate_pem(server.cert_pem)
    assert info.subject == "CN=qavach-test.local"
    assert set(info.sans) == {"qavach-test.local", "alt.qavach-test.local"}
    assert info.public_key_algorithm == "RSA"
    assert info.public_key_size_bits == 2048
    assert len(info.sha256_fingerprint_hex) == 64
    assert len(info.spki_sha256_hex) == 64
    assert info.not_before < info.not_after


def test_perform_handshake_against_a_real_local_server(tmp_path: Path) -> None:
    with run_test_tls_server(tmp_path=tmp_path) as server:
        target = resolve_and_validate("localhost", server.port, policy=_ALLOW_LOOPBACK_POLICY)
        result = perform_handshake(target)

    assert result.protocol_version == "TLSv1.3"
    assert "TLS_" in result.cipher_suite or "AES" in result.cipher_suite
    assert len(result.chain) == 1
    assert result.chain[0].public_key_algorithm == "RSA"


def test_probe_hybrid_groups_detects_a_real_supported_group(tmp_path: Path) -> None:
    """The core reason to own this collector: a server configured to
    support `X25519MLKEM768` must be positively detected when that group
    is offered alone — not merely inferred from a default handshake."""
    with run_test_tls_server(tmp_path=tmp_path, groups="X25519MLKEM768:X25519") as server:
        target = resolve_and_validate("localhost", server.port, policy=_ALLOW_LOOPBACK_POLICY)
        result = probe_hybrid_groups(target, candidates=("X25519MLKEM768", "SecP384r1MLKEM1024"))

    assert result.accepted == ("X25519MLKEM768",)
    assert result.candidates_tested == ("X25519MLKEM768", "SecP384r1MLKEM1024")


def test_probe_hybrid_groups_reports_none_accepted_for_a_classical_only_server(
    tmp_path: Path,
) -> None:
    with run_test_tls_server(tmp_path=tmp_path, groups="X25519:secp256r1") as server:
        target = resolve_and_validate("localhost", server.port, policy=_ALLOW_LOOPBACK_POLICY)
        result = probe_hybrid_groups(target, candidates=("X25519MLKEM768",))

    assert result.accepted == ()


def test_probe_endpoint_end_to_end(tmp_path: Path) -> None:
    with run_test_tls_server(tmp_path=tmp_path, groups="X25519MLKEM768:X25519") as server:
        handshake, hybrid = probe_endpoint("localhost", server.port, policy=_ALLOW_LOOPBACK_POLICY)

    assert handshake.protocol_version == "TLSv1.3"
    assert len(handshake.chain) == 1
    assert "X25519MLKEM768" in hybrid.accepted


def test_probe_endpoint_ssrf_denial_prevents_any_connection(tmp_path: Path) -> None:
    """The production denylist must stop the probe *before* any socket is
    opened — proven by pointing at a real running server but using the
    real (loopback-denying) policy instead of the test-only one."""
    real_policy = NetworkPolicy.from_dict(
        yaml.safe_load((ROOT / "config" / "security" / "network_policy.yaml").read_text())
    )
    with run_test_tls_server(tmp_path=tmp_path) as server:
        with pytest.raises(SsrfDeniedError):
            probe_endpoint("localhost", server.port, policy=real_policy)
