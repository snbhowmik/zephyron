"""T-042 — `ssh.hostkey` network probe: the KEXINIT parser (including
hostile input) and the collector against a real local `sshd`."""

from __future__ import annotations

import json
import socket
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml
from _sshd_fixture import SSHD_AVAILABLE, run_sshd
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.ssh import (
    SshHostKeyCollector,
    SshProbeError,
    parse_host_key_line,
    parse_kexinit,
    read_kexinit,
)
from qavach_collectors.ssh.probe import scan_types_for
from qavach_collectors.tls import NetworkPolicy, ResolvedTarget
from qavach_core.normalize import AliasTable, CryptographyRegistry, resolve_algorithm
from qavach_core.normalize.resolve import RawAlgorithmClaim, ResolvedAlgorithm

ROOT = Path(__file__).parent.parent.parent
_ALLOW_LOOPBACK = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})


def _name_list(items: list[str]) -> bytes:
    raw = ",".join(items).encode()
    return struct.pack(">I", len(raw)) + raw


def build_kexinit(
    kex: list[str],
    host_keys: list[str],
    ciphers: list[str],
    macs: list[str],
) -> bytes:
    lists = [kex, host_keys, ciphers, ciphers, macs, macs, ["none"], ["none"], [], []]
    return bytes([20]) + b"\x00" * 16 + b"".join(_name_list(x) for x in lists) + b"\x00" + b"\0" * 4


def _packet(payload: bytes) -> bytes:
    padding = 8 - ((len(payload) + 5) % 8)
    padding = padding + 8 if padding < 4 else padding
    body = bytes([padding]) + payload + b"\x00" * padding
    return struct.pack(">I", len(body)) + body


@contextmanager
def fake_server(response: bytes) -> Iterator[int]:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                conn.sendall(response)
                conn.settimeout(1)
                try:
                    conn.recv(1024)
                except OSError:
                    pass
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()


def _target(port: int) -> ResolvedTarget:
    from ipaddress import ip_address

    return ResolvedTarget(hostname="localhost", address=ip_address("127.0.0.1"), port=port)


def test_parse_kexinit_extracts_the_lists() -> None:
    payload = build_kexinit(
        ["mlkem768x25519-sha256", "curve25519-sha256"],
        ["ssh-ed25519"],
        ["aes256-ctr"],
        ["hmac-sha2-256"],
    )
    parsed = parse_kexinit(payload, banner="SSH-2.0-x")
    assert parsed.kex_algorithms == ("mlkem768x25519-sha256", "curve25519-sha256")
    assert parsed.host_key_algorithms == ("ssh-ed25519",)
    assert parsed.encryption_algorithms == ("aes256-ctr",)
    assert parsed.mac_algorithms == ("hmac-sha2-256",)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x15" + b"\x00" * 40,
        bytes([20]) + b"\x00" * 16 + struct.pack(">I", 2**31) + b"abc",
        bytes([20]) + b"\x00" * 16 + b"\x00\x00",
    ],
)
def test_parse_kexinit_rejects_malformed_payloads(payload: bytes) -> None:
    with pytest.raises(SshProbeError):
        parse_kexinit(payload)


def test_read_kexinit_from_a_scripted_server() -> None:
    payload = build_kexinit(["curve25519-sha256"], ["ssh-ed25519"], ["aes128-ctr"], ["hmac-sha1"])
    with fake_server(b"noise before banner\r\nSSH-2.0-Test_1\r\n" + _packet(payload)) as port:
        parsed = read_kexinit(_target(port))
    assert parsed.banner == "SSH-2.0-Test_1"
    assert parsed.kex_algorithms == ("curve25519-sha256",)


def test_implausible_packet_length_is_refused_before_allocation() -> None:
    with fake_server(b"SSH-2.0-Evil\r\n" + struct.pack(">I", 0x7FFFFFFF)) as port:
        with pytest.raises(SshProbeError, match="implausible"):
            read_kexinit(_target(port))


def test_endless_banner_is_capped() -> None:
    with fake_server(b"A" * 10000) as port:
        with pytest.raises(SshProbeError, match="cap"):
            read_kexinit(_target(port))


def test_server_that_hangs_up_degrades() -> None:
    with fake_server(b"SSH-2.0-x\r\n") as port:
        with pytest.raises(SshProbeError):
            read_kexinit(_target(port))


def test_scan_types_derived_from_advertised_algorithms() -> None:
    assert scan_types_for(
        ("rsa-sha2-512", "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519-cert-v01@openssh.com")
    ) == ("rsa", "ecdsa", "ed25519")


def test_parse_host_key_line_rejects_junk() -> None:
    assert parse_host_key_line("# comment") is None
    assert parse_host_key_line("host ssh-rsa !!!notbase64") is None
    assert parse_host_key_line("too short") is None


@pytest.mark.skipif(not SSHD_AVAILABLE, reason="no sshd/ssh-keyscan on PATH")
def test_collector_against_a_real_sshd(tmp_path: Path) -> None:
    with run_sshd(tmp_path) as port:
        result = SshHostKeyCollector(policy=_ALLOW_LOOPBACK).collect(
            Target(type=TargetType.NETWORK_ENDPOINT, ref=f"127.0.0.1:{port}"),
            RunContext(scan_run_id="r"),
        )
    assert not result.partial, result.errors
    raw = json.loads(result.raw)
    assert raw["banner"].startswith("SSH-2.0-OpenSSH")

    sigs = {(c.name, c.parameter_set) for c in result.claims if c.primitive == "signature"}
    assert ("RSA", "3072") in sigs
    assert ("EdDSA", None) in sigs
    assert all(c.confidence.name == "RUNTIME" for c in result.claims)
    assert result.claims[0].locus.protocol == "ssh"  # type: ignore[union-attr]

    assert any(c.name == "ECDH" and c.parameter_set == "x25519" for c in result.claims)
    assert any(c.name == "AES" and c.mode == "ctr" for c in result.claims)
    assert not any(c.name in ("ext-info-s", "kex-strict-s-v00@openssh.com") for c in result.claims)


def test_unmapped_algorithm_is_reported_by_name_not_dropped() -> None:
    payload = build_kexinit(["frobnicate-sha3"], [], ["aes256-ctr"], ["hmac-sha2-256"])
    with fake_server(b"SSH-2.0-x\r\n" + _packet(payload)) as port:
        result = SshHostKeyCollector(policy=_ALLOW_LOOPBACK).collect(
            Target(type=TargetType.NETWORK_ENDPOINT, ref=f"127.0.0.1:{port}"),
            RunContext(scan_run_id="r"),
        )
    assert any(c.name == "frobnicate-sha3" and c.primitive is None for c in result.claims)


def test_etm_and_weak_algorithms_map() -> None:
    payload = build_kexinit(
        ["diffie-hellman-group1-sha1", "mlkem768x25519-sha256"],
        [],
        ["3des-cbc", "aes256-gcm@openssh.com", "arcfour"],
        ["hmac-sha1-etm@openssh.com"],
    )
    with fake_server(b"SSH-2.0-x\r\n" + _packet(payload)) as port:
        result = SshHostKeyCollector(policy=_ALLOW_LOOPBACK).collect(
            Target(type=TargetType.NETWORK_ENDPOINT, ref=f"127.0.0.1:{port}"),
            RunContext(scan_run_id="r"),
        )
    names = {(c.name, c.parameter_set) for c in result.claims}
    assert ("FFDH", "1024") in names
    assert ("ML-KEM", "768") in names
    assert ("3DES", None) in names
    assert ("RC4", None) in names
    assert ("HMAC", "SHA-1") in names
    gcm = [c for c in result.claims if c.name == "AES"]
    assert gcm[0].mode == "gcm" and gcm[0].primitive == "ae"


def test_private_address_is_refused_by_default_policy() -> None:
    from qavach_collectors.tls import SsrfDeniedError  # noqa: F401

    default = NetworkPolicy.from_dict(
        yaml.safe_load((ROOT / "config" / "security" / "network_policy.yaml").read_text())
    )
    result = SshHostKeyCollector(policy=default).collect(
        Target(type=TargetType.NETWORK_ENDPOINT, ref="127.0.0.1:22"), RunContext(scan_run_id="r")
    )
    assert result.partial and result.errors[0].fatal
    assert result.claims == []


def test_bad_ref_and_supports() -> None:
    collector = SshHostKeyCollector(policy=_ALLOW_LOOPBACK)
    assert collector.supports(Target(type=TargetType.NETWORK_ENDPOINT, ref="h:22"))
    assert not collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))
    assert collector.collect(
        Target(type=TargetType.NETWORK_ENDPOINT, ref="nohost"), RunContext(scan_run_id="r")
    ).partial


def test_every_mapped_name_resolves_in_the_registry() -> None:
    """The mapping table is only useful if the names it emits are ones the
    registry/aliases actually resolve (I8 would otherwise flag all of SSH as UNKNOWN)."""
    from qavach_collectors.ssh import collector as mod

    registry = CryptographyRegistry.from_dict(
        json.loads(
            (ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text()
        )
    )
    aliases = AliasTable.from_dict(
        yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text())
    )
    for table in (mod._KEX, mod._CIPHER, mod._MAC):
        for algorithm, (name, primitive, parameter_set) in table.items():
            resolved = resolve_algorithm(
                RawAlgorithmClaim(
                    name=name, oid=None, primitive=primitive, parameter_set=parameter_set
                ),
                registry=registry,
                aliases=aliases,
            )
            assert isinstance(resolved, ResolvedAlgorithm), f"{algorithm} -> {name}"
