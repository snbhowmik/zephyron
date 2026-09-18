"""ARCH.md §2.2 `ssh.hostkey`, network-probe half. T-042 / `PRD.md FR-160`.

Two things are read from an SSH server, neither needing authentication:

1. **Its `SSH_MSG_KEXINIT`** (RFC 4253 §7.1). Both sides send their
   algorithm preference lists in the clear immediately after the version
   exchange, before any key exchange. That message is the server's complete
   statement of the key-exchange, host-key, cipher and MAC algorithms it is
   willing to use — including post-quantum hybrids such as
   `mlkem768x25519-sha256`. Parsed here in pure Python: it is a length-
   prefixed binary format, a few dozen lines, and there is no library to
   wrap.
2. **Its host keys**, via `ssh-keyscan` — the server's actual public key is
   only sent inside the key exchange, which needs a real KEX implementation.
   `ssh-keyscan` is the OpenSSH project's own tool for exactly this and
   parses to a key we then size with `cryptography`.

Everything the server *offers* is reported, not what any particular client
would negotiate; the claim records that the server accepts an algorithm, not
that every connection uses it (`NOTE.md`, T-042 entry).

Untrusted input (`SECURITY.md §9`): the server is hostile. The version
banner is capped in lines and bytes, the packet length is capped at the RFC
4253 §6.1 maximum before any allocation, and a malformed name-list raises a
typed error rather than indexing past the buffer.
"""

from __future__ import annotations

import socket
import struct
import subprocess
from dataclasses import dataclass

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from qavach_collectors.tls.ssrf import ResolvedTarget

SSH_MSG_KEXINIT = 20
_MAX_PACKET = 35000
"""RFC 4253 §6.1: implementations MUST handle packets up to 35000 bytes."""
_MAX_BANNER_BYTES = 4096
_MAX_PRE_BANNER_LINES = 64
_CLIENT_BANNER = b"SSH-2.0-QAVACH_probe\r\n"
_PROBE_TIMEOUT_SECONDS = 10.0

PSEUDO_ALGORITHMS = frozenset(
    {
        "ext-info-c",
        "ext-info-s",
        "kex-strict-c-v00@openssh.com",
        "kex-strict-s-v00@openssh.com",
    }
)
"""KEX-list entries that are protocol signalling, not algorithms."""


class SshProbeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class KexInit:
    banner: str
    kex_algorithms: tuple[str, ...]
    host_key_algorithms: tuple[str, ...]
    encryption_algorithms: tuple[str, ...]
    """Union of client-to-server and server-to-client, order preserved."""
    mac_algorithms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HostKey:
    key_type: str
    algorithm: str
    """`RSA`, `ECDSA`, `EdDSA` or `DSA` — matching `tls.endpoint`'s claim names."""
    size_bits: int | None
    curve_name: str | None


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise SshProbeError("server closed the connection before sending its KEXINIT")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_banner(sock: socket.socket) -> str:
    """The server may send free-form lines before its `SSH-2.0-` banner
    (RFC 4253 §4.2); bounded so a server that never sends one cannot pin us."""
    total = 0
    for _ in range(_MAX_PRE_BANNER_LINES):
        line = bytearray()
        while not line.endswith(b"\n"):
            byte = sock.recv(1)
            if not byte:
                raise SshProbeError("server closed the connection before sending a banner")
            line += byte
            total += 1
            if total > _MAX_BANNER_BYTES:
                raise SshProbeError("SSH banner exceeded the size cap")
        text = bytes(line).decode("utf-8", errors="replace").rstrip("\r\n")
        if text.startswith("SSH-"):
            return text
    raise SshProbeError("no SSH version banner within the line cap")


def parse_kexinit(payload: bytes, *, banner: str = "") -> KexInit:
    """Parses the payload of an `SSH_MSG_KEXINIT` packet (RFC 4253 §7.1):
    `byte 20`, 16 cookie bytes, then ten `name-list`s (uint32 length +
    comma-separated ASCII), a first-kex-follows byte and a reserved uint32."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise SshProbeError("first SSH packet was not a KEXINIT")
    offset = 17
    lists: list[tuple[str, ...]] = []
    for _ in range(10):
        if offset + 4 > len(payload):
            raise SshProbeError("KEXINIT truncated inside a name-list header")
        (length,) = struct.unpack_from(">I", payload, offset)
        offset += 4
        if length > len(payload) - offset:
            raise SshProbeError("KEXINIT name-list length runs past the packet")
        raw = payload[offset : offset + length].decode("ascii", errors="replace")
        offset += length
        lists.append(tuple(item for item in raw.split(",") if item))

    kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c = (
        lists[0],
        lists[1],
        lists[2],
        lists[3],
        lists[4],
        lists[5],
    )
    return KexInit(
        banner=banner,
        kex_algorithms=kex,
        host_key_algorithms=host_key,
        encryption_algorithms=tuple(dict.fromkeys(enc_c2s + enc_s2c)),
        mac_algorithms=tuple(dict.fromkeys(mac_c2s + mac_s2c)),
    )


def read_kexinit(target: ResolvedTarget) -> KexInit:
    try:
        sock = socket.create_connection(
            (str(target.address), target.port), timeout=_PROBE_TIMEOUT_SECONDS
        )
    except OSError as exc:
        raise SshProbeError(f"could not connect to {target.hostname}:{target.port}: {exc}") from exc
    with sock:
        sock.settimeout(_PROBE_TIMEOUT_SECONDS)
        try:
            sock.sendall(_CLIENT_BANNER)
            banner = _read_banner(sock)
            (packet_length,) = struct.unpack(">I", _read_exact(sock, 4))
            if not 6 <= packet_length <= _MAX_PACKET:
                raise SshProbeError(f"implausible SSH packet length {packet_length}")
            body = _read_exact(sock, packet_length)
        except (TimeoutError, OSError) as exc:
            raise SshProbeError(f"SSH probe of {target.hostname} failed: {exc}") from exc
    padding_length = body[0]
    if padding_length + 1 > len(body):
        raise SshProbeError("SSH packet padding exceeds packet length")
    return parse_kexinit(body[1 : len(body) - padding_length], banner=banner)


_HOST_KEY_ALGORITHM_TO_SCAN_TYPE = (
    ("ssh-rsa", "rsa"),
    ("rsa-sha2-256", "rsa"),
    ("rsa-sha2-512", "rsa"),
    ("ecdsa-sha2-", "ecdsa"),
    ("ssh-ed25519", "ed25519"),
    ("ssh-dss", "dsa"),
)


def scan_types_for(host_key_algorithms: tuple[str, ...]) -> tuple[str, ...]:
    """The `ssh-keyscan -t` types worth asking for, derived from what the
    server itself advertised (certificate variants collapse to their key
    type; asking for a type the server doesn't have just wastes a connection)."""
    found: list[str] = []
    for algorithm in host_key_algorithms:
        bare = algorithm.removesuffix("-cert-v01@openssh.com")
        for prefix, scan_type in _HOST_KEY_ALGORITHM_TO_SCAN_TYPE:
            if bare.startswith(prefix) and scan_type not in found:
                found.append(scan_type)
    return tuple(found)


def parse_host_key_line(line: str) -> HostKey | None:
    """One `ssh-keyscan` output line: `<host> <type> <base64>`. Returns
    `None` for comments and lines that are not a key."""
    if line.startswith("#") or not line.strip():
        return None
    parts = line.split()
    if len(parts) < 3:
        return None
    key_type, blob = parts[1], parts[2]
    try:
        key = load_ssh_public_key(f"{key_type} {blob}".encode("ascii"))
    except (ValueError, UnicodeEncodeError, UnsupportedAlgorithm):
        return None
    if isinstance(key, rsa.RSAPublicKey):
        return HostKey(key_type, "RSA", key.key_size, None)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return HostKey(key_type, "ECDSA", key.key_size, key.curve.name)
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return HostKey(key_type, "EdDSA", None, None)
    if isinstance(key, dsa.DSAPublicKey):
        return HostKey(key_type, "DSA", key.key_size, None)
    return None


def scan_host_keys(target: ResolvedTarget, scan_types: tuple[str, ...]) -> list[HostKey]:
    """Runs `ssh-keyscan` once per type so one type the local OpenSSH build
    refuses (`-t dsa` on a modern client) cannot discard the others. The
    address is the SSRF-pinned IP, never the hostname."""
    keys: list[HostKey] = []
    for scan_type in scan_types:
        command = [
            "ssh-keyscan",
            "-T",
            "5",
            "-t",
            scan_type,
            "-p",
            str(target.port),
            str(target.address),
        ]
        try:
            proc = subprocess.run(
                command, capture_output=True, timeout=_PROBE_TIMEOUT_SECONDS, check=False
            )
        except FileNotFoundError as exc:
            raise SshProbeError("ssh-keyscan is not installed") from exc
        except subprocess.TimeoutExpired:
            continue
        for line in proc.stdout.decode("ascii", errors="replace").splitlines():
            key = parse_host_key_line(line)
            if key is not None and key not in keys:
                keys.append(key)
    return keys
