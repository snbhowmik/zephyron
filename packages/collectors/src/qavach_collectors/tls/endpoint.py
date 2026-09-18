"""ARCH.md §2.2 `tls.endpoint` — QAVACH's own TLS handshake probe. T-035.

Resolves OQ-10 (`NOTE.md`'s decision log, T-035 entry): **stays fully
custom, does not wrap testssl.sh.** Every classical check ARCH.md asks
for — protocol version, cipher suite, full certificate chain, per-cert
public-key algorithm/size/curve, signature algorithm, validity, SANs,
SHA-256 fingerprint, SPKI hash — comes from the system's own `openssl
s_client`, not a new dependency (the same OpenSSL library Python's `ssl`
module itself binds to). `s_client -showcerts` prints the full chain as
PEM blocks and a `Negotiated TLS1.3 group: ...` line, both confirmed live
against a real local `openssl s_server` fixture — output stdlib `ssl`
cannot produce at all on Python 3.12 (`SSLSocket.get_unverified_chain()`
is 3.13+ only, and there is no public API for the negotiated group,
confirmed live: `dir(ssl.SSLSocket)` has no `group()` method).

**Hybrid group probing** (the actual reason to own this collector — 'no
existing scanner probes hybrid post-quantum key-exchange groups,' `NOTE.md`
OQ-10): confirmed live that `openssl s_client -groups <name>` accepts
real hybrid names (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`SecP384r1MLKEM1024` — the exact strings `openssl list -tls-groups`
reports on this machine's OpenSSL 3.5.8) and correctly reports which one a
server actually negotiates, against both a real public endpoint and an
offline `openssl s_server` test fixture. testssl.sh has no equivalent
capability regardless of the OQ-10 choice, so the wrap-vs-custom decision
never touched this half at all — only the classical checks were in play,
and stdlib+openssl-CLI already cover them for free.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from qavach_collectors.tls.ssrf import NetworkPolicy, ResolvedTarget, resolve_and_validate

HYBRID_GROUP_CANDIDATES = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
"""Verified live against `openssl list -tls-groups` on OpenSSL 3.5.8 —
the exact hybrid classical+ML-KEM group names it recognises. Re-verify
this list against a newer OpenSSL before assuming a name not listed here
is unsupported; the hybrid-group namespace is still evolving."""

_PROBE_TIMEOUT_SECONDS = 15.0


class TlsProbeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    sans: tuple[str, ...]
    public_key_algorithm: str
    public_key_size_bits: int | None
    curve_name: str | None
    signature_algorithm_oid: str
    sha256_fingerprint_hex: str
    spki_sha256_hex: str


@dataclass(frozen=True, slots=True)
class HandshakeResult:
    protocol_version: str
    cipher_suite: str
    negotiated_group: str | None
    chain: tuple[CertificateInfo, ...]


@dataclass(frozen=True, slots=True)
class HybridProbeResult:
    candidates_tested: tuple[str, ...]
    accepted: tuple[str, ...]
    """Every candidate group the server actually negotiated when offered
    alone — usually 0 or 1 entries, but a server could accept more than
    one across separate probe connections if its own preference varies,
    so this is never collapsed to a single value."""


def parse_certificate_der(der_bytes: bytes) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der_bytes)
    return _certificate_info_from_x509(cert)


def parse_certificate_pem(pem_bytes: bytes) -> CertificateInfo:
    cert = x509.load_pem_x509_certificate(pem_bytes)
    return _certificate_info_from_x509(cert)


def _certificate_info_from_x509(cert: x509.Certificate) -> CertificateInfo:
    pubkey = cert.public_key()

    public_key_algorithm: str
    size_bits: int | None = None
    curve_name: str | None = None
    if isinstance(pubkey, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
        size_bits = pubkey.key_size
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
        curve_name = pubkey.curve.name
        size_bits = pubkey.key_size
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        public_key_algorithm = "Ed25519"
    elif isinstance(pubkey, ed448.Ed448PublicKey):
        public_key_algorithm = "Ed448"
    elif isinstance(pubkey, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
        size_bits = pubkey.key_size
    else:
        public_key_algorithm = type(pubkey).__name__

    try:
        sans_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = tuple(str(name.value) for name in sans_ext.value)
    except x509.ExtensionNotFound:
        sans = ()

    spki_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_hasher = hashes.Hash(hashes.SHA256())
    spki_hasher.update(spki_bytes)

    fingerprint_hasher = hashes.Hash(hashes.SHA256())
    fingerprint_hasher.update(cert.public_bytes(serialization.Encoding.DER))

    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=sans,
        public_key_algorithm=public_key_algorithm,
        public_key_size_bits=size_bits,
        curve_name=curve_name,
        signature_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
        sha256_fingerprint_hex=fingerprint_hasher.finalize().hex(),
        spki_sha256_hex=spki_hasher.finalize().hex(),
    )


_PEM_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
_PROTOCOL_CIPHER_RE = re.compile(r"New, (\S+), Cipher is (\S+)")
_NEGOTIATED_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group: (\S+)")


def _run_s_client(target: ResolvedTarget, *, groups: str | None = None) -> str:
    address = f"{target.address}:{target.port}"
    if target.address.version == 6:
        address = f"[{target.address}]:{target.port}"
    command = [
        "openssl",
        "s_client",
        "-connect",
        address,
        "-servername",
        target.hostname,
        "-showcerts",
    ]
    if groups is not None:
        command += ["-groups", groups]
    try:
        proc = subprocess.run(
            command,
            input=b"",
            capture_output=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise TlsProbeError(f"openssl s_client timed out probing {target.hostname}") from exc
    return proc.stdout.decode(errors="replace")


def perform_handshake(target: ResolvedTarget) -> HandshakeResult:
    """One `openssl s_client -showcerts` connection using the default
    group offer — gives protocol version, cipher suite, the full
    certificate chain and, whenever the default negotiation already lands
    on a hybrid group, that too, without needing a separate probe."""
    output = _run_s_client(target)

    protocol_cipher_match = _PROTOCOL_CIPHER_RE.search(output)
    if protocol_cipher_match is None:
        raise TlsProbeError(
            f"could not complete a TLS handshake with {target.hostname}: {output[-500:]}"
        )
    protocol_version, cipher_suite = protocol_cipher_match.groups()

    group_match = _NEGOTIATED_GROUP_RE.search(output)
    negotiated_group = group_match.group(1) if group_match else None

    pem_blocks = _PEM_BLOCK_RE.findall(output.encode())
    chain = tuple(parse_certificate_pem(block) for block in pem_blocks)

    return HandshakeResult(
        protocol_version=protocol_version,
        cipher_suite=cipher_suite,
        negotiated_group=negotiated_group,
        chain=chain,
    )


def probe_hybrid_groups(
    target: ResolvedTarget, *, candidates: tuple[str, ...] = HYBRID_GROUP_CANDIDATES
) -> HybridProbeResult:
    """One connection per candidate group, offered alone, so a positive
    result unambiguously means the server accepted *that* group — not
    merely that it was included among several offered together."""
    accepted: list[str] = []
    for candidate in candidates:
        output = _run_s_client(target, groups=candidate)
        match = _NEGOTIATED_GROUP_RE.search(output)
        if match is not None and match.group(1) == candidate:
            accepted.append(candidate)
    return HybridProbeResult(candidates_tested=candidates, accepted=tuple(accepted))


def probe_endpoint(
    hostname: str, port: int, *, policy: NetworkPolicy
) -> tuple[HandshakeResult, HybridProbeResult]:
    """The full `tls.endpoint` probe for one target: resolve-then-pin
    against the SSRF policy (`ssrf.resolve_and_validate`), then the
    classical handshake, then the hybrid-group probe. Raises
    `SsrfDeniedError`/`TlsProbeError` on failure — the caller (the
    `Collector` implementation) is responsible for turning that into a
    `CollectorResult(partial=True, ...)`, matching every other collector's
    'failure is isolated' contract rather than this function silently
    swallowing it."""
    target = resolve_and_validate(hostname, port, policy=policy)
    handshake = perform_handshake(target)
    hybrid = probe_hybrid_groups(target)
    return handshake, hybrid
