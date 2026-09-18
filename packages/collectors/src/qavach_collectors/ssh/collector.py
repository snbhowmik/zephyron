"""`Collector` wrapper for the `ssh.hostkey` network probe. T-042."""

from __future__ import annotations

import json
import time

from qavach_core.model import ConfidenceTier, NetworkLocus

from qavach_collectors.base import (
    CollectorError,
    CollectorResult,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)
from qavach_collectors.ssh.probe import (
    PSEUDO_ALGORITHMS,
    HostKey,
    KexInit,
    SshProbeError,
    read_kexinit,
    scan_host_keys,
    scan_types_for,
)
from qavach_collectors.tls.ssrf import NetworkPolicy, SsrfDeniedError, resolve_and_validate

# (name, primitive, parameter_set) — names are CycloneDX registry families.
_Mapping = tuple[str, str | None, str | None]

_KEX: dict[str, _Mapping] = {
    "curve25519-sha256": ("ECDH", "key-agree", "x25519"),
    "curve25519-sha256@libssh.org": ("ECDH", "key-agree", "x25519"),
    "ecdh-sha2-nistp256": ("ECDH", "key-agree", "secp256r1"),
    "ecdh-sha2-nistp384": ("ECDH", "key-agree", "secp384r1"),
    "ecdh-sha2-nistp521": ("ECDH", "key-agree", "secp521r1"),
    "diffie-hellman-group1-sha1": ("FFDH", "key-agree", "1024"),
    "diffie-hellman-group14-sha1": ("FFDH", "key-agree", "2048"),
    "diffie-hellman-group14-sha256": ("FFDH", "key-agree", "2048"),
    "diffie-hellman-group15-sha512": ("FFDH", "key-agree", "3072"),
    "diffie-hellman-group16-sha512": ("FFDH", "key-agree", "4096"),
    "diffie-hellman-group17-sha512": ("FFDH", "key-agree", "6144"),
    "diffie-hellman-group18-sha512": ("FFDH", "key-agree", "8192"),
    # Group-exchange: the modulus size is chosen at negotiation, so unknown here.
    "diffie-hellman-group-exchange-sha1": ("FFDH", "key-agree", None),
    "diffie-hellman-group-exchange-sha256": ("FFDH", "key-agree", None),
    "mlkem768x25519-sha256": ("ML-KEM", "kem", "768"),
    "mlkem768nistp256-sha256": ("ML-KEM", "kem", "768"),
    "mlkem1024nistp384-sha384": ("ML-KEM", "kem", "1024"),
}

_CIPHER: dict[str, _Mapping] = {
    "aes128-ctr": ("AES", "block-cipher", "128"),
    "aes192-ctr": ("AES", "block-cipher", "192"),
    "aes256-ctr": ("AES", "block-cipher", "256"),
    "aes128-cbc": ("AES", "block-cipher", "128"),
    "aes192-cbc": ("AES", "block-cipher", "192"),
    "aes256-cbc": ("AES", "block-cipher", "256"),
    "aes128-gcm@openssh.com": ("AES", "ae", "128"),
    "aes256-gcm@openssh.com": ("AES", "ae", "256"),
    "chacha20-poly1305@openssh.com": ("ChaCha20", "ae", "256"),
    "3des-cbc": ("3DES", "block-cipher", None),
    "blowfish-cbc": ("Blowfish", "block-cipher", None),
    "cast128-cbc": ("CAST5", "block-cipher", None),
    "arcfour": ("RC4", "stream-cipher", None),
    "arcfour128": ("RC4", "stream-cipher", "128"),
    "arcfour256": ("RC4", "stream-cipher", "256"),
}
_CIPHER_MODE = {"ctr": "ctr", "cbc": "cbc", "gcm": "gcm"}

_MAC: dict[str, _Mapping] = {
    "hmac-md5": ("HMAC", "mac", "MD5"),
    "hmac-sha1": ("HMAC", "mac", "SHA-1"),
    "hmac-sha2-256": ("HMAC", "mac", "SHA-256"),
    "hmac-sha2-512": ("HMAC", "mac", "SHA-512"),
    "umac-64@openssh.com": ("UMAC", "mac", "64"),
    "umac-128@openssh.com": ("UMAC", "mac", "128"),
}


def _lookup(table: dict[str, _Mapping], algorithm: str) -> _Mapping | None:
    return table.get(algorithm.removesuffix("-etm@openssh.com")) or table.get(algorithm)


def _cipher_mode(algorithm: str) -> str | None:
    tail = algorithm.split("@")[0].rsplit("-", 1)[-1]
    return _CIPHER_MODE.get(tail)


def claims_from_kexinit(
    kexinit: KexInit, host_keys: list[HostKey], *, locus: NetworkLocus, confidence: ConfidenceTier
) -> list[RawClaim]:
    claims: list[RawClaim] = []

    def add(
        table: dict[str, _Mapping], algorithms: tuple[str, ...], *, with_mode: bool = False
    ) -> None:
        for algorithm in algorithms:
            if algorithm in PSEUDO_ALGORITHMS:
                continue
            mapping = _lookup(table, algorithm)
            if mapping is None:
                # I8: an algorithm we cannot map is reported under its own
                # name so it surfaces as UNKNOWN, never silently dropped.
                claims.append(
                    RawClaim(
                        locus=locus,
                        name=algorithm,
                        detection_method="runtime",
                        confidence=confidence,
                    )
                )
                continue
            name, primitive, parameter_set = mapping
            claims.append(
                RawClaim(
                    locus=locus,
                    name=name,
                    primitive=primitive,
                    parameter_set=parameter_set,
                    mode=_cipher_mode(algorithm) if with_mode else None,
                    detection_method="runtime",
                    confidence=confidence,
                )
            )

    add(_KEX, kexinit.kex_algorithms)
    add(_CIPHER, kexinit.encryption_algorithms, with_mode=True)
    add(_MAC, kexinit.mac_algorithms)

    for key in host_keys:
        parameter_set = key.curve_name or (
            str(key.size_bits) if key.size_bits is not None else None
        )
        claims.append(
            RawClaim(
                locus=locus,
                name=key.algorithm,
                primitive="signature",
                parameter_set=parameter_set,
                detection_method="runtime",
                confidence=confidence,
            )
        )
    return claims


class SshHostKeyCollector:
    name = "ssh.hostkey"
    version = "1.0.0"
    default_confidence = ConfidenceTier.RUNTIME
    requires_sandbox = True
    requires_network = True

    def __init__(self, *, policy: NetworkPolicy) -> None:
        self._policy = policy

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.NETWORK_ENDPOINT

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        start = time.monotonic()
        invocation = ("ssh.hostkey", target.ref)

        def degraded(message: str, *, raw: bytes = b"") -> CollectorResult:
            return CollectorResult(
                raw=raw,
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=ToolIdentity(
                    name=self.name,
                    version=self.version,
                    invocation=invocation,
                    exit_code=None,
                    duration_seconds=time.monotonic() - start,
                ),
                errors=[CollectorError(message=message, fatal=True)],
                partial=True,
            )

        hostname, _, port_str = target.ref.rpartition(":")
        if not hostname or not port_str.isdigit():
            return degraded(f"target ref {target.ref!r} is not a valid host:port")
        port = int(port_str)

        try:
            pinned = resolve_and_validate(hostname, port, policy=self._policy)
            kexinit = read_kexinit(pinned)
        except (SsrfDeniedError, SshProbeError) as exc:
            return degraded(str(exc))

        errors: list[CollectorError] = []
        host_keys: list[HostKey] = []
        try:
            host_keys = scan_host_keys(pinned, scan_types_for(kexinit.host_key_algorithms))
        except SshProbeError as exc:
            errors.append(CollectorError(message=str(exc), fatal=False))
        if not host_keys and not errors:
            errors.append(
                CollectorError(message="ssh-keyscan returned no usable host keys", fatal=False)
            )

        locus = NetworkLocus(host=hostname, port=port, sni=None, protocol="ssh")
        claims = claims_from_kexinit(
            kexinit, host_keys, locus=locus, confidence=self.default_confidence
        )
        raw = json.dumps(
            {
                "banner": kexinit.banner,
                "kex_algorithms": kexinit.kex_algorithms,
                "host_key_algorithms": kexinit.host_key_algorithms,
                "encryption_algorithms": kexinit.encryption_algorithms,
                "mac_algorithms": kexinit.mac_algorithms,
                "host_keys": [
                    {
                        "type": k.key_type,
                        "algorithm": k.algorithm,
                        "bits": k.size_bits,
                        "curve": k.curve_name,
                    }
                    for k in host_keys
                ],
            }
        ).encode()
        return CollectorResult(
            raw=raw,
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=invocation,
                exit_code=0,
                duration_seconds=time.monotonic() - start,
            ),
            errors=errors,
            partial=bool(errors),
        )
