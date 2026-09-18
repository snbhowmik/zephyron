"""ARCH.md §2.2 `tls.endpoint` — the `Collector` protocol wrapper around
`endpoint.probe_endpoint`. T-035.

`requires_sandbox = True` per `ARCH.md §2.3`'s classification table (`tls.
endpoint` stays on the sandboxed-subprocess path even for a Host target —
'it is a network probe with no filesystem access'), but `requires_network
= True` always: unlike `source_scan.*`/`sbom.syft`, this collector's
entire job is making an outbound connection, so there is no meaningful
"default closed" posture to flip — the SSRF denylist (`ssrf.py`,
`SECURITY.md §4`) is what does the actual containment work here, not
`--network=none`.
"""

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
from qavach_collectors.tls.endpoint import (
    CertificateInfo,
    HandshakeResult,
    HybridProbeResult,
    TlsProbeError,
    probe_endpoint,
)
from qavach_collectors.tls.ssrf import NetworkPolicy, SsrfDeniedError

_CERT_ALGORITHM_TO_CLAIM: dict[str, tuple[str, str | None]] = {
    "RSA": ("RSA", "signature"),
    "EC": ("ECDSA", "signature"),
    "Ed25519": ("EdDSA", "signature"),
    "Ed448": ("EdDSA", "signature"),
    "DSA": ("DSA", "signature"),
}
"""Maps `CertificateInfo.public_key_algorithm` to a `(name, primitive)`
pair for `RawClaim`. A certificate's own public key is used by its
subject to *sign* future material (TLS handshake signatures, further
certificates) in the overwhelming real-world case — reporting `EC` keys
as ECDSA rather than generic key-agreement is the correct default reading
of "what algorithm is this," not a guess; `qavach_core.normalize`
resolves the exact family from here."""


class TlsEndpointCollector:
    name = "tls.endpoint"
    version = "1.0.0"
    default_confidence = ConfidenceTier.RUNTIME
    requires_sandbox = True
    requires_network = True

    def __init__(self, *, policy: NetworkPolicy) -> None:
        self._policy = policy

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.NETWORK_ENDPOINT

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        hostname, _, port_str = target.ref.rpartition(":")
        if not hostname or not port_str.isdigit():
            return CollectorResult(
                raw=b"",
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=ToolIdentity(
                    name=self.name,
                    version=self.version,
                    invocation=(),
                    exit_code=None,
                    duration_seconds=0.0,
                ),
                errors=[
                    CollectorError(
                        message=f"target ref {target.ref!r} is not a valid host:port", fatal=True
                    )
                ],
                partial=True,
            )
        port = int(port_str)

        start = time.monotonic()
        try:
            handshake, hybrid = probe_endpoint(hostname, port, policy=self._policy)
        except (SsrfDeniedError, TlsProbeError) as exc:
            return CollectorResult(
                raw=b"",
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=ToolIdentity(
                    name=self.name,
                    version=self.version,
                    invocation=("openssl", "s_client", target.ref),
                    exit_code=None,
                    duration_seconds=time.monotonic() - start,
                ),
                errors=[CollectorError(message=str(exc), fatal=True)],
                partial=True,
            )
        duration = time.monotonic() - start

        raw = json.dumps(
            {
                "protocol_version": handshake.protocol_version,
                "cipher_suite": handshake.cipher_suite,
                "negotiated_group": handshake.negotiated_group,
                "chain_length": len(handshake.chain),
                "hybrid_candidates_tested": hybrid.candidates_tested,
                "hybrid_accepted": hybrid.accepted,
            }
        ).encode()

        claims = _to_raw_claims(
            hostname, port, handshake, hybrid, confidence=self.default_confidence
        )

        return CollectorResult(
            raw=raw,
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=("openssl", "s_client", target.ref),
                exit_code=0,
                duration_seconds=duration,
            ),
            errors=[],
            partial=False,
        )


def _to_raw_claims(
    hostname: str,
    port: int,
    handshake: HandshakeResult,
    hybrid: HybridProbeResult,
    *,
    confidence: ConfidenceTier,
) -> list[RawClaim]:
    locus = NetworkLocus(
        host=hostname, port=port, sni=hostname, protocol=handshake.protocol_version
    )
    claims: list[RawClaim] = []

    for cert in handshake.chain:
        claims.extend(_cert_claims(cert, locus=locus, confidence=confidence))

    if hybrid.accepted:
        for group in hybrid.accepted:
            claims.append(
                RawClaim(
                    locus=locus,
                    name="ML-KEM",
                    parameter_set=group,
                    primitive="kem",
                    detection_method="runtime",
                    confidence=confidence,
                )
            )

    return claims


def _cert_claims(
    cert: CertificateInfo, *, locus: NetworkLocus, confidence: ConfidenceTier
) -> list[RawClaim]:
    mapping = _CERT_ALGORITHM_TO_CLAIM.get(cert.public_key_algorithm)
    if mapping is None:
        return []
    name, primitive = mapping
    parameter_set = (
        cert.curve_name
        if cert.curve_name is not None
        else (str(cert.public_key_size_bits) if cert.public_key_size_bits is not None else None)
    )
    return [
        RawClaim(
            locus=locus,
            name=name,
            primitive=primitive,
            parameter_set=parameter_set,
            detection_method="runtime",
            confidence=confidence,
        )
    ]
