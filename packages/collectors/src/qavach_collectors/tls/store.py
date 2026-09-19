"""ARCH.md §2.2 `tls.store` — the certfinder half. T-036.

**Runs exclusively via the deployed agent** (`ARCH.md §2.3`, §3a) — no
sandboxed-subprocess variant; `Target.type` is always `HOST`, `target.ref`
a filesystem path on the host the agent is installed on (`apps/agent/src/
qavach_agent/runtime.py`'s own convention for every path in a scan spec).

**Scope note, decided with the user 2026-09-19 after live verification**:
CBOMkit-theia's `dir` command (secrets/private-key detection, OpenSSL
config extraction, known-bad-CA flagging) is specified in `ARCH.md §2.2`
as this collector's second half, additive to certfinder. Checked live
against every CBOMkit-theia GitHub release (`v1.1.0`-`v1.1.2`): zero
binary assets on any of them — theia ships as a container image only,
which the deployed agent cannot run (`ARCH.md §3a`: 'Python only... no new
runtime'). This is a real conflict between two ARCH.md-stated
requirements, not resolvable by more effort here alone, and was raised to
the user rather than silently picked around. Decision: build the
certfinder half now (fully real, checksummed, tested — this file), defer
theia's agent-side integration as its own follow-up once a
build/bundling decision is made (see `NOTE.md`, flagged `# QAVACH-OPEN:
AGENT-02`). Every ARCH.md claim this collector itself makes (certfinder's
CLI, its JSON schema, its checksum) was independently re-verified live
against the real v0.7.0 release, not assumed from the spec's own summary.

**PKCS#7 chain reconstruction, QAVACH's own addition on top of
certfinder** (`ARCH.md §2.2`: 'QAVACH owns PKCS#7 parsing and chain
reconstruction on top'): certfinder's own `--help` names PEM/DER/JKS/
JCEKS/PKCS#12 — no PKCS#7 (`.p7b`/`.p7c` `SignedData` bundles, a real gap
confirmed against the tool's own documented format list, not assumed) —
so `packages/collectors/tls/pkcs7.py` fills that in, and `chain.py`
stitches individual certificates (whatever their source — certfinder or
the PKCS#7 walk) into trust chains by subject/issuer DN matching.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from qavach_core.model import ConfidenceTier, FileLocus
from qavach_core.normalize import AliasTable, CryptographyRegistry, normalise_bom

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
from qavach_collectors.cbom_claims import normalised_to_raw_claims
from qavach_collectors.tls.theia_dir import TheiaDirError, run_theia_dir

_PROBE_TIMEOUT_SECONDS = 120.0

_CERTFINDER_ALGORITHM_TO_CLAIM: dict[str, tuple[str, str | None]] = {
    "RSA": ("RSA", "signature"),
    "ECDSA": ("ECDSA", "signature"),
    "Ed25519": ("EdDSA", "signature"),
    "Ed448": ("EdDSA", "signature"),
    "DSA": ("DSA", "signature"),
}
"""certfinder's own `public_key.algorithm` strings (confirmed live: `RSA`
for an RSA cert, and the tool's `--help`/schema imply `ECDSA` rather than
a bare `EC` for elliptic-curve certs — unlike Python's `cryptography`
library, which reports the generic key type `EC` and leaves purpose
inference to the caller, T-035's own `_CERT_ALGORITHM_TO_CLAIM`)."""


class CertfinderError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DiscoveredCertificate:
    path: str
    subject: str
    issuer: str
    public_key_algorithm: str | None
    public_key_bits: int | None
    public_key_curve: str | None
    signature_algorithm: str | None
    sha256_fingerprint: str
    spki_sha256: str
    self_signed: bool


@dataclass(frozen=True, slots=True)
class UndecryptableKeystore:
    """A JKS/PKCS#12 file certfinder found but could not open without a
    password it wasn't given — real evidence of an asset's *presence*,
    with genuinely no algorithm information available. Reported as a
    `RawClaim` with no resolvable name/OID so it correctly becomes
    `FindingClass.UNKNOWN` downstream (invariant I8) rather than being
    silently dropped because there was "nothing to report" for it."""

    path: str


def run_certfinder(binary_path: Path, target_dir: Path) -> list[dict[str, object]]:
    try:
        proc = subprocess.run(
            [str(binary_path), "-json", "-quiet", str(target_dir)],
            capture_output=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise CertfinderError(f"certfinder timed out scanning {target_dir}") from exc

    # certfinder's own exit status distinguishes "no matches" (a specific
    # non-zero code) from a genuine scan failure — but since `-json` always
    # emits a valid (possibly empty) JSON array on stdout regardless of
    # that distinction (confirmed live), parsing stdout is sufficient and
    # more robust than trying to special-case exit codes that may shift
    # between certfinder releases.
    try:
        records = json.loads(proc.stdout.decode() or "[]")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        stderr_tail = proc.stderr.decode(errors="replace")[:500]
        raise CertfinderError(
            f"certfinder produced invalid JSON: {exc}; stderr={stderr_tail}"
        ) from exc

    if not isinstance(records, list):
        raise CertfinderError(f"certfinder JSON output was not a list: {type(records).__name__}")
    return records


def parse_certfinder_records(
    records: list[dict[str, object]],
) -> tuple[list[DiscoveredCertificate], list[UndecryptableKeystore]]:
    certificates: list[DiscoveredCertificate] = []
    undecryptable: list[UndecryptableKeystore] = []

    for record in records:
        if record.get("record_type") == "pkcs12_encrypted_content":
            path = record.get("path")
            if isinstance(path, str):
                undecryptable.append(UndecryptableKeystore(path=path))
            continue

        public_key = record.get("public_key")
        algorithm: str | None = None
        bits: int | None = None
        curve: str | None = None
        if isinstance(public_key, dict):
            algorithm = public_key.get("algorithm")
            bits = public_key.get("bits")
            curve = public_key.get("curve")

        fingerprints = record.get("fingerprints")
        sha256 = ""
        spki_sha256 = ""
        if isinstance(fingerprints, dict):
            sha256 = str(fingerprints.get("sha256", ""))
            spki_sha256 = str(fingerprints.get("spki_sha256", ""))

        path = record.get("path")
        subject = record.get("subject")
        issuer = record.get("issuer")
        if not isinstance(path, str) or not isinstance(subject, str) or not isinstance(issuer, str):
            continue

        signature_algorithm = record.get("signature_algorithm")

        certificates.append(
            DiscoveredCertificate(
                path=path,
                subject=subject,
                issuer=issuer,
                public_key_algorithm=algorithm,
                public_key_bits=bits,
                public_key_curve=curve,
                signature_algorithm=(
                    signature_algorithm if isinstance(signature_algorithm, str) else None
                ),
                sha256_fingerprint=sha256,
                spki_sha256=spki_sha256,
                self_signed=bool(record.get("self_signed", False)),
            )
        )

    return certificates, undecryptable


class TlsStoreCollector:
    name = "tls.store"
    version = "0.7.0"
    """Tracks the pinned certfinder release this collector was verified
    against (`config/scanners.yaml`), not this file's own version."""
    default_confidence = ConfidenceTier.ARTEFACT
    requires_sandbox = False
    """Agent-side only (`ARCH.md §2.3`) — never goes through `packages/
    sandbox`; the agent's own host-boundary is the containment."""
    requires_network = False

    def __init__(
        self,
        *,
        certfinder_binary: Path,
        theia_binary: Path | None = None,
        registry: CryptographyRegistry | None = None,
        aliases: AliasTable | None = None,
    ) -> None:
        """Theia (T-036c) runs only if its binary *and* the registry/aliases
        needed to normalise its CBOM are supplied; otherwise this is the
        certfinder-only collector it was before."""
        self._certfinder_binary = certfinder_binary
        self._theia_binary = theia_binary
        self._registry = registry
        self._aliases = aliases

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        target_dir = Path(target.ref)
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=(str(self._certfinder_binary), "-json", target.ref),
            exit_code=None,
            duration_seconds=0.0,
        )

        try:
            records = run_certfinder(self._certfinder_binary, target_dir)
        except CertfinderError as exc:
            return CollectorResult(
                raw=b"",
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=tool,
                errors=[CollectorError(message=str(exc), fatal=True)],
                partial=True,
            )

        certificates, undecryptable = parse_certfinder_records(records)
        claims = [
            claim
            for cert in certificates
            for claim in _certificate_claims(cert, confidence=self.default_confidence)
        ] + [
            _undecryptable_claim(entry, confidence=self.default_confidence)
            for entry in undecryptable
        ]

        errors: list[CollectorError] = []
        theia_document: dict[str, Any] | None = None
        if self._theia_binary is not None and self._registry and self._aliases:
            try:
                theia_document = run_theia_dir(self._theia_binary, target_dir)
                claims += _theia_claims(
                    theia_document,
                    target_dir,
                    registry=self._registry,
                    aliases=self._aliases,
                    confidence=self.default_confidence,
                )
            except (TheiaDirError, ValueError) as exc:
                errors.append(CollectorError(message=f"theia dir: {exc}", fatal=False))

        return CollectorResult(
            raw=json.dumps({"certfinder": records, "theia": theia_document}).encode(),
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=tool,
            errors=errors,
            partial=bool(errors),
        )


def _theia_claims(
    document: dict[str, Any],
    target_dir: Path,
    *,
    registry: CryptographyRegistry,
    aliases: AliasTable,
    confidence: ConfidenceTier,
) -> list[RawClaim]:
    """Theia reports paths relative to the scanned directory; certfinder
    reports absolute ones. Joined here so both tools' findings for one file
    are the same locus and can corroborate each other."""
    out: list[RawClaim] = []
    ref = Target(type=TargetType.HOST, ref=str(target_dir))
    for item in normalise_bom(document, registry=registry, aliases=aliases):
        for claim in normalised_to_raw_claims(item, target=ref, confidence=confidence):
            locus = claim.locus
            if isinstance(locus, FileLocus) and not Path(locus.path).is_absolute():
                claim = replace(
                    claim,
                    locus=FileLocus(path=str(target_dir / locus.path), offset=locus.offset),
                )
            out.append(claim)
    return out


def _certificate_claims(
    cert: DiscoveredCertificate, *, confidence: ConfidenceTier
) -> list[RawClaim]:
    if cert.public_key_algorithm is None:
        return []
    mapping = _CERTFINDER_ALGORITHM_TO_CLAIM.get(cert.public_key_algorithm)
    if mapping is None:
        return []
    name, primitive = mapping
    parameter_set = cert.public_key_curve or (
        str(cert.public_key_bits) if cert.public_key_bits is not None else None
    )
    return [
        RawClaim(
            locus=FileLocus(path=cert.path, offset=0),
            name=name,
            primitive=primitive,
            parameter_set=parameter_set,
            detection_method="artefact",
            confidence=confidence,
        )
    ]


def _undecryptable_claim(entry: UndecryptableKeystore, *, confidence: ConfidenceTier) -> RawClaim:
    """No name/OID — resolves to `UnresolvedAlgorithm` -> `FindingClass.
    UNKNOWN` downstream (invariant I8), never silently dropped just
    because certfinder couldn't see inside it."""
    return RawClaim(
        locus=FileLocus(path=entry.path, offset=0),
        name=None,
        detection_method="artefact",
        confidence=confidence,
    )
