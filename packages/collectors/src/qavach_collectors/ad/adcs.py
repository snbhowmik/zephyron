"""ARCH.md §2.2 `ad.adcs` — AD Certificate Services via Certipy (MIT).
T-045 / `PRD.md FR-135`.

Runs `certipy find -json` inside the sandbox (network-mode, not the
deployed agent — no host install) against a domain controller with an
operator-supplied low-privilege credential, and reads what Certipy
reports about certificate templates, CAs and ESC misconfigurations.

**Credential handling (`SECURITY.md §6`).** Certipy accepts a password only
as `-p <value>` on the command line — which would appear in `ps`, in
`docker inspect` and in the recorded `ToolIdentity.invocation` — or via an
interactive `getpass` prompt, which falls back to reading **stdin** when
there is no TTY. This collector uses the second path: the secret travels in
an environment variable (passed to Docker by *name only*, see
`SandboxConfig.secret_env`) and the shell wrapper pipes it to Certipy's
stdin. It appears in no argv anywhere, and `AdcsCredential` hides it from
its own `repr`.

**Resolve then pin (`SECURITY.md §4`).** The DC hostname is resolved once,
validated against the SSRF policy, and Certipy is handed the resulting IP.

**Verification limit, stated plainly.** No Active Directory exists in this
project's development environment, so nothing here has run against a real
domain. The output schema was read from Certipy's own source at the pinned
commit (`docker/certipy/Dockerfile`), and the parser is tested against
fixtures shaped from that source — *derived*, not recorded. Recording a
real Certipy run against a lab domain (`TASK.md` T-024) is the step that
would upgrade this from "matches the source" to "matches the tool."
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from qavach_core.model import CloudLocus, ConfidenceTier
from qavach_sandbox import SandboxConfig, run_sandboxed

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
from qavach_collectors.tls.ssrf import NetworkPolicy, SsrfDeniedError, resolve_and_validate

ADCS_VERSION = "certipy@3ae3442"

_VULN_KEY = "[!] Vulnerabilities"
_MIN_RSA_KEY = "Minimum RSA Key Length"


@dataclass(frozen=True, slots=True)
class AdcsCredential:
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AdcsFinding:
    """A certificate-service misconfiguration (an ESC*) on a template or CA.

    These are **not** algorithm findings and are deliberately not forced
    into `RawClaim`s or invariant I1's four crypto classes — an ESC1
    template is dangerous because of who can enrol and what the template
    permits, not because of a weak primitive. See `NOTE.md` OQ-13.
    """

    kind: str
    subject_kind: str
    subject: str
    description: str


@dataclass(frozen=True, slots=True)
class AdcsTemplate:
    name: str
    enabled: bool | None
    min_rsa_key_bits: int | None


def _entries(section: Any) -> list[dict[str, Any]]:
    """Certipy emits either `{"0": {...}, "1": {...}}` or, when empty, a
    bare *string* such as `"[!] Could not find any CAs"` — a string where a
    mapping is expected, which a naive `.values()` would crash on."""
    if not isinstance(section, dict):
        return []
    return [entry for entry in section.values() if isinstance(entry, dict)]


def parse_certipy_json(
    document: dict[str, Any],
) -> tuple[list[AdcsTemplate], list[AdcsFinding]]:
    templates: list[AdcsTemplate] = []
    findings: list[AdcsFinding] = []

    for entry in _entries(document.get("Certificate Templates")):
        name = str(entry.get("Template Name", "<unnamed>"))
        raw_bits = entry.get(_MIN_RSA_KEY)
        templates.append(
            AdcsTemplate(
                name=name,
                enabled=entry.get("Enabled") if isinstance(entry.get("Enabled"), bool) else None,
                min_rsa_key_bits=int(raw_bits)
                if isinstance(raw_bits, int | str) and str(raw_bits).isdigit()
                else None,
            )
        )
        findings.extend(_findings(entry, "template", name))

    for entry in _entries(document.get("Certificate Authorities")):
        name = str(entry.get("CA Name", "<unnamed>"))
        findings.extend(_findings(entry, "ca", name))

    return templates, findings


def _findings(entry: dict[str, Any], subject_kind: str, subject: str) -> list[AdcsFinding]:
    vulnerabilities = entry.get(_VULN_KEY)
    if not isinstance(vulnerabilities, dict):
        return []
    return [
        AdcsFinding(
            kind=str(kind), subject_kind=subject_kind, subject=subject, description=str(text)
        )
        for kind, text in vulnerabilities.items()
    ]


def findings_from_raw(raw: bytes) -> list[AdcsFinding]:
    """Recovers the ESC findings from a `CollectorResult.raw` payload."""
    _templates, findings = parse_certipy_json(json.loads(raw.decode()))
    return findings


class AdcsCollector:
    name = "ad.adcs"
    version = ADCS_VERSION
    default_confidence = ConfidenceTier.ATTESTED
    requires_sandbox = True
    requires_network = True

    def __init__(
        self, *, image_ref: str, credential: AdcsCredential, policy: NetworkPolicy, domain: str
    ) -> None:
        self._image_ref = image_ref
        self._credential = credential
        self._policy = policy
        self._domain = domain

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.DIRECTORY_SERVICE

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        start = time.monotonic()
        dc_host = target.ref.removeprefix("ldaps://").removeprefix("ldap://").split(":")[0]

        def degraded(
            message: str, *, raw: bytes = b"", exit_code: int | None = None
        ) -> CollectorResult:
            return CollectorResult(
                raw=raw,
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=ToolIdentity(
                    name=self.name,
                    version=self.version,
                    invocation=("certipy", "find"),
                    exit_code=exit_code,
                    duration_seconds=time.monotonic() - start,
                ),
                errors=[CollectorError(message=message, fatal=True)],
                partial=True,
            )

        try:
            pinned = resolve_and_validate(dc_host, 389, policy=self._policy)
        except SsrfDeniedError as exc:
            return degraded(str(exc))

        # The password and username come from the environment, piped to
        # Certipy's stdin — nothing secret is interpolated into this text.
        script = (
            'printf "%s\\n" "$QAVACH_ADCS_PASSWORD" | '
            'certipy find -u "$QAVACH_ADCS_USER" '
            f"-dc-ip {pinned.address} -json -output /work/adcs >/work/certipy.log 2>&1 "
            "&& cat /work/adcs_Certipy.json"
        )
        command = ("sh", "-c", script)
        sandbox_result = run_sandboxed(
            SandboxConfig(
                image_ref=self._image_ref,
                target_mount=None,
                command=command,
                requires_network=True,
                secret_env={
                    "QAVACH_ADCS_USER": f"{self._credential.username}@{self._domain}",
                    "QAVACH_ADCS_PASSWORD": self._credential.password,
                },
            )
        )

        if not sandbox_result.ok:
            return degraded(
                f"certipy find did not complete successfully "
                f"(exit {sandbox_result.exit_code}); see the sandbox log for the reason",
                exit_code=sandbox_result.exit_code,
            )

        try:
            document = json.loads(sandbox_result.output.decode())
            templates, _findings_ = parse_certipy_json(document)
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
            return degraded(
                f"certipy output was not the expected JSON: {exc}", raw=sandbox_result.output
            )

        claims = [
            RawClaim(
                locus=CloudLocus(
                    provider="ad-cs",
                    account=self._domain,
                    region=str(pinned.address),
                    resource_arn=f"CN=Certificate Templates/CN={template.name}",
                ),
                name="RSA",
                primitive="signature",
                parameter_set=str(template.min_rsa_key_bits),
                detection_method="attested",
                confidence=self.default_confidence,
            )
            for template in templates
            if template.min_rsa_key_bits is not None
        ]

        return CollectorResult(
            raw=sandbox_result.output,
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=command,
                exit_code=sandbox_result.exit_code,
                duration_seconds=sandbox_result.duration_seconds,
            ),
            errors=[],
            partial=False,
        )
