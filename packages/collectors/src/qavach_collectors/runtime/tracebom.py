"""ARCH.md §2.2 `runtime.tracebom` — what a program *actually loads and
negotiates when it runs*. T-044 / `PRD.md FR-170`.

`tracebom` (Apache-2.0; ships in the cdxgen image) runs a command and
reports a CycloneDX 1.7 BOM of what the process touched. Runs in the QAVACH
sandbox (`SECURITY.md §3`) via a thin derived image, `docker/tracebom`.

**Executes the target's program.** This is the one collector whose job is to
run the thing under inspection. The command is operator-supplied
(`Target.options["cmd"]`), runs with the target mounted read-only at
`/target` as its working directory, with no network, no capabilities and no
writable root — the sandbox is the containment, exactly as for any scanner.
The command travels to the container as an environment variable, never
interpolated into a shell string.

**What was verified live and what was not — this matters for how far to trust
the output.** Under the sandbox's real flags, `tracebom` reports the shared
libraries the process loaded (`libcrypto.so.3`, `libssl.so.3`, `_hashlib`,
...) as `library` components with `cdx:dynamic:filePath` properties. Those
become **capability** claims (the library *can* do AES/RSA/...), not usage,
so they sit at `DEPENDENCY` — the same contract as `crypto_libraries.yaml` —
even though the load itself was observed. What the sandbox *cannot* provide:
its eBPF cipher-suite tracing needs `CAP_BPF`, which `--cap-drop=ALL` removes
on purpose, and TLS negotiation needs a network the sandbox denies. So no
`cryptographic-asset` components appeared in any run here. If a future
tracebom or an operator-approved configuration does emit them, they are
normalised through the shared CBOM mapper at `RUNTIME` — that path is tested
against hand-written input only, never recorded output (`NOTE.md` OQ-17).

**Silent failure.** With the helper binary non-executable, or `/tmp`
`noexec`, `tracebom` prints an error and *still exits 0 with an empty BOM*.
An empty result is therefore **never** reported as "no crypto observed": it
is a non-fatal coverage failure (invariant I8), and a stderr trace-failure
message is fatal.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qavach_core.model import ConfidenceTier, RuntimeLocus
from qavach_core.normalize import AliasTable, CryptographyRegistry, normalise_bom
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
from qavach_collectors.binary.collector import BinaryKnowledge
from qavach_collectors.cbom_claims import normalised_to_raw_claims
from qavach_collectors.source_scan.cbomkit import ImageNotBuiltError

TRACEBOM_VERSION = "13.0.1"
_TIMEOUT_MS = 60_000
_CMD_ENV = "QAVACH_TRACE_CMD"
_DYNAMIC_PATH = "cdx:dynamic:filePath"
_MAX_CMD_LEN = 4096

_SCRIPT = (
    f'tracebom --cmd "${_CMD_ENV}" -d /target -o /work/bom.json '
    f"--timeout {_TIMEOUT_MS} >&2 && cat /work/bom.json"
)
_COMMAND = ("sh", "-c", _SCRIPT)
_FAILURE_MARKER = re.compile(r"Tracing command execution failed", re.IGNORECASE)


def _loaded_library_paths(document: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for component in document.get("components") or []:
        if not isinstance(component, dict) or component.get("type") != "library":
            continue
        for prop in component.get("properties") or []:
            if isinstance(prop, dict) and prop.get("name") == _DYNAMIC_PATH:
                value = prop.get("value")
                if isinstance(value, str) and value not in paths:
                    paths.append(value)
    return paths


def library_claims(
    paths: list[str], knowledge: BinaryKnowledge, *, process: str, observed_at: datetime
) -> list[RawClaim]:
    claims: list[RawClaim] = []
    for path in paths:
        base = Path(path).name
        for rule in knowledge.libraries:
            if rule.pattern.match(base):
                locus = RuntimeLocus(process=process, module=path, observed_at=observed_at)
                claims.extend(
                    RawClaim(
                        locus=locus,
                        name=family,
                        detection_method="runtime",
                        confidence=ConfidenceTier.DEPENDENCY,
                    )
                    for family in rule.provides
                )
                break
    return claims


def _observed_at(document: dict[str, Any]) -> datetime:
    """From the tool's own timestamp, so the same output always yields the
    same claims; falls back to the epoch rather than reading the clock."""
    stamp = (document.get("metadata") or {}).get("timestamp")
    if isinstance(stamp, str):
        try:
            return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.fromtimestamp(0, tz=UTC)


# QAVACH-OPEN: OQ-17 — runtime crypto-asset (TLS suite) tracing is unavailable in the sandbox.
class TracebomCollector:
    name = "runtime.tracebom"
    version = TRACEBOM_VERSION
    default_confidence = ConfidenceTier.RUNTIME
    requires_sandbox = True
    requires_network = False

    def __init__(
        self,
        *,
        registry: CryptographyRegistry,
        aliases: AliasTable,
        knowledge: BinaryKnowledge,
        image_ref: str | None,
    ) -> None:
        if not image_ref:
            raise ImageNotBuiltError(
                "no tracebom image configured: run `make build-images` and pass its ID"
            )
        self._registry = registry
        self._aliases = aliases
        self._knowledge = knowledge
        self._image_ref = image_ref

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY and "cmd" in target.options

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        command = target.options.get("cmd", "")
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=_COMMAND,
            exit_code=None,
            duration_seconds=0.0,
        )

        def degraded(
            message: str, *, raw: bytes = b"", fatal: bool = True, tool: ToolIdentity = tool
        ) -> CollectorResult:
            return CollectorResult(
                raw=raw,
                raw_format=RawFormat.CDX_1_7,
                claims=[],
                tool=tool,
                errors=[CollectorError(message=message, fatal=fatal)],
                partial=True,
            )

        if not command.strip() or len(command) > _MAX_CMD_LEN or "\x00" in command:
            return degraded("target.options['cmd'] must be a non-empty command under 4096 chars")

        sandbox_result = run_sandboxed(
            SandboxConfig(
                image_ref=self._image_ref,
                target_mount=Path(target.ref),
                command=_COMMAND,
                requires_network=False,
                tmp_exec=True,
                env={_CMD_ENV: command},
            )
        )
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=_COMMAND,
            exit_code=sandbox_result.exit_code,
            duration_seconds=sandbox_result.duration_seconds,
        )
        stderr = sandbox_result.stderr.decode(errors="replace")
        if not sandbox_result.ok:
            return degraded(f"tracebom did not complete successfully: {stderr[-500:]}", tool=tool)
        if _FAILURE_MARKER.search(stderr):
            return degraded(
                f"tracebom could not trace the command: {stderr[-500:]}",
                raw=sandbox_result.output,
                tool=tool,
            )
        try:
            document = json.loads(sandbox_result.output.decode())
            if not isinstance(document, dict):
                raise ValueError("not a JSON object")
        except (UnicodeDecodeError, ValueError) as exc:
            return degraded(f"tracebom output was not a BOM: {exc}", tool=tool)

        process = command.split()[0]
        claims = library_claims(
            _loaded_library_paths(document),
            self._knowledge,
            process=process,
            observed_at=_observed_at(document),
        )
        errors: list[CollectorError] = []
        try:
            normalised = normalise_bom(document, registry=self._registry, aliases=self._aliases)
        except ValueError as exc:
            normalised = []
            errors.append(
                CollectorError(
                    message=f"crypto-asset components not normalised: {exc}", fatal=False
                )
            )
        for item in normalised:
            claims.extend(
                normalised_to_raw_claims(
                    item,
                    target=target,
                    confidence=self.default_confidence,
                    locus_prefix="runtime!",
                )
            )

        if not (document.get("components") or []):
            errors.append(
                CollectorError(
                    message=(
                        "tracebom observed nothing — the trace may have failed silently; "
                        "an empty result is a coverage gap, not evidence of no cryptography"
                    ),
                    fatal=False,
                )
            )
        return CollectorResult(
            raw=sandbox_result.output,
            raw_format=RawFormat.CDX_1_7,
            claims=claims,
            tool=tool,
            errors=errors,
            partial=bool(errors),
        )
