"""ARCH.md §2.2 `source_scan.opengrep` — the low-confidence breadth tier.
T-037 / `NOTE.md §3.3`.

Runs the QAVACH-owned image built from `docker/opengrep/Dockerfile`
(upstream publishes none) with QAVACH's fourteen-rule pack
(`config/opengrep-rules/crypto.yaml`) and turns its SARIF into claims at
`PATTERN` confidence. Opengrep (LGPL-2.1) is only ever run as a separate
process — never imported or vendored (NFR-10).

**Why there is no rule tuning here.** Opengrep matches API *names*. It cannot
tell a live call from a test fixture or a comment, so false positives are
expected and are absorbed by the confidence tier and the dispute mechanism
(`NOTE.md §3.3`). The value is language coverage — C/C++, C#, PHP, Ruby,
Rust — that the AST scanners miss.

**Rule metadata comes from the rules file, not the SARIF.** Verified against
the real tool: Opengrep's SARIF results carry `ruleId` but not the rule's
`metadata`, so the adapter maps `ruleId` -> algorithm through the same
`crypto.yaml` the image was built from. Opengrep prefixes the rule id with
the config path (`opt.qavach.rules.<id>`), so matching is by suffix.
A finding whose rule is not in the table means the image and the table have
drifted; it is reported as a non-fatal error, never guessed at.

Two facts about the real tool that shaped the image (`docker/opengrep`): the
release binary unpacks its engine into `$XDG_CACHE_HOME` and execs it, which
the sandbox's `noexec` tmpfs forbids — so it is unpacked at build time — and
it reads rule files with the process locale, so the image sets `C.UTF-8`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from qavach_core.model import ConfidenceTier, FileLocus
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
from qavach_collectors.source_scan.cbomkit import ImageNotBuiltError

OPENGREP_VERSION = "1.30.0"
_TARGET_MOUNT = "/target"

_COMMAND = (
    "opengrep",
    "scan",
    "--config",
    "/opt/qavach/rules",
    "--sarif",
    "--disable-version-check",
    "--quiet",
    _TARGET_MOUNT,
)


@dataclass(frozen=True, slots=True)
class OpengrepRule:
    id: str
    algorithm: str
    primitive: str | None
    parameter_set: str | None
    name_regex: str | None = None
    """If set, the claim's name is group 1 of this regex over the matched snippet."""


def load_rules(document: dict[str, Any]) -> dict[str, OpengrepRule]:
    """From the parsed `crypto.yaml`. A rule without `qavach_algorithm`
    metadata is a bug in the rule pack and is rejected here."""
    rules: dict[str, OpengrepRule] = {}
    for entry in document["rules"]:
        metadata = entry.get("metadata") or {}
        name_regex = metadata.get("qavach_name_regex")
        algorithm = metadata.get("qavach_algorithm") or ("" if name_regex else None)
        if algorithm is None:
            raise ValueError(f"rule {entry.get('id')!r} has no qavach_algorithm metadata")
        if name_regex:
            re.compile(str(name_regex))  # a bad pattern in the rule pack is a bug: fail at load
        rules[str(entry["id"])] = OpengrepRule(
            id=str(entry["id"]),
            algorithm=str(algorithm),
            primitive=metadata.get("qavach_primitive"),
            parameter_set=metadata.get("qavach_parameter"),
            name_regex=str(name_regex) if name_regex else None,
        )
    return rules


def _match_rule(rule_id: str, rules: dict[str, OpengrepRule]) -> OpengrepRule | None:
    for known_id, rule in rules.items():
        if rule_id == known_id or rule_id.endswith("." + known_id):
            return rule
    return None


def _relative_path(uri: str) -> str:
    return uri.removeprefix(_TARGET_MOUNT + "/").removeprefix(_TARGET_MOUNT)


def claims_from_sarif(
    sarif: dict[str, Any], rules: dict[str, OpengrepRule]
) -> tuple[list[RawClaim], list[CollectorError]]:
    claims: list[RawClaim] = []
    errors: list[CollectorError] = []
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId", ""))
            rule = _match_rule(rule_id, rules)
            if rule is None:
                errors.append(
                    CollectorError(message=f"finding from unknown rule {rule_id!r}", fatal=False)
                )
                continue
            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") or {}
                uri = (physical.get("artifactLocation") or {}).get("uri")
                line = (physical.get("region") or {}).get("startLine")
                if not isinstance(uri, str) or not isinstance(line, int):
                    errors.append(
                        CollectorError(
                            message=f"finding from {rule.id} has no usable location", fatal=False
                        )
                    )
                    continue
                name = rule.algorithm
                if rule.name_regex:
                    # The rule matched an algorithm *string literal*: the name is what the
                    # source says (`"PBEWithMD5AndDES"`), taken from the matched snippet.
                    snippet = ((physical.get("region") or {}).get("snippet") or {}).get("text", "")
                    found = re.search(rule.name_regex, str(snippet))
                    if not found:
                        errors.append(
                            CollectorError(
                                message=f"{rule.id}: no algorithm name in the matched snippet",
                                fatal=False,
                            )
                        )
                        continue
                    name = found.group(1)
                claims.append(
                    RawClaim(
                        # LOCUS-01: FileLocus.offset carries the line number.
                        locus=FileLocus(path=_relative_path(uri), offset=line),
                        name=name,
                        primitive=rule.primitive,
                        parameter_set=rule.parameter_set,
                        detection_method="pattern",
                        confidence=ConfidenceTier.PATTERN,
                    )
                )
    return claims, errors


class OpengrepCollector:
    name = "source_scan.opengrep"
    version = OPENGREP_VERSION
    default_confidence = ConfidenceTier.PATTERN
    requires_sandbox = True
    requires_network = False

    def __init__(self, *, rules: dict[str, OpengrepRule], image_ref: str | None) -> None:
        if not image_ref:
            raise ImageNotBuiltError(
                "no opengrep image configured: run `make build-images` and pass its ID"
            )
        self._rules = rules
        self._image_ref = image_ref

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        from pathlib import Path

        sandbox_result = run_sandboxed(
            SandboxConfig(
                image_ref=self._image_ref,
                target_mount=Path(target.ref),
                command=_COMMAND,
                requires_network=False,
            )
        )
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=_COMMAND,
            exit_code=sandbox_result.exit_code,
            duration_seconds=sandbox_result.duration_seconds,
        )

        def degraded(message: str) -> CollectorResult:
            return CollectorResult(
                raw=sandbox_result.output,
                raw_format=RawFormat.SARIF,
                claims=[],
                tool=tool,
                errors=[CollectorError(message=message, fatal=True)],
                partial=True,
            )

        if not sandbox_result.ok:
            tail = sandbox_result.stderr.decode(errors="replace")[-500:]
            return degraded(f"opengrep did not complete successfully: {tail}")
        try:
            sarif = json.loads(sandbox_result.output.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return degraded(f"opengrep output was not valid JSON: {exc}")
        if not isinstance(sarif, dict):
            return degraded("opengrep output was not a SARIF object")

        claims, errors = claims_from_sarif(sarif, self._rules)
        return CollectorResult(
            raw=sandbox_result.output,
            raw_format=RawFormat.SARIF,
            claims=claims,
            tool=tool,
            errors=errors,
            partial=bool(errors),
        )
