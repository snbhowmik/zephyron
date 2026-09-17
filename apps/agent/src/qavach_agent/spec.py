"""ARCH.md §3a — the typed scan-spec protocol. T-031a.

'The wire protocol accepts a typed scan spec, not a command... no `exec`, no
shell, no arbitrary payload field. This is the single most important
hardening property of the agent: a compromised backend or a spoofed spec
still cannot run an attacker's code on the host, only re-run a collector
QAVACH already ships against a path.'

`parse_scan_spec` is the only way to construct a `ScanSpec`, and it rejects
anything outside `{paths, collectors}`, anything whose `collectors` entries
fall outside the closed vocabulary below, and anything of the wrong shape.
There is deliberately no escape hatch — a collector name not in
`AGENT_COLLECTOR_NAMES` is rejected outright, not passed through with a
warning, because "warn and proceed" is exactly the failure mode this
property exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass

# ARCH.md §2.2 / §3a: the only collector modules that ever run agent-side.
# tls.store, hsm.evidence and the deployed-artefact collector are agent-only
# (no sandboxed-subprocess variant exists for them); ssh.hostkey's
# `sshd_config` half moves agent-side while its network-probe half stays
# sandboxed (ARCH.md §2.3) — the agent only ever receives the local-file
# half under this same module name.
AGENT_COLLECTOR_NAMES = frozenset(
    {
        "tls.store",
        "hsm.evidence",
        "artefact.deployed",
        "ssh.hostkey",
    }
)

_ALLOWED_KEYS = frozenset({"paths", "collectors"})


class InvalidScanSpecError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ScanSpec:
    paths: tuple[str, ...]
    collectors: tuple[str, ...]


def parse_scan_spec(payload: dict[str, object]) -> ScanSpec:
    """Parses and validates a scan spec received from the backend. Raises
    `InvalidScanSpecError` for anything malformed or out of vocabulary —
    never silently drops or coerces a bad field, since a spec this module
    accepts is a spec the agent will act on."""
    if not isinstance(payload, dict):
        raise InvalidScanSpecError(f"scan spec must be a JSON object, got {type(payload).__name__}")

    extra_keys = set(payload) - _ALLOWED_KEYS
    if extra_keys:
        raise InvalidScanSpecError(
            f"scan spec has unexpected field(s): {sorted(extra_keys)} — "
            f"only {sorted(_ALLOWED_KEYS)} are accepted"
        )

    raw_paths = payload.get("paths", [])
    raw_collectors = payload.get("collectors", [])

    if not isinstance(raw_paths, list) or not all(isinstance(p, str) for p in raw_paths):
        raise InvalidScanSpecError("'paths' must be a list of strings")
    if not isinstance(raw_collectors, list) or not all(isinstance(c, str) for c in raw_collectors):
        raise InvalidScanSpecError("'collectors' must be a list of strings")

    unknown = sorted(set(raw_collectors) - AGENT_COLLECTOR_NAMES)
    if unknown:
        raise InvalidScanSpecError(
            f"unknown collector module(s) {unknown} — not in the agent's closed "
            f"vocabulary {sorted(AGENT_COLLECTOR_NAMES)}"
        )

    if not raw_paths:
        raise InvalidScanSpecError("'paths' must not be empty")
    if not raw_collectors:
        raise InvalidScanSpecError("'collectors' must not be empty")

    return ScanSpec(paths=tuple(raw_paths), collectors=tuple(raw_collectors))
