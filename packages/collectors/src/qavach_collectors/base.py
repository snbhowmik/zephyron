"""ARCH.md §2.1 — the Collector protocol, CollectorResult, and a registry.
T-030.

Every source, whether a third-party binary or something QAVACH wrote, sits
behind this one interface. A collector never writes to the database, never
merges or deduplicates (that's `qavach_core.reconcile`, Phase 2) — it only
reports what its tool said. `raw` is always retained: when a reviewer asks
"did the tool really say that," the answer is a stored artefact, not a
reconstruction. A collector failing is a degraded scan, not a failed scan
(`partial=True`), never an exception escaping into the pipeline.

Unlike `packages/core`, this package is allowed I/O (CLAUDE.md §2 forbids
only the reverse import direction) — but this specific module has none:
it is the shared protocol/data shapes every real collector implements.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from qavach_core.model import ConfidenceTier, Locus


class TargetType(StrEnum):
    """PRD.md FR-601's target-type selector, given a concrete shape."""

    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container-image"
    NETWORK_ENDPOINT = "network-endpoint"
    DIRECTORY_SERVICE = "directory-service"
    CLOUD_ACCOUNT = "cloud-account"
    HOST = "host"
    CBOM_UPLOAD = "cbom-upload"


@dataclass(frozen=True, slots=True)
class Target:
    """What a collector is asked to scan. `ref` is the primary locator
    (repo URL/path, image ref, `host:port`, LDAP URL, ...); `options` is a
    flexible bag for the rest rather than one giant dataclass with mostly-
    unused fields per target type — ARCH.md does not specify a single
    fixed shape here."""

    type: TargetType
    ref: str
    options: dict[str, str] = field(default_factory=dict)


class RawFormat(StrEnum):
    """ARCH.md §2.1's `CDX_1_6 | CDX_1_7 | SARIF | SYFT_JSON |
    QAVACH_NATIVE` — extended to the full 1.4-1.7 range T-014 actually
    accepts (ARCH.md §5.1), since restricting to just 1.6/1.7 here would
    silently narrow what that layer already supports."""

    CDX_1_4 = "cdx-1.4"
    CDX_1_5 = "cdx-1.5"
    CDX_1_6 = "cdx-1.6"
    CDX_1_7 = "cdx-1.7"
    SARIF = "sarif"
    SYFT_JSON = "syft-json"
    QAVACH_NATIVE = "qavach-native"


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    name: str
    version: str
    invocation: tuple[str, ...]
    """The exact command/args run, for audit — SECURITY.md §6: credentials
    are passed via env var or a 0400 tmpfs file, never as a CLI argument
    that would end up here."""
    exit_code: int | None
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class CollectorError:
    message: str
    fatal: bool
    """True if this error means the collector produced nothing usable;
    False for a soft/partial failure where `claims` may still be
    non-empty."""


@dataclass(frozen=True, slots=True)
class RawClaim:
    """Parsed, not yet normalised — `qavach_core.normalize` does
    canonicalisation (T-012/T-014). Deliberately close to
    `RawAlgorithmClaim`'s input shape (a name/oid/etc a collector
    observed) rather than a resolved result; a collector reports what it
    saw, it does not resolve against the registry itself."""

    locus: Locus
    name: str | None = None
    oid: str | None = None
    primitive: str | None = None
    parameter_set: str | None = None
    mode: str | None = None
    padding: str | None = None
    detection_method: str = "other"
    confidence: ConfidenceTier = ConfidenceTier.HEURISTIC


@dataclass(frozen=True, slots=True)
class CollectorResult:
    raw: bytes
    raw_format: RawFormat
    claims: list[RawClaim]
    tool: ToolIdentity
    errors: list[CollectorError]
    partial: bool


@dataclass(frozen=True, slots=True)
class RunContext:
    """Per-scan-run context every collector gets. ARCH.md names this type
    (`ctx: RunContext`) without specifying its fields beyond what
    `SECURITY.md §3.1` requires (`--allow-build-resolution`, off by
    default) — extended here only as far as that citable requirement,
    not guessed further."""

    scan_run_id: str
    allow_build_resolution: bool = False


@runtime_checkable
class Collector(Protocol):
    name: str
    version: str
    default_confidence: ConfidenceTier
    requires_sandbox: bool
    requires_network: bool

    def supports(self, target: Target) -> bool: ...
    def collect(self, target: Target, ctx: RunContext) -> CollectorResult: ...


class DuplicateCollectorError(ValueError):
    pass


class CollectorRegistry:
    """T-030's '+ registry' — register collectors, look up which ones
    support a given target."""

    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}

    def register(self, collector: Collector) -> None:
        if collector.name in self._collectors:
            raise DuplicateCollectorError(f"collector {collector.name!r} already registered")
        self._collectors[collector.name] = collector

    def get(self, name: str) -> Collector:
        return self._collectors[name]

    def for_target(self, target: Target) -> list[Collector]:
        return [c for c in self._collectors.values() if c.supports(target)]

    def __iter__(self) -> Iterator[Collector]:
        return iter(self._collectors.values())

    def __len__(self) -> int:
        return len(self._collectors)
