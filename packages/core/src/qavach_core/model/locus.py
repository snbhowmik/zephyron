"""ARCH.md §6.2 — where a claim about an asset came from, precisely.

Occurrences are never merged across locus types (ARCH.md §6.2) — that is
what makes an asset's blast radius visible. Every variant is its own
frozen dataclass rather than one loosely-typed locus record, so a
collector cannot accidentally construct a locus that mixes fields from two
kinds of source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class SourceLocus:
    repo: str
    commit: str
    path: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class DependencyLocus:
    purl: str
    dependency_path: str


@dataclass(frozen=True, slots=True)
class ContainerLocus:
    image_digest: str
    layer_digest: str
    path: str


@dataclass(frozen=True, slots=True)
class RuntimeLocus:
    process: str
    module: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class NetworkLocus:
    host: str
    port: int
    sni: str | None
    protocol: str


@dataclass(frozen=True, slots=True)
class CloudLocus:
    provider: str
    account: str
    region: str
    resource_arn: str


@dataclass(frozen=True, slots=True)
class HsmLocus:
    module_path: str
    slot_ref: str


@dataclass(frozen=True, slots=True)
class FileLocus:
    """Local mount — the target is implicit (a repo checkout, an image
    layer). Never repurposed for agent-collected evidence; see HostLocus."""

    path: str
    offset: int


@dataclass(frozen=True, slots=True)
class HostLocus:
    """Agent-collected evidence — names which host. ARCH.md §3a.4, §6.2;
    resolves OQ-09 (NOTE.md §6).

    host_identity is the agent's registered identity issued at enrollment
    (ARCH.md §3a), never an operator-typed hostname string — a typed
    string can be wrong or spoofed, the identity the backend itself issued
    cannot.
    """

    host_identity: str
    path: str
    offset: int


type Locus = (
    SourceLocus
    | DependencyLocus
    | ContainerLocus
    | RuntimeLocus
    | NetworkLocus
    | CloudLocus
    | HsmLocus
    | FileLocus
    | HostLocus
)
