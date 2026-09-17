"""ARCH.md §6.2 — where a claim about an asset came from, precisely.

Occurrences are never merged across locus types (ARCH.md §6.2) — that is
what makes an asset's blast radius visible. Every variant is its own
frozen dataclass rather than one loosely-typed locus record, so a
collector cannot accidentally construct a locus that mixes fields from two
kinds of source.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


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


# --- Round-trip (de)serialisation, T-021. ARCH.md §11's storage schema
# stores each occurrence as (locus_type, locus_json) — this is that
# discriminator plus the (de)serialiser, kept in this module since it's
# the one place that must stay in sync with the Locus union above. ---

_LOCUS_TYPES: dict[str, type] = {
    "source": SourceLocus,
    "dependency": DependencyLocus,
    "container": ContainerLocus,
    "runtime": RuntimeLocus,
    "network": NetworkLocus,
    "cloud": CloudLocus,
    "hsm": HsmLocus,
    "file": FileLocus,
    "host": HostLocus,
}
_LOCUS_TYPE_NAMES: dict[type, str] = {cls: name for name, cls in _LOCUS_TYPES.items()}


def locus_type_name(locus: Locus) -> str:
    try:
        return _LOCUS_TYPE_NAMES[type(locus)]
    except KeyError as exc:
        raise TypeError(f"not a known Locus variant: {type(locus)!r}") from exc


def locus_to_dict(locus: Locus) -> dict[str, Any]:
    """`{"locus_type": ..., **fields}` — the shape ARCH.md §11's
    `locus_type`/`locus_json` storage columns expect. `datetime` fields
    (only `RuntimeLocus.observed_at`) are serialised to ISO 8601 so the
    result is plain-JSON-safe."""
    data: dict[str, Any] = dataclasses.asdict(locus)
    for key, value in data.items():
        if isinstance(value, datetime):
            data[key] = value.isoformat()
    return {"locus_type": locus_type_name(locus), **data}


def locus_from_dict(data: Mapping[str, Any]) -> Locus:
    """Inverse of `locus_to_dict` — round-trips exactly, including
    `RuntimeLocus.observed_at`'s ISO 8601 string back to a `datetime`."""
    locus_type = data.get("locus_type")
    cls = _LOCUS_TYPES.get(locus_type)  # type: ignore[arg-type]
    if cls is None:
        raise ValueError(f"unknown locus_type: {locus_type!r}")

    fields = {k: v for k, v in data.items() if k != "locus_type"}
    if cls is RuntimeLocus and isinstance(fields.get("observed_at"), str):
        fields["observed_at"] = datetime.fromisoformat(fields["observed_at"])
    return cls(**fields)  # type: ignore[no-any-return]
