"""Asset -> system binding. T-051.

Assets are found by scanners; systems are owned by people. This links them by
the identifiers an operator actually has: a repository, a container image, a
network endpoint, a cloud account (and, for agent evidence, a host).

**Nothing is dropped.** An asset that matches no system goes to an explicit
`unassigned` list the UI must show, because "we cannot say who owns this" is a
finding, not an omission. An asset matching several systems is bound to all of
them - shared crypto is real, and each system decides its own migration.

**Loci do not carry the scan target.** A source scan emits a `FileLocus`
(`path`, `offset`) with no repository, because the target is implicit in the
scan. So a binding key is derived from the locus *and*, where the locus cannot
name it, the scan target the pipeline already knows (`BindingKey`). This module
does not pretend a locus says more than it does.

Matching rules (normalisation is deliberate and minimal - it is exact matching
on a canonical form, never fuzzy):

* repo: lower-case, scheme/credentials/`git@host:` and a trailing `.git` or `/`
  stripped, so `https://GitHub.com/acme/pay.git` == `git@github.com:acme/pay`;
* image: exact `sha256:<hex>` digest;
* endpoint: `host`, `host:port`, or a `*.suffix` wildcard (host part only);
* cloud account: `provider:account`;
* host: the agent's registered host identity.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from qavach_core.context.systems import SystemBindings
from qavach_core.model.identity import AssetIdentity
from qavach_core.model.locus import (
    CloudLocus,
    ContainerLocus,
    HostLocus,
    Locus,
    NetworkLocus,
    SourceLocus,
)

REPO, IMAGE, ENDPOINT, CLOUD_ACCOUNT, HOST = "repo", "image", "endpoint", "cloud_account", "host"


@dataclass(frozen=True, slots=True)
class BindingKey:
    kind: str
    ref: str


@dataclass(frozen=True, slots=True)
class SystemMatch:
    system_id: str
    basis: tuple[str, ...]
    """Which keys matched, e.g. `('repo:acme/pay',)` - shown so the operator can
    see why an asset landed on a system."""


@dataclass(frozen=True, slots=True)
class BindingResult:
    matches: Mapping[AssetIdentity, tuple[SystemMatch, ...]]
    unassigned: tuple[AssetIdentity, ...]

    def systems_for(self, identity: AssetIdentity) -> tuple[str, ...]:
        return tuple(m.system_id for m in self.matches.get(identity, ()))


def normalise_repo(ref: str) -> str:
    text = ref.strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = re.sub(r"^[^@/]+@", "", text)
    text = text.replace(":", "/", 1) if re.match(r"^[^/]+:[^/0-9]", text) else text
    text = text.rstrip("/")
    return text.removesuffix(".git").rstrip("/")


def _endpoint_matches(pattern: str, host: str, port: int | None) -> bool:
    pattern = pattern.strip().lower()
    host = host.lower()
    pattern_host, _, pattern_port = pattern.partition(":")
    if pattern_port and (port is None or str(port) != pattern_port):
        return False
    if pattern_host.startswith("*."):
        return host.endswith(pattern_host[1:]) and host != pattern_host[2:]
    return host == pattern_host


def keys_for_locus(locus: Locus, *, scan_target: BindingKey | None = None) -> list[BindingKey]:
    keys: list[BindingKey] = []
    if isinstance(locus, SourceLocus):
        keys.append(BindingKey(REPO, locus.repo))
    elif isinstance(locus, ContainerLocus):
        keys.append(BindingKey(IMAGE, locus.image_digest))
    elif isinstance(locus, NetworkLocus):
        keys.append(BindingKey(ENDPOINT, f"{locus.host}:{locus.port}"))
    elif isinstance(locus, CloudLocus):
        keys.append(BindingKey(CLOUD_ACCOUNT, f"{locus.provider}:{locus.account}"))
    elif isinstance(locus, HostLocus):
        keys.append(BindingKey(HOST, locus.host_identity))
    if scan_target is not None:
        keys.append(scan_target)
    return keys


def _matching_basis(keys: Iterable[BindingKey], bindings: SystemBindings) -> list[str]:
    basis: list[str] = []
    repos = {normalise_repo(r) for r in bindings.repos}
    images = {i.strip().lower() for i in bindings.images}
    accounts = {a.strip().lower() for a in bindings.cloud_accounts}
    hosts = {h.strip().lower() for h in bindings.hosts}
    for key in keys:
        if key.kind == REPO and normalise_repo(key.ref) in repos:
            basis.append(f"repo:{normalise_repo(key.ref)}")
        elif key.kind == IMAGE and key.ref.strip().lower() in images:
            basis.append(f"image:{key.ref.strip().lower()}")
        elif key.kind == CLOUD_ACCOUNT and key.ref.strip().lower() in accounts:
            basis.append(f"cloud_account:{key.ref.strip().lower()}")
        elif key.kind == HOST and key.ref.strip().lower() in hosts:
            basis.append(f"host:{key.ref.strip().lower()}")
        elif key.kind == ENDPOINT:
            host, _, port_text = key.ref.rpartition(":")
            port = int(port_text) if port_text.isdigit() else None
            for pattern in sorted(bindings.endpoints):
                if _endpoint_matches(pattern, host or key.ref, port):
                    basis.append(f"endpoint:{pattern.lower()}")
                    break
    return basis


def bind_assets(
    assets: Mapping[AssetIdentity, Sequence[BindingKey]],
    bindings: Mapping[str, SystemBindings],
) -> BindingResult:
    """`assets` maps each asset to every binding key its occurrences yield
    (`keys_for_locus`). Deterministic: systems are visited in sorted order."""
    matches: dict[AssetIdentity, tuple[SystemMatch, ...]] = {}
    unassigned: list[AssetIdentity] = []
    for identity, keys in assets.items():
        found: list[SystemMatch] = []
        for system_id in sorted(bindings):
            basis = sorted(set(_matching_basis(keys, bindings[system_id])))
            if basis:
                found.append(SystemMatch(system_id, tuple(basis)))
        if found:
            matches[identity] = tuple(found)
        else:
            unassigned.append(identity)
    return BindingResult(matches=matches, unassigned=tuple(unassigned))
