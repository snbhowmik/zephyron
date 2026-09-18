"""SECURITY.md §4 — the TLS endpoint collector accepts operator-supplied
host:port targets, 'an SSRF primitive by construction.' T-035.

`NetworkPolicy` loads `config/security/network_policy.yaml`'s denylist.
`resolve_and_validate` is the one function every network-target collector
must route through: it resolves the hostname exactly once, validates the
resulting address against the policy, and returns that address for the
caller to connect to directly — 'resolve then pin... never resolve twice.
Re-resolution between validation and connection is a classic
DNS-rebinding bypass' (SECURITY.md §4).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import cast

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class SsrfDeniedError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    denied_cidrs: tuple[IPNetwork, ...]
    denied_hostnames: frozenset[str]
    own_network_cidrs: tuple[IPNetwork, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> NetworkPolicy:
        denied_cidrs = tuple(
            ipaddress.ip_network(c, strict=False)
            for c in cast("list[str]", data.get("denied_cidrs", []))
        )
        own_network_cidrs = tuple(
            ipaddress.ip_network(c, strict=False)
            for c in cast("list[str]", data.get("own_network_cidrs", []))
        )
        denied_hostnames = frozenset(
            str(h).lower() for h in cast("list[str]", data.get("denied_hostnames", []))
        )
        return cls(
            denied_cidrs=denied_cidrs,
            denied_hostnames=denied_hostnames,
            own_network_cidrs=own_network_cidrs,
        )

    def with_kubernetes_service_cidr(self, env: dict[str, str] | None = None) -> NetworkPolicy:
        """SECURITY.md §4: 'Kubernetes service CIDRs and the API server,
        when detected.' Detected via the same `KUBERNETES_SERVICE_HOST`
        env var kubelet injects into every pod — if it's absent, QAVACH
        isn't running in a cluster and nothing is added."""
        environ = env if env is not None else dict(os.environ)
        host = environ.get("KUBERNETES_SERVICE_HOST")
        if not host:
            return self
        try:
            api_server_addr = ipaddress.ip_address(host)
        except ValueError:
            return self
        api_server_network = ipaddress.ip_network(f"{api_server_addr}/32")
        return type(self)(
            denied_cidrs=(*self.denied_cidrs, api_server_network),
            denied_hostnames=self.denied_hostnames,
            own_network_cidrs=self.own_network_cidrs,
        )

    def is_address_denied(self, address: IPAddress) -> bool:
        all_denied = (*self.denied_cidrs, *self.own_network_cidrs)
        return any(address in network for network in all_denied)

    def is_hostname_denied(self, hostname: str) -> bool:
        return hostname.lower() in self.denied_hostnames


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    hostname: str
    address: IPAddress
    port: int


def resolve_and_validate(hostname: str, port: int, *, policy: NetworkPolicy) -> ResolvedTarget:
    """Resolves `hostname` exactly once, validates the hostname itself and
    every candidate address `getaddrinfo` returns against `policy`, and
    returns the first address that passes — for the caller to connect to
    *by address*, with SNI set to `hostname` separately, never by
    resolving the hostname a second time at connect time."""
    if policy.is_hostname_denied(hostname):
        raise SsrfDeniedError(f"{hostname!r} is on the denylist")

    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SsrfDeniedError(f"could not resolve {hostname!r}: {exc}") from exc

    candidates = [ipaddress.ip_address(info[4][0]) for info in infos]
    if not candidates:
        raise SsrfDeniedError(f"{hostname!r} resolved to no addresses")

    denied = [addr for addr in candidates if policy.is_address_denied(addr)]
    if denied:
        raise SsrfDeniedError(
            f"{hostname!r} resolves to denylisted address(es): {[str(a) for a in denied]}"
        )

    return ResolvedTarget(hostname=hostname, address=candidates[0], port=port)
