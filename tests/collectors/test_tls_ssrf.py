"""T-035 — `tls/ssrf.py`, `SECURITY.md §4`'s denylist. Loads the *real*
`config/security/network_policy.yaml` for most tests (its own exit
criterion: the file must actually parse and deny what it claims to), plus
a couple of hand-built policies for edge cases that don't belong in the
production file itself (Kubernetes detection, an intentionally-empty
policy)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
import yaml
from qavach_collectors.tls import NetworkPolicy, SsrfDeniedError, resolve_and_validate

ROOT = Path(__file__).parent.parent.parent
REAL_POLICY_YAML = ROOT / "config" / "security" / "network_policy.yaml"


@pytest.fixture(scope="module")
def real_policy() -> NetworkPolicy:
    return NetworkPolicy.from_dict(yaml.safe_load(REAL_POLICY_YAML.read_text()))


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",  # cloud metadata
        "169.254.1.1",  # link-local
        "127.0.0.1",  # loopback
        "::1",  # IPv6 loopback
        "10.0.0.5",  # RFC 1918
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.1",
        "224.0.0.1",  # multicast
        "192.0.2.1",  # TEST-NET-1
    ],
)
def test_real_policy_denies_known_bad_addresses(real_policy: NetworkPolicy, address: str) -> None:
    assert real_policy.is_address_denied(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_real_policy_allows_ordinary_public_addresses(
    real_policy: NetworkPolicy, address: str
) -> None:
    assert not real_policy.is_address_denied(ipaddress.ip_address(address))


def test_real_policy_denies_known_metadata_hostnames(real_policy: NetworkPolicy) -> None:
    assert real_policy.is_hostname_denied("metadata.google.internal")
    assert real_policy.is_hostname_denied("METADATA.GOOGLE.INTERNAL")  # case-insensitive
    assert real_policy.is_hostname_denied("metadata.goog")


def test_real_policy_allows_ordinary_hostnames(real_policy: NetworkPolicy) -> None:
    assert not real_policy.is_hostname_denied("example.com")


def test_kubernetes_service_cidr_added_only_when_env_var_present() -> None:
    policy = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})
    assert not policy.is_address_denied(ipaddress.ip_address("10.96.0.1"))

    with_k8s = policy.with_kubernetes_service_cidr(env={"KUBERNETES_SERVICE_HOST": "10.96.0.1"})
    assert with_k8s.is_address_denied(ipaddress.ip_address("10.96.0.1"))
    assert not with_k8s.is_address_denied(ipaddress.ip_address("10.96.0.2"))

    without_k8s = policy.with_kubernetes_service_cidr(env={})
    assert without_k8s is policy  # unchanged — no env var, no mutation


def test_own_network_cidrs_are_denied_like_any_other_cidr() -> None:
    policy = NetworkPolicy.from_dict(
        {"denied_cidrs": [], "denied_hostnames": [], "own_network_cidrs": ["10.50.0.0/16"]}
    )
    assert policy.is_address_denied(ipaddress.ip_address("10.50.1.1"))
    assert not policy.is_address_denied(ipaddress.ip_address("10.51.1.1"))


# --- resolve_and_validate: real DNS resolution against a name that is
# universally available without any network dependency ---


def test_resolve_and_validate_denies_localhost_via_the_real_policy(
    real_policy: NetworkPolicy,
) -> None:
    """`localhost` resolves to `127.0.0.1`/`::1`, both denylisted by the
    real policy — a real (loopback-only) DNS resolution, no live internet
    dependency, and a genuine end-to-end proof `resolve_and_validate`
    actually rejects what the policy says it should."""
    with pytest.raises(SsrfDeniedError, match="denylisted"):
        resolve_and_validate("localhost", 443, policy=real_policy)


def test_resolve_and_validate_denies_a_denylisted_hostname_before_resolving() -> None:
    policy = NetworkPolicy.from_dict(
        {"denied_cidrs": [], "denied_hostnames": ["metadata.google.internal"]}
    )
    with pytest.raises(SsrfDeniedError, match="denylist"):
        resolve_and_validate("metadata.google.internal", 443, policy=policy)


def test_resolve_and_validate_raises_on_unresolvable_hostname() -> None:
    policy = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})
    with pytest.raises(SsrfDeniedError, match="could not resolve"):
        resolve_and_validate("this-domain-should-never-resolve.invalid", 443, policy=policy)


def test_resolve_and_validate_succeeds_for_an_allowed_loopback_policy() -> None:
    """An empty-denylist policy (never the production default) allows
    `localhost` to resolve — proves the function itself isn't hardcoded to
    reject loopback, only that the real policy does."""
    policy = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})
    target = resolve_and_validate("localhost", 443, policy=policy)
    assert target.hostname == "localhost"
    assert str(target.address) in {"127.0.0.1", "::1"}
    assert target.port == 443
