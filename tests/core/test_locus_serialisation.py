"""T-021 — Locus parsers and round-trip serialisation (ARCH.md §6.2, §11)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from qavach_core.model.locus import (
    CloudLocus,
    ContainerLocus,
    DependencyLocus,
    FileLocus,
    HostLocus,
    HsmLocus,
    NetworkLocus,
    RuntimeLocus,
    SourceLocus,
    locus_from_dict,
    locus_to_dict,
    locus_type_name,
)

ALL_LOCI = [
    SourceLocus(
        repo="github.com/x/y", commit="abc123", path="src/Main.java", start_line=1, end_line=5
    ),
    DependencyLocus(purl="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78", dependency_path="a>b>c"),
    ContainerLocus(image_digest="sha256:abc", layer_digest="sha256:def", path="/usr/lib/libssl.so"),
    RuntimeLocus(process="java", module="Auth", observed_at=datetime(2026, 9, 18, tzinfo=UTC)),
    NetworkLocus(host="example.com", port=443, sni="example.com", protocol="tls1.3"),
    CloudLocus(
        provider="aws", account="123456789", region="ap-south-1", resource_arn="arn:aws:kms:..."
    ),
    HsmLocus(module_path="/usr/lib/pkcs11.so", slot_ref="slot-0"),
    FileLocus(path="/etc/ssl/cert.pem", offset=0),
    HostLocus(host_identity="agent-7f3c9e", path="/etc/pki/tls/certs/x.pem", offset=0),
]


@pytest.mark.parametrize("locus", ALL_LOCI, ids=[type(x).__name__ for x in ALL_LOCI])
def test_round_trips_exactly(locus) -> None:
    assert locus_from_dict(locus_to_dict(locus)) == locus


@pytest.mark.parametrize("locus", ALL_LOCI, ids=[type(x).__name__ for x in ALL_LOCI])
def test_serialised_form_is_plain_json_safe(locus) -> None:
    """No datetime objects, no custom types — every value must be a str,
    int, float, bool or None so json.dumps() works without a custom
    encoder (ARCH.md §11 stores this as a plain JSON column)."""
    import json

    serialised = locus_to_dict(locus)
    json.dumps(serialised)  # raises TypeError if anything isn't JSON-safe


def test_locus_type_discriminator_is_present_and_correct() -> None:
    assert locus_to_dict(FileLocus(path="/x", offset=0))["locus_type"] == "file"
    assert locus_to_dict(HostLocus(host_identity="a", path="/x", offset=0))["locus_type"] == "host"
    assert (
        locus_to_dict(NetworkLocus(host="h", port=443, sni=None, protocol="tls"))["locus_type"]
        == "network"
    )


def test_locus_type_name_matches_the_dict_discriminator() -> None:
    for locus in ALL_LOCI:
        assert locus_to_dict(locus)["locus_type"] == locus_type_name(locus)


def test_unknown_locus_type_on_deserialise_raises() -> None:
    with pytest.raises(ValueError, match="unknown locus_type"):
        locus_from_dict({"locus_type": "not-a-real-type", "path": "/x"})


def test_runtime_locus_datetime_round_trips_exactly() -> None:
    original = RuntimeLocus(
        process="python3",
        module="tls_scanner",
        observed_at=datetime(2026, 9, 18, 3, 14, 15, tzinfo=UTC),
    )
    serialised = locus_to_dict(original)
    assert isinstance(serialised["observed_at"], str)  # not a datetime object
    restored = locus_from_dict(serialised)
    assert restored == original
    assert restored.observed_at.tzinfo is not None  # timezone info survives the round trip
