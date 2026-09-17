"""T-030 — the Collector protocol, CollectorResult, and registry."""

from __future__ import annotations

import pytest
from qavach_collectors import (
    Collector,
    CollectorError,
    CollectorRegistry,
    CollectorResult,
    DuplicateCollectorError,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)
from qavach_core.model import ConfidenceTier, FileLocus


class _FakeCollector:
    """A minimal real implementation — proves `Collector` is a usable
    structural protocol, not just an unreachable abstract shape."""

    name = "fake.collector"
    version = "0.1.0"
    default_confidence = ConfidenceTier.PATTERN
    requires_sandbox = True
    requires_network = False

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        return CollectorResult(
            raw=b'{"ok": true}',
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=[
                RawClaim(
                    locus=FileLocus(path="x.py", offset=0),
                    name="AES",
                    confidence=self.default_confidence,
                )
            ],
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=("fake",),
                exit_code=0,
                duration_seconds=0.1,
            ),
            errors=[],
            partial=False,
        )


def test_fake_collector_satisfies_the_protocol_structurally() -> None:
    """`Collector` is a `typing.Protocol` — a class needs no explicit
    inheritance to satisfy it, only the right shape."""
    assert isinstance(_FakeCollector(), Collector)


def test_collect_returns_a_valid_result() -> None:
    collector = _FakeCollector()
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="https://example.com/repo"),
        RunContext(scan_run_id="run-1"),
    )
    assert not result.partial
    assert len(result.claims) == 1
    assert result.errors == []
    assert result.raw == b'{"ok": true}'


def test_partial_result_is_a_valid_shape_not_an_exception() -> None:
    """ARCH.md §2.1: a collector failing is a degraded scan, not a failed
    scan — CollectorResult must be able to represent that directly."""
    result = CollectorResult(
        raw=b"",
        raw_format=RawFormat.QAVACH_NATIVE,
        claims=[],
        tool=ToolIdentity(
            name="x", version="1", invocation=(), exit_code=137, duration_seconds=900.0
        ),
        errors=[CollectorError(message="timed out", fatal=True)],
        partial=True,
    )
    assert result.partial
    assert result.errors[0].fatal


# --- CollectorRegistry ---


def test_registry_registers_and_looks_up_by_name() -> None:
    registry = CollectorRegistry()
    registry.register(_FakeCollector())
    assert registry.get("fake.collector").name == "fake.collector"
    assert len(registry) == 1


def test_registry_rejects_duplicate_names() -> None:
    registry = CollectorRegistry()
    registry.register(_FakeCollector())
    with pytest.raises(DuplicateCollectorError):
        registry.register(_FakeCollector())


def test_registry_for_target_filters_by_supports() -> None:
    registry = CollectorRegistry()
    registry.register(_FakeCollector())
    matches = registry.for_target(Target(type=TargetType.REPOSITORY, ref="x"))
    assert len(matches) == 1
    no_matches = registry.for_target(Target(type=TargetType.CLOUD_ACCOUNT, ref="x"))
    assert no_matches == []


def test_registry_iterates_registered_collectors() -> None:
    registry = CollectorRegistry()
    registry.register(_FakeCollector())
    assert [c.name for c in registry] == ["fake.collector"]


def test_target_options_default_to_empty_dict() -> None:
    target = Target(type=TargetType.HOST, ref="agent-123")
    assert target.options == {}


def test_run_context_build_resolution_defaults_to_off() -> None:
    """SECURITY.md §3.1: build resolution is off by default — never
    silently enabled."""
    ctx = RunContext(scan_run_id="run-1")
    assert ctx.allow_build_resolution is False
