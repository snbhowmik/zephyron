"""T-044 — `runtime.tracebom`. Library mapping is replayed from a BOM
recorded from the *real* tool under the sandbox's real flags; the
crypto-asset path (TLS suites) is exercised with hand-written input only,
because the sandbox cannot provide the eBPF/network tracebom needs for it
(`NOTE.md` OQ-17). The integration test runs the real image."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.binary import BinaryKnowledge
from qavach_collectors.runtime import TracebomCollector, library_claims
from qavach_collectors.source_scan import ImageNotBuiltError
from qavach_core.model import RuntimeLocus
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_sandbox import SandboxConfig, SandboxResult

ROOT = Path(__file__).parent.parent.parent
RECORDED = ROOT / "tests/fixtures/scanner-output/tracebom/python-ssl.cdx.json"
FAKE_IMAGE = "sha256:" + "e" * 64
REGISTRY = CryptographyRegistry.from_dict(
    json.loads((ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text())
)
ALIASES = AliasTable.from_dict(yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text()))
KNOWLEDGE = BinaryKnowledge.from_dict(
    yaml.safe_load((ROOT / "config/knowledge/binary_crypto.yaml").read_text())
)
TARGET = Target(type=TargetType.REPOSITORY, ref="/repo", options={"cmd": "python3 app.py"})


def _collector(image: str | None = FAKE_IMAGE) -> TracebomCollector:
    return TracebomCollector(
        registry=REGISTRY, aliases=ALIASES, knowledge=KNOWLEDGE, image_ref=image
    )


def _run(
    monkeypatch: pytest.MonkeyPatch, result: SandboxResult, target: Target = TARGET
) -> tuple[Any, list[SandboxConfig]]:
    seen: list[SandboxConfig] = []

    def fake(config: SandboxConfig) -> SandboxResult:
        seen.append(config)
        return result

    monkeypatch.setattr("qavach_collectors.runtime.tracebom.run_sandboxed", fake)
    return _collector().collect(target, RunContext(scan_run_id="r")), seen


def _ok(document: dict[str, Any] | bytes) -> SandboxResult:
    body = document if isinstance(document, bytes) else json.dumps(document).encode()
    return SandboxResult(0, body, b"", 1.0, False)


def test_supports_only_repository_targets_that_carry_a_command() -> None:
    c = _collector()
    assert c.supports(TARGET)
    assert not c.supports(Target(type=TargetType.REPOSITORY, ref="/r"))
    assert not c.supports(Target(type=TargetType.HOST, ref="/r", options={"cmd": "x"}))


def test_unconfigured_image_fails_loudly() -> None:
    with pytest.raises(ImageNotBuiltError, match="build-images"):
        _collector(None)


def test_recorded_real_bom_yields_capability_claims_at_dependency_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _ = _run(monkeypatch, _ok(RECORDED.read_bytes()))
    assert not result.partial, result.errors
    assert {c.confidence.name for c in result.claims} == {"DEPENDENCY"}
    assert all(isinstance(c.locus, RuntimeLocus) for c in result.claims)
    modules = {c.locus.module.rsplit("/", 1)[-1] for c in result.claims}
    assert {"libcrypto.so.3", "libssl.so.3"} <= modules
    assert any(c.name == "AES" for c in result.claims)
    assert result.raw_format.value == "cdx-1.7"


def test_claims_are_deterministic_for_the_same_output(monkeypatch: pytest.MonkeyPatch) -> None:
    a, _ = _run(monkeypatch, _ok(RECORDED.read_bytes()))
    b, _ = _run(monkeypatch, _ok(RECORDED.read_bytes()))
    assert a.claims == b.claims  # observed_at comes from the BOM, not the clock


def test_command_reaches_the_sandbox_as_env_never_in_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    hostile = "python3 -c 'x'; rm -rf / #"
    _, seen = _run(
        monkeypatch,
        _ok(RECORDED.read_bytes()),
        Target(type=TargetType.REPOSITORY, ref="/repo", options={"cmd": hostile}),
    )
    config = seen[0]
    assert config.env["QAVACH_TRACE_CMD"] == hostile
    assert hostile not in " ".join(config.command)
    assert config.tmp_exec is True and config.requires_network is False


def test_empty_bom_is_a_coverage_gap_not_no_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    empty = {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}
    result, _ = _run(monkeypatch, _ok(empty))
    assert result.partial and result.claims == []
    assert "not evidence of no cryptography" in result.errors[0].message
    assert not result.errors[0].fatal


def test_trace_failure_on_stderr_is_fatal_even_with_exit_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = json.dumps({"components": []}).encode()
    result, _ = _run(
        monkeypatch,
        SandboxResult(
            0, empty, b"Tracing command execution failed: Error: spawn EACCES", 1.0, False
        ),
    )
    assert result.partial and result.errors[0].fatal and result.claims == []


@pytest.mark.parametrize(
    "sandbox_result",
    [
        SandboxResult(1, b"", b"boom", 1.0, False),
        SandboxResult(None, b"", b"", 900.0, True),
        SandboxResult(0, b"not json", b"", 1.0, False),
        SandboxResult(0, b"[1]", b"", 1.0, False),
    ],
)
def test_failures_degrade(monkeypatch: pytest.MonkeyPatch, sandbox_result: SandboxResult) -> None:
    result, _ = _run(monkeypatch, sandbox_result)
    assert result.partial and result.errors[0].fatal and result.claims == []


@pytest.mark.parametrize("cmd", ["", "   ", "x" * 5000, "a\x00b"])
def test_invalid_commands_never_reach_the_sandbox(
    monkeypatch: pytest.MonkeyPatch, cmd: str
) -> None:
    result, seen = _run(
        monkeypatch,
        _ok(RECORDED.read_bytes()),
        Target(type=TargetType.REPOSITORY, ref="/repo", options={"cmd": cmd}),
    )
    assert seen == [] and result.partial and result.errors[0].fatal


def test_library_components_that_are_not_crypto_produce_nothing() -> None:
    assert (
        library_claims(
            ["/lib64/libc.so.6", "/lib64/libz.so.1"],
            KNOWLEDGE,
            process="p",
            observed_at=datetime.now(UTC),
        )
        == []
    )


def test_crypto_asset_components_are_normalised_at_runtime_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "tls/suite",
                "name": "AES-256-GCM",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "ae",
                        "algorithmFamily": "AES",
                        "mode": "gcm",
                        "parameterSetIdentifier": "256",
                    },
                },
            }
        ],
    }
    result, _ = _run(monkeypatch, _ok(bom))
    aes = [c for c in result.claims if c.name == "AES"]
    assert aes and aes[0].confidence.name == "RUNTIME"
    assert aes[0].locus.path.startswith("runtime!")  # type: ignore[union-attr]


def _built_image_id() -> str | None:
    if shutil.which("docker") is None:
        return None
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "qavach/tracebom:dev"],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


@pytest.mark.integration
def test_real_image_reports_the_crypto_libraries_a_process_actually_loads() -> None:
    image = _built_image_id()
    if image is None:
        pytest.skip("image not built — run `make build-images`")
    target = Target(
        type=TargetType.REPOSITORY,
        ref=str(ROOT / "tests/fixtures/targets/polyglot"),
        options={"cmd": "python3 -c 'import hashlib, ssl; ssl.create_default_context()'"},
    )
    result = _collector(image).collect(target, RunContext(scan_run_id="r"))
    assert not result.partial, result.errors
    modules = {c.locus.module.rsplit("/", 1)[-1] for c in result.claims}  # type: ignore[union-attr]
    assert "libcrypto.so.3" in modules

    quiet = _collector(image).collect(
        Target(type=TargetType.REPOSITORY, ref=target.ref, options={"cmd": "true"}),
        RunContext(scan_run_id="r"),
    )
    assert not quiet.partial and quiet.claims == []  # loads only glibc: genuinely no crypto
