"""T-033 — `sbom.syft`. As with `test_cdxgen.py`, the parsing/mapping
pipeline is tested deterministically against hand-written syft-shaped
CycloneDX output (`crypto_libraries.yaml`'s real 40-library curation is
T-034, not built here — this uses a small fixture mapping, exactly this
repo's established "the real data file is a separate task" pattern), and
a real Docker integration test proves the actual sandboxed invocation
works end to end against real `pip`-ecosystem packages syft reliably
detects from a bare `requirements.txt` (verified live while building this
adapter — a bare `package.json` with no lockfile produces zero components,
whereas `requirements.txt` with pinned versions does not need one)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.sbom import CryptoLibraryMapping, SyftCollector
from qavach_sandbox import SandboxResult

FIXTURE_MAPPING = CryptoLibraryMapping.from_entries(
    [
        {
            "type": "pypi",
            "name": "cryptography",
            "provides": ["AES", "RSA", "SHA-256", "ECDSA"],
        },
        {
            "type": "pypi",
            "name": "pyjwt",
            "provides": ["HMAC", "RSA"],
        },
        {
            "type": "maven",
            "namespace": "org.bouncycastle",
            "name": "bcprov-jdk18on",
            "provides": ["AES", "RSA"],
        },
    ]
)

HAND_WRITTEN_SYFT_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/cryptography@43.0.1",
            "name": "cryptography",
            "version": "43.0.1",
            "purl": "pkg:pypi/cryptography@43.0.1",
        },
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.32.3",
            "name": "requests",
            "version": "2.32.3",
            "purl": "pkg:pypi/requests@2.32.3",
        },
        {
            # syft also emits the manifest file itself as a component,
            # with no purl at all — must not crash or match anything.
            "type": "file",
            "bom-ref": "/target/requirements.txt",
            "name": "/target/requirements.txt",
        },
    ],
}


def _fake_sandbox_result(output: dict[str, object], *, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(
        exit_code=exit_code,
        output=json.dumps(output).encode(),
        stderr=b"",
        duration_seconds=1.0,
        timed_out=False,
    )


def test_supports_only_repository_targets() -> None:
    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    assert collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))
    assert not collector.supports(Target(type=TargetType.HOST, ref="x"))


def test_matched_package_produces_one_claim_per_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "qavach_collectors.sbom.syft.run_sandboxed",
        lambda config: _fake_sandbox_result(HAND_WRITTEN_SYFT_CDX),
    )
    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )

    assert not result.partial
    assert result.errors == []
    names = {c.name for c in result.claims}
    assert names == {"AES", "RSA", "SHA-256", "ECDSA"}
    assert all(c.detection_method == "dependency" for c in result.claims)
    assert all(c.confidence.name == "DEPENDENCY" for c in result.claims)
    assert all(c.locus.path == "pkg:pypi/cryptography@43.0.1" for c in result.claims)  # type: ignore[union-attr]


def test_unmapped_package_produces_no_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    """`requests` isn't in the fixture mapping — no claims, no error."""
    monkeypatch.setattr(
        "qavach_collectors.sbom.syft.run_sandboxed",
        lambda config: _fake_sandbox_result(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [HAND_WRITTEN_SYFT_CDX["components"][1]],  # requests only
            }
        ),
    )
    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert not result.partial
    assert result.claims == []


def test_non_package_components_are_skipped_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `file` component (the manifest itself, no purl) must not raise
    or be mistaken for a package."""
    monkeypatch.setattr(
        "qavach_collectors.sbom.syft.run_sandboxed",
        lambda config: _fake_sandbox_result(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [HAND_WRITTEN_SYFT_CDX["components"][2]],  # file only
            }
        ),
    )
    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert not result.partial
    assert result.claims == []


def test_a_failed_sandbox_run_is_reported_as_partial_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.sbom.syft.run_sandboxed",
        lambda config: SandboxResult(
            exit_code=1, output=b"", stderr=b"syft crashed", duration_seconds=0.5, timed_out=False
        ),
    )
    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert result.partial
    assert result.claims == []
    assert result.errors[0].fatal


def test_malformed_json_output_is_reported_as_partial_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.sbom.syft.run_sandboxed",
        lambda config: SandboxResult(
            exit_code=0, output=b"not json", stderr=b"", duration_seconds=0.5, timed_out=False
        ),
    )
    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="run-1")
    )
    assert result.partial
    assert "not valid JSON" in result.errors[0].message


def test_uses_the_pinned_digest() -> None:
    from qavach_collectors.sbom.syft import SYFT_IMAGE

    collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
    assert collector._image_ref == SYFT_IMAGE
    assert "@sha256:" in SYFT_IMAGE


# --- Real Docker integration test ---

_DOCKER_AVAILABLE = shutil.which("docker") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="no Docker on PATH")
def test_real_syft_run_detects_real_packages_and_maps_capabilities() -> None:
    """Proves the actual sandboxed syft invocation end to end: a real
    `requirements.txt` with `cryptography` and `pyjwt` pinned gets
    correctly catalogued by the real pinned syft binary, and the fixture
    mapping (standing in for T-034's real file) correctly attributes
    capabilities to the detected packages."""
    root = Path(__file__).parent.parent.parent
    repo_dir = root / "tests" / "collectors" / ".scratch-syft-repo"
    repo_dir.mkdir(exist_ok=True)
    (repo_dir / "requirements.txt").write_text("cryptography==43.0.1\npyjwt==2.9.0\n")
    try:
        collector = SyftCollector(crypto_libraries=FIXTURE_MAPPING)
        result = collector.collect(
            Target(type=TargetType.REPOSITORY, ref=str(repo_dir)),
            RunContext(scan_run_id="run-real"),
        )
        assert not result.partial, result.errors
        assert result.tool.exit_code == 0

        names = {c.name for c in result.claims}
        assert names == {"AES", "RSA", "SHA-256", "ECDSA", "HMAC"}
        paths = {c.locus.path for c in result.claims}  # type: ignore[union-attr]
        assert any("cryptography" in p for p in paths)
        assert any("pyjwt" in p for p in paths)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
