"""T-036c — CBOMkit-theia `dir`, built from source and run agent-side inside
`tls.store`. Replays real recorded output, runs the real cross-compiled binary
when present, and proves theia's failure never costs the certfinder result."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.tls import TlsStoreCollector, store
from qavach_collectors.tls.store import _theia_claims
from qavach_collectors.tls.theia_dir import TheiaDirError, run_theia_dir
from qavach_core.model import ConfidenceTier
from qavach_core.normalize import AliasTable, CryptographyRegistry

ROOT = Path(__file__).parent.parent.parent
RECORDED = ROOT / "tests/fixtures/scanner-output/theia-dir/host.cdx.json"
BUILT = ROOT / "dist/theia/cbomkit-theia-linux-amd64"
REGISTRY = CryptographyRegistry.from_dict(
    json.loads((ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text())
)
ALIASES = AliasTable.from_dict(yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text()))


def _script(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake-theia"
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _collector(binary: Path | None, tmp_path: Path) -> TlsStoreCollector:
    return TlsStoreCollector(
        certfinder_binary=tmp_path / "certfinder-unused",
        theia_binary=binary,
        registry=REGISTRY,
        aliases=ALIASES,
    )


@pytest.fixture
def no_certfinder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "run_certfinder", lambda binary, directory: [])


def test_recorded_output_maps_with_absolute_paths_that_match_certfinder(tmp_path: Path) -> None:
    doc = json.loads(RECORDED.read_text())
    claims = _theia_claims(
        doc,
        Path("/host"),
        registry=REGISTRY,
        aliases=ALIASES,
        confidence=ConfidenceTier.ARTEFACT,
    )
    paths = {c.locus.path for c in claims}  # type: ignore[union-attr]
    assert paths == {"/host/etc/ssl/server.pem", "/host/etc/ssl/server.key"}
    assert any(c.name == "SHA-2" and c.parameter_set == "256" for c in claims)  # theia's "SHA256"
    assert all(c.confidence.name == "ARTEFACT" for c in claims)


def test_the_private_key_file_is_reported_at_its_own_locus(tmp_path: Path) -> None:
    doc = json.loads(RECORDED.read_text())
    claims = _theia_claims(
        doc,
        Path("/h"),
        registry=REGISTRY,
        aliases=ALIASES,
        confidence=ConfidenceTier.ARTEFACT,
    )
    assert any(c.locus.path.endswith("server.key") for c in claims)  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "body",
    ["exit 3", "echo 'not json'", "echo '[1,2]'", "sleep 0; exit 0", "kill -9 $$"],
)
def test_a_failing_theia_costs_nothing_but_a_note(
    tmp_path: Path, no_certfinder: None, body: str
) -> None:
    result = _collector(_script(tmp_path, body), tmp_path).collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="r")
    )
    assert result.partial and not result.errors[0].fatal
    assert result.errors[0].message.startswith("theia dir:")
    assert json.loads(result.raw)["theia"] is None


def test_oversized_output_is_refused_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qavach_collectors.tls import theia_dir

    monkeypatch.setattr(theia_dir, "MAX_OUTPUT_BYTES", 10)
    with pytest.raises(TheiaDirError, match="size cap"):
        run_theia_dir(_script(tmp_path, 'echo \'{"a": "aaaaaaaaaaaaaaaaaaaa"}\''), tmp_path)


def test_theia_gets_a_throwaway_home_and_no_stdin(tmp_path: Path) -> None:
    probe = _script(
        tmp_path,
        'printf \'{"home": "%s", "stdin": "%s"}\' "$HOME" "$(cat)"',
    )
    doc = run_theia_dir(probe, tmp_path)
    assert doc["stdin"] == ""
    assert not doc["home"].startswith(str(Path.home()))
    assert not Path(doc["home"]).exists()  # cleaned up


def test_without_a_theia_binary_it_is_the_certfinder_only_collector(
    tmp_path: Path, no_certfinder: None
) -> None:
    result = _collector(None, tmp_path).collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="r")
    )
    assert not result.partial and json.loads(result.raw) == {"certfinder": [], "theia": None}


@pytest.mark.skipif(
    not BUILT.exists() or shutil.which("openssl") is None,
    reason="run `make build-theia` (and have openssl) to exercise the real binary",
)
def test_real_cross_compiled_binary_finds_the_cert_and_the_private_key(
    tmp_path: Path, no_certfinder: None
) -> None:
    (tmp_path / "etc/ssl").mkdir(parents=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(tmp_path / "etc/ssl/server.key"),
            "-out",
            str(tmp_path / "etc/ssl/server.pem"),
            "-days",
            "30",
            "-subj",
            "/CN=fixture.local",
        ],
        check=True,
        capture_output=True,
    )
    result = _collector(BUILT, tmp_path).collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="r")
    )
    assert not result.partial, result.errors
    paths = {c.locus.path for c in result.claims}  # type: ignore[union-attr]
    assert str(tmp_path / "etc/ssl/server.key") in paths
    assert str(tmp_path / "etc/ssl/server.pem") in paths
    theia: dict[str, Any] = json.loads(result.raw)["theia"]
    assert theia["bomFormat"] == "CycloneDX"
    assert os.access(BUILT, os.X_OK)
