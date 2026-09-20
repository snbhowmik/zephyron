"""T-037 — `source_scan.opengrep`. Mapping is replayed from SARIF recorded
from the *real* tool (`tests/fixtures/scanner-output/opengrep/`); the
integration test runs the real QAVACH-built image under the sandbox."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.source_scan import (
    ImageNotBuiltError,
    OpengrepCollector,
    claims_from_sarif,
    load_rules,
)
from qavach_sandbox import SandboxResult

ROOT = Path(__file__).parent.parent.parent
RULES_DOC = yaml.safe_load((ROOT / "config/opengrep-rules/crypto.yaml").read_text())
RULES = load_rules(RULES_DOC)
RECORDED = ROOT / "tests/fixtures/scanner-output/opengrep/polyglot.sarif"
POLYGLOT = ROOT / "tests/fixtures/targets/polyglot"
FAKE_IMAGE = "sha256:" + "d" * 64

EXPECTED = {
    ("Hasher.cs", 5, "MD5"),
    ("Hasher.cs", 6, "RSA"),
    ("Hasher.cs", 7, "AES"),
    ("cipher.rb", 2, "AES"),
    ("keys.rs", 4, "RSA"),
    ("legacy.c", 6, "MD5"),
    ("legacy.c", 7, "SHA-1"),
    ("legacy.c", 8, "3DES"),
    ("legacy.c", 9, "AES"),
    ("legacy.c", 10, "RSA"),
    ("legacy.php", 2, "MD5"),
}


def _sarif() -> dict[str, Any]:
    return json.loads(RECORDED.read_text())  # type: ignore[no-any-return]


def test_rule_pack_stays_within_the_note_3_3_budget() -> None:
    # 14 breadth rules for languages the AST scanners miss, plus 2 JVM string-literal
    # rules added on evidence from a real scan (jasypt: the algorithm is a constant).
    assert 10 <= len(RULES) <= 16


def test_every_rule_has_algorithm_metadata_and_ascii_only_text() -> None:
    raw = (ROOT / "config/opengrep-rules/crypto.yaml").read_bytes()
    raw.decode("ascii")  # Opengrep reads rules with the process locale
    assert all(r.algorithm or r.name_regex for r in RULES.values())


def test_recorded_real_sarif_maps_to_pattern_claims() -> None:
    claims, errors = claims_from_sarif(_sarif(), RULES)
    assert errors == []
    got = {(c.locus.path, c.locus.offset, c.name) for c in claims}  # type: ignore[union-attr]
    assert got == EXPECTED
    assert {c.confidence.name for c in claims} == {"PATTERN"}
    assert {c.detection_method for c in claims} == {"pattern"}


def test_paths_are_relative_to_the_target_not_the_container_mount() -> None:
    claims, _ = claims_from_sarif(_sarif(), RULES)
    assert not any(c.locus.path.startswith("/") for c in claims)  # type: ignore[union-attr]


def test_a_finding_from_an_unknown_rule_is_reported_not_guessed() -> None:
    sarif = _sarif()
    sarif["runs"][0]["results"][0]["ruleId"] = "opt.qavach.rules.qavach.c.renamed-rule"
    claims, errors = claims_from_sarif(sarif, RULES)
    assert len(claims) == len(EXPECTED) - 1
    assert "renamed-rule" in errors[0].message and not errors[0].fatal


@pytest.mark.parametrize(
    "sarif",
    [
        {},
        {"runs": None},
        {"runs": [{"results": None}]},
        {"runs": [{"results": [{"ruleId": "qavach.c.openssl-md5"}]}]},
        {"runs": [{"results": [{"ruleId": "qavach.c.openssl-md5", "locations": [{}]}]}]},
    ],
)
def test_malformed_sarif_never_raises(sarif: dict[str, Any]) -> None:
    claims, _errors = claims_from_sarif(sarif, RULES)
    assert claims == []


def test_rule_without_algorithm_metadata_is_rejected() -> None:
    with pytest.raises(ValueError, match="qavach_algorithm"):
        load_rules({"rules": [{"id": "x", "metadata": {}}]})


def test_unconfigured_image_fails_loudly() -> None:
    with pytest.raises(ImageNotBuiltError, match="build-images"):
        OpengrepCollector(rules=RULES, image_ref=None)


def _run(monkeypatch: pytest.MonkeyPatch, result: SandboxResult) -> Any:
    monkeypatch.setattr(
        "qavach_collectors.source_scan.opengrep.run_sandboxed", lambda config: result
    )
    return OpengrepCollector(rules=RULES, image_ref=FAKE_IMAGE).collect(
        Target(type=TargetType.REPOSITORY, ref="/repo"), RunContext(scan_run_id="r")
    )


def test_collector_maps_sandbox_output(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(monkeypatch, SandboxResult(0, RECORDED.read_bytes(), b"", 1.0, False))
    assert not result.partial and len(result.claims) == len(EXPECTED)
    assert result.raw_format.value == "sarif"


@pytest.mark.parametrize(
    "sandbox_result",
    [
        SandboxResult(2, b"", b"boom", 1.0, False),
        SandboxResult(None, b"", b"", 900.0, True),
        SandboxResult(0, b"not json", b"", 1.0, False),
        SandboxResult(0, b"[1, 2]", b"", 1.0, False),
    ],
)
def test_failures_degrade_to_partial(
    monkeypatch: pytest.MonkeyPatch, sandbox_result: SandboxResult
) -> None:
    result = _run(monkeypatch, sandbox_result)
    assert result.partial and result.errors[0].fatal and result.claims == []


def _built_image_id() -> str | None:
    if shutil.which("docker") is None:
        return None
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "qavach/opengrep:dev"],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


@pytest.mark.integration
def test_real_image_finds_planted_crypto_in_five_languages_and_nothing_in_benign_code() -> None:
    image = _built_image_id()
    if image is None:
        pytest.skip("image not built — run `make build-images`")
    result = OpengrepCollector(rules=RULES, image_ref=image).collect(
        Target(type=TargetType.REPOSITORY, ref=str(POLYGLOT)), RunContext(scan_run_id="r")
    )
    assert not result.partial, result.errors
    got = {(c.locus.path, c.locus.offset, c.name) for c in result.claims}  # type: ignore[union-attr]
    # the JVM literal rules also (correctly) see the algorithm strings in Legacy.java
    assert got == EXPECTED | {
        ("src/main/java/Legacy.java", 6, "DES/ECB/PKCS5Padding"),
        ("src/main/java/Legacy.java", 7, "MD5"),
    }
    assert not any(p == "benign.c" for p, _, _ in got)


def test_a_literal_rule_takes_the_algorithm_name_from_the_matched_snippet() -> None:
    """Found scanning a real repository (jasypt): the algorithm is a string literal
    the AST scanners never see. The rule declares a regex; the claim's name is the
    literal as written, which the JCA grammar later splits into its algorithms."""
    from qavach_collectors.source_scan.opengrep import claims_from_sarif, load_rules

    rules = load_rules(
        {
            "rules": [
                {
                    "id": "qavach.jvm.lit",
                    "metadata": {"qavach_name_regex": '"(PBEWith\\w+)"'},
                }
            ]
        }
    )

    def result(snippet: str) -> dict:  # type: ignore[type-arg]
        return {
            "ruleId": "opt.qavach.rules.qavach.jvm.lit",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "/target/A.java"},
                        "region": {"startLine": 7, "snippet": {"text": snippet}},
                    }
                }
            ],
        }

    claims, errors = claims_from_sarif(
        {"runs": [{"results": [result('  x = "PBEWithMD5AndDES";'), result("no literal here")]}]},
        rules,
    )
    assert [c.name for c in claims] == ["PBEWithMD5AndDES"]
    assert claims[0].locus.offset == 7 and claims[0].confidence.name == "PATTERN"
    assert len(errors) == 1 and "no algorithm name" in errors[0].message  # reported, not dropped


def test_a_rule_needs_an_algorithm_or_a_name_regex_and_a_bad_regex_fails_at_load() -> None:
    import pytest
    from qavach_collectors.source_scan.opengrep import load_rules

    with pytest.raises(ValueError, match="qavach_algorithm"):
        load_rules({"rules": [{"id": "r", "metadata": {}}]})
    with pytest.raises(Exception):  # noqa: B017,PT011 - re.error
        load_rules({"rules": [{"id": "r", "metadata": {"qavach_name_regex": "("}}]})
