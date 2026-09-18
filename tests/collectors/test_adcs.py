"""T-045 — `ad.adcs`.

**What is and is not verified here.** No Active Directory exists in this
environment. The fixture below is *derived from Certipy's own source* at
the pinned commit (`certipy/commands/find.py`: the `properties_map`, the
`"[!] Vulnerabilities"` key, and the bare-string-when-empty behaviour) —
not recorded from a real run, and is named accordingly. What *is* run for
real: the pinned Certipy image, the sandbox, the stdin password path, and
the unreachable-DC failure path. Recording a real lab-domain run is T-024.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.ad import (
    AdcsCollector,
    AdcsCredential,
    findings_from_raw,
    parse_certipy_json,
)
from qavach_collectors.tls import NetworkPolicy
from qavach_sandbox import SandboxResult

SECRET = "Sup3r-S3cret-Pa55!"
ALLOW_ALL = NetworkPolicy.from_dict({"denied_cidrs": [], "denied_hostnames": []})
DENY_DEFAULT_PRIVATE = NetworkPolicy.from_dict(
    {"denied_cidrs": ["127.0.0.0/8"], "denied_hostnames": []}
)

# Shaped from certipy/commands/find.py (see module docstring): derived, not recorded.
SOURCE_DERIVED_OUTPUT = {
    "Certificate Authorities": {
        "0": {
            "CA Name": "corp-ca",
            "DNS Name": "ca01.lab.test",
            "Web Enrollment": "Enabled",
            "[!] Vulnerabilities": {
                "ESC8": "Web Enrollment is enabled and Request Disposition is set to Issue"
            },
        }
    },
    "Certificate Templates": {
        "0": {
            "Template Name": "VulnWebServer",
            "Enabled": True,
            "Client Authentication": True,
            "Enrollee Supplies Subject": True,
            "Minimum RSA Key Length": 1024,
            "[!] Vulnerabilities": {
                "ESC1": (
                    "'Domain Users' can enroll, enrollee supplies subject "
                    "and template allows client authentication"
                )
            },
        },
        "1": {"Template Name": "User", "Enabled": True, "Minimum RSA Key Length": 2048},
        "2": {"Template Name": "NoKeyInfo", "Enabled": False},
    },
}
EMPTY_OUTPUT = {
    "Certificate Authorities": "[!] Could not find any CAs",
    "Certificate Templates": "[!] Could not find any certificate templates",
}


def _collector(policy: NetworkPolicy = ALLOW_ALL) -> AdcsCollector:
    return AdcsCollector(
        image_ref="sha256:" + "d" * 64,
        credential=AdcsCredential(username="svc", password=SECRET),
        policy=policy,
        domain="lab.test",
    )


def _target() -> Target:
    return Target(type=TargetType.DIRECTORY_SERVICE, ref="localhost")


def test_parses_templates_and_esc_findings_from_both_templates_and_cas() -> None:
    templates, findings = parse_certipy_json(SOURCE_DERIVED_OUTPUT)
    assert {t.name: t.min_rsa_key_bits for t in templates} == {
        "VulnWebServer": 1024,
        "User": 2048,
        "NoKeyInfo": None,
    }
    assert {(f.kind, f.subject_kind, f.subject) for f in findings} == {
        ("ESC1", "template", "VulnWebServer"),
        ("ESC8", "ca", "corp-ca"),
    }


def test_empty_sections_arrive_as_bare_strings_and_must_not_crash() -> None:
    """Certipy emits a *string* (not an empty mapping) when it finds
    nothing — a naive `.values()` would raise `AttributeError`."""
    templates, findings = parse_certipy_json(EMPTY_OUTPUT)
    assert templates == [] and findings == []


def test_findings_are_recoverable_from_the_retained_raw_payload() -> None:
    raw = json.dumps(SOURCE_DERIVED_OUTPUT).encode()
    assert {f.kind for f in findings_from_raw(raw)} == {"ESC1", "ESC8"}


def test_credential_is_hidden_from_repr() -> None:
    assert SECRET not in repr(AdcsCredential(username="svc", password=SECRET))


def test_supports_only_directory_service_targets() -> None:
    assert _collector().supports(_target())
    assert not _collector().supports(Target(type=TargetType.REPOSITORY, ref="x"))


def test_template_key_lengths_become_attested_claims_with_distinct_loci(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "qavach_collectors.ad.adcs.run_sandboxed",
        lambda config: SandboxResult(
            0, json.dumps(SOURCE_DERIVED_OUTPUT).encode(), b"", 1.0, False
        ),
    )
    result = _collector().collect(_target(), RunContext(scan_run_id="r"))

    assert not result.partial
    assert sorted(c.parameter_set for c in result.claims) == ["1024", "2048"]
    assert all(c.name == "RSA" and c.confidence.name == "ATTESTED" for c in result.claims)
    # Distinct loci, or reconciliation would read the two sizes as a dispute.
    assert len({c.locus.resource_arn for c in result.claims}) == 2  # type: ignore[union-attr]


def test_the_password_appears_in_no_argv_and_no_recorded_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECURITY.md §6, checked at every place it could leak: the
    docker argv, the config repr, and the ToolIdentity kept for audit."""
    from qavach_sandbox import build_sandbox_args

    seen = {}

    def _capture(config):  # type: ignore[no-untyped-def]
        seen["config"] = config
        return SandboxResult(0, json.dumps(EMPTY_OUTPUT).encode(), b"", 1.0, False)

    monkeypatch.setattr("qavach_collectors.ad.adcs.run_sandboxed", _capture)
    result = _collector().collect(_target(), RunContext(scan_run_id="r"))

    config = seen["config"]
    assert SECRET in config.secret_env.values(), "the secret must still reach the container"
    assert not any(SECRET in arg for arg in build_sandbox_args(config, container_name="x"))
    assert SECRET not in repr(config)
    assert not any(SECRET in part for part in result.tool.invocation)
    assert SECRET not in repr(result)


def test_the_dc_address_is_pinned_into_the_command_not_the_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = {}

    def _capture(config):  # type: ignore[no-untyped-def]
        seen["script"] = config.command[-1]
        return SandboxResult(0, json.dumps(EMPTY_OUTPUT).encode(), b"", 1.0, False)

    monkeypatch.setattr("qavach_collectors.ad.adcs.run_sandboxed", _capture)
    _collector().collect(_target(), RunContext(scan_run_id="r"))
    assert "-dc-ip 127.0.0.1" in seen["script"] or "-dc-ip ::1" in seen["script"]
    assert "localhost" not in seen["script"]


def test_ssrf_denied_dc_never_reaches_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(
        "qavach_collectors.ad.adcs.run_sandboxed", lambda config: called.append(config)
    )
    result = _collector(DENY_DEFAULT_PRIVATE).collect(_target(), RunContext(scan_run_id="r"))
    assert result.partial and called == []


def test_a_failed_run_is_partial_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "qavach_collectors.ad.adcs.run_sandboxed",
        lambda config: SandboxResult(1, b"", b"boom", 0.1, False),
    )
    result = _collector().collect(_target(), RunContext(scan_run_id="r"))
    assert result.partial and result.errors[0].fatal


def test_unparseable_output_is_partial_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "qavach_collectors.ad.adcs.run_sandboxed",
        lambda config: SandboxResult(0, b"not json", b"", 0.1, False),
    )
    assert _collector().collect(_target(), RunContext(scan_run_id="r")).partial


def _certipy_image() -> str | None:
    if shutil.which("docker") is None:
        return None
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "qavach/certipy:dev"],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


@pytest.mark.integration
def test_real_certipy_image_against_an_unreachable_dc_degrades_and_leaks_nothing() -> None:
    """The real pinned Certipy, in the real sandbox, driven through the
    real stdin-password path, against a DC that does not exist. It must
    consume the piped password (not hang on a prompt), fail to connect,
    and come back as a clean `partial=True` with the credential nowhere."""
    image = _certipy_image()
    if image is None:
        pytest.skip("image not built — run `make build-images`")

    collector = AdcsCollector(
        image_ref=image,
        credential=AdcsCredential(username="svc", password=SECRET),
        policy=ALLOW_ALL,
        domain="lab.test",
    )
    result = collector.collect(
        Target(type=TargetType.DIRECTORY_SERVICE, ref="192.0.2.1"),  # RFC 5737 TEST-NET-1
        RunContext(scan_run_id="r"),
    )

    assert result.partial
    assert result.errors and result.errors[0].fatal
    assert SECRET not in repr(result)
    assert SECRET not in result.errors[0].message
    assert SECRET not in result.raw.decode(errors="replace")
