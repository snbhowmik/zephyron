"""T-031a — the CLI entrypoint (`__main__.py`) and `AgentCredential`'s JSON
round-trip, which the `enroll`/`run` subcommands rely on to hand a
credential from one process invocation to the next."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from _mock_backend import run_mock_backend
from _pki import make_test_ca
from qavach_agent import AgentCredential
from qavach_agent.__main__ import _cmd_enroll, build_parser


def test_credential_json_round_trips() -> None:
    original = AgentCredential(
        agent_id="agent-42",
        private_key_pem=b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        client_cert_pem=b"-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----\n",
        ca_bundle_pem=b"-----BEGIN CERTIFICATE-----\nghi\n-----END CERTIFICATE-----\n",
    )
    round_tripped = AgentCredential.from_json_dict(original.to_json_dict())
    assert round_tripped == original


def test_parser_requires_a_subcommand() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_enroll_subcommand_parses_all_required_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "enroll",
            "--backend-url",
            "https://backend.example",
            "--token",
            "tok-1",
            "--ca-bundle",
            "/path/ca.pem",
            "--credential-out",
            "/path/cred.json",
        ]
    )
    assert args.func is _cmd_enroll
    assert args.backend_url == "https://backend.example"
    assert args.token == "tok-1"


def test_run_subcommand_defaults_poll_interval_to_30s() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["run", "--backend-url", "https://backend.example", "--credential", "/path/cred.json"]
    )
    assert args.poll_interval == 30.0


def test_enroll_writes_credential_with_owner_only_permissions(tmp_path: Path) -> None:
    ca = make_test_ca()
    with run_mock_backend(tmp_path=tmp_path, ca=ca, expected_enrollment_token="tok-cli") as (
        backend_url,
        _state,
    ):
        ca_path = tmp_path / "ca.crt"
        ca_path.write_bytes(ca.cert_pem)
        credential_out = tmp_path / "credential.json"

        parser = build_parser()
        args = parser.parse_args(
            [
                "enroll",
                "--backend-url",
                backend_url,
                "--token",
                "tok-cli",
                "--ca-bundle",
                str(ca_path),
                "--credential-out",
                str(credential_out),
            ]
        )
        exit_code = args.func(args)

        assert exit_code == 0
        assert credential_out.exists()
        mode = stat.S_IMODE(credential_out.stat().st_mode)
        assert mode == 0o600

        restored = AgentCredential.from_json_dict(json.loads(credential_out.read_text()))
        assert restored.agent_id == "agent-1"
