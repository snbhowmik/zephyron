"""T-042a — `sshd_config` (agent-side half of `ssh.hostkey`): sshd's real
semantics (first value wins, Include order, Match blocks, list modifiers),
a real distribution crypto-policy file, and the never-open-the-private-key rule."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.ssh import SshdConfigCollector, parse_sshd_config

ROOT = Path(__file__).parent.parent.parent
FEDORA = ROOT / "tests/fixtures/sshd/opensshserver-fedora-DEFAULT.conf"


def _collect(path: Path, **kwargs):  # type: ignore[no-untyped-def]
    return SshdConfigCollector(**kwargs).collect(
        Target(type=TargetType.HOST, ref=str(path)), RunContext(scan_run_id="r")
    )


def _names(result) -> set[tuple[str, str | None, str | None]]:  # type: ignore[no-untyped-def]
    return {(c.name, c.parameter_set, c.mode) for c in result.claims}


def test_supports_only_host_targets() -> None:
    c = SshdConfigCollector()
    assert c.supports(Target(type=TargetType.HOST, ref="/etc/ssh/sshd_config"))
    assert not c.supports(Target(type=TargetType.NETWORK_ENDPOINT, ref="h:22"))
    assert not c.supports(Target(type=TargetType.HOST, ref="/etc/ssl/certs"))


def test_real_fedora_crypto_policy_file() -> None:
    """A genuine distribution file (Fedora's DEFAULT crypto policy, copied
    from /usr/share/crypto-policies)."""
    result = _collect(FEDORA)
    assert not result.partial, result.errors
    names = _names(result)
    assert ("ML-KEM", "768", None) in names  # mlkem768x25519-sha256 offered
    assert ("ECDH", "x25519", None) in names
    assert ("FFDH", "2048", None) in names  # diffie-hellman-group14-sha256
    assert ("AES", "256", "gcm") in names and ("ChaCha20", "256", None) in names
    assert ("HMAC", "SHA-1", None) in names  # hmac-sha1 is in the real default policy
    assert not any(c.name in ("3DES", "RC4", "DES") for c in result.claims)
    assert all(c.confidence.name == "ARTEFACT" for c in result.claims)
    raw = json.loads(result.raw)
    assert raw["directives"]["kexalgorithms"]["source"].endswith(":4")


def test_first_value_wins_across_an_include_that_appears_first(tmp_path: Path) -> None:
    (tmp_path / "dropin.conf").write_text("Ciphers aes256-ctr\n")
    main = tmp_path / "sshd_config"
    main.write_text(f"Include {tmp_path}/*.conf\nCiphers 3des-cbc\n")
    config = parse_sshd_config(main)
    assert config.directives["ciphers"].values == ("aes256-ctr",)
    assert config.directives["ciphers"].path.endswith("dropin.conf")


def test_a_directive_before_the_include_beats_it(tmp_path: Path) -> None:
    (tmp_path / "dropin.conf").write_text("Ciphers aes256-ctr\n")
    main = tmp_path / "sshd_config"
    main.write_text(f"Ciphers 3des-cbc\nInclude {tmp_path}/*.conf\n")
    assert parse_sshd_config(main).directives["ciphers"].values == ("3des-cbc",)


def test_keywords_are_case_insensitive_and_accept_equals(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text('cIpHeRs = "aes128-ctr,aes256-ctr"\nMACS hmac-sha2-256\n')
    config = parse_sshd_config(f)
    assert config.directives["ciphers"].values == ("aes128-ctr", "aes256-ctr")
    assert config.directives["macs"].values == ("hmac-sha2-256",)


def test_match_blocks_are_not_the_baseline(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text("Ciphers aes256-ctr\nMatch User backup\n  MACs hmac-md5\n  Ciphers 3des-cbc\n")
    result = _collect(f)
    assert "3DES" not in {c.name for c in result.claims}
    assert not any(c.name == "HMAC" and c.parameter_set == "MD5" for c in result.claims)
    assert any("Match blocks skipped" in n for n in json.loads(result.raw)["notes"])


def test_plus_modifier_reports_the_deliberate_addition(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text("Ciphers +3des-cbc\nKexAlgorithms -diffie-hellman-group1-sha1\n")
    result = _collect(f)
    assert ("3DES", None, "cbc") in _names(result)  # someone re-enabled it on purpose
    notes = json.loads(result.raw)["notes"]
    assert any("adds to the built-in default" in n for n in notes)
    assert any("modifies the built-in default" in n for n in notes)
    assert not any(c.name == "FFDH" for c in result.claims)  # '-' is not an enablement


def test_absent_directives_are_stated_not_left_looking_safe(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text("PermitRootLogin no\n")
    result = _collect(f)
    assert result.claims == []
    notes = " ".join(json.loads(result.raw)["notes"])
    assert "kexalgorithms: not set" in notes and "built-in default applies" in notes


def test_unmapped_algorithm_surfaces_under_its_own_name(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text("KexAlgorithms sntrup761x25519-sha512,curve25519-sha256\n")
    names = {c.name for c in _collect(f).claims}
    assert "sntrup761x25519-sha512" in names  # I8: unmapped -> UNKNOWN downstream


@pytest.mark.skipif(
    subprocess.run(["which", "ssh-keygen"], capture_output=True).returncode != 0,
    reason="no ssh-keygen",
)
def test_host_key_is_read_from_the_public_file_never_the_private_one(tmp_path: Path) -> None:
    key = tmp_path / "ssh_host_rsa_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-f", str(key)], check=True
    )
    private_text = key.read_text()
    key.chmod(0)  # any attempt to open the private key raises PermissionError
    config = tmp_path / "sshd_config"
    config.write_text(f"HostKey {key}\n")
    try:
        result = _collect(config)
    finally:
        key.chmod(0o600)
    assert not result.partial, result.errors
    assert [(c.name, c.parameter_set) for c in result.claims] == [("RSA", "3072")]
    assert result.claims[0].locus.path.endswith(".pub")  # type: ignore[union-attr]
    assert private_text.splitlines()[1] not in result.raw.decode()


def test_missing_public_key_is_noted(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text(f"HostKey {tmp_path}/absent_key\n")
    result = _collect(f)
    assert result.claims == []
    assert any("no readable public key" in n for n in json.loads(result.raw)["notes"])


def test_include_depth_is_capped(tmp_path: Path) -> None:
    loop = tmp_path / "sshd_config"
    loop.write_text(f"Include {loop}\nCiphers aes256-ctr\n")
    config = parse_sshd_config(loop)
    assert any("depth cap" in n for n in config.notes)
    assert config.directives["ciphers"].values == ("aes256-ctr",)


def test_oversized_config_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qavach_collectors.ssh import sshd_config as mod

    monkeypatch.setattr(mod, "MAX_CONFIG_BYTES", 8)
    f = tmp_path / "sshd_config"
    f.write_text("Ciphers aes256-ctr\n" * 10)
    result = _collect(f)
    assert result.partial and result.errors[0].fatal


def test_directory_target_and_missing_file(tmp_path: Path) -> None:
    (tmp_path / "sshd_config").write_text("Ciphers aes256-ctr\n")
    assert _collect(tmp_path).claims
    assert _collect(tmp_path / "nope").partial


def test_binary_junk_does_not_crash(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_bytes(os.urandom(2048))
    assert _collect(f).errors == []
