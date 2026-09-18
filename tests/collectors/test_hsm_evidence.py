"""T-041 — `hsm.evidence`: PKCS#11 boundary evidence from the filesystem,
including the never-retain-a-PIN rule and hostile-tree behaviour."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.hsm import (
    REDACTED,
    HsmEvidenceCollector,
    load_vendor_table,
    parse_text_evidence,
    scan_tree,
)
from qavach_collectors.hsm import evidence as evidence_mod

ROOT = Path(__file__).parent.parent.parent
VENDORS = load_vendor_table(
    yaml.safe_load((ROOT / "config/knowledge/hsm_vendors.yaml").read_text())
)


def _collect(path: Path):  # type: ignore[no-untyped-def]
    return HsmEvidenceCollector(vendors=VENDORS).collect(
        Target(type=TargetType.HOST, ref=str(path)), RunContext(scan_run_id="r")
    )


def test_supports_only_host_targets() -> None:
    c = HsmEvidenceCollector(vendors=VENDORS)
    assert c.supports(Target(type=TargetType.HOST, ref="/"))
    assert not c.supports(Target(type=TargetType.NETWORK_ENDPOINT, ref="h:1"))


def test_p11kit_module_names_the_vendor() -> None:
    found = parse_text_evidence(
        "/etc/pkcs11/modules/luna.module", "module: /opt/luna/libCryptoki2_64.so\n", VENDORS
    )
    assert [(e.kind, e.vendor, e.library_class) for e in found] == [
        ("p11kit_module", "Thales", "hardware")
    ]
    assert found[0].line == 1


def test_unknown_module_library_is_still_evidence_without_a_vendor() -> None:
    found = parse_text_evidence("/x/y.module", "module: /opt/acme/libacme.so\n", VENDORS)
    assert found[0].vendor is None and found[0].is_boundary


def test_system_trust_module_is_recorded_but_not_a_boundary(tmp_path: Path) -> None:
    (tmp_path / "trust.module").write_text("module: p11-kit-trust.so\npriority: 1\n")
    result = _collect(tmp_path)
    assert result.claims == []
    assert json.loads(result.raw)["evidence"][0]["library_class"] == "system_trust"


def test_real_host_p11kit_modules_if_present() -> None:
    directory = Path("/usr/share/p11-kit/modules")
    if not directory.is_dir():
        pytest.skip("no p11-kit modules on this host")
    result = _collect(directory)
    kinds = {e["kind"] for e in json.loads(result.raw)["evidence"]}
    assert "p11kit_module" in kinds
    # p11-kit-trust must never become a claim; every claim is nameless (I8).
    assert all(c.name is None for c in result.claims)


def test_sunpkcs11_config_and_provider_line() -> None:
    cfg = "name = LunaHSM\nlibrary = /usr/lib/libCryptoki2_64.so\nslot = 1\npin = 1234secret\n"
    found = parse_text_evidence("/opt/app/pkcs11.cfg", cfg, VENDORS)
    assert len(found) == 1 and found[0].kind == "sunpkcs11_config"
    assert found[0].vendor == "Thales"
    assert found[0].details["slot"] == "1"
    assert "1234secret" not in json.dumps([found[0].details, found[0].module_path])

    provider = parse_text_evidence(
        "/jvm/conf/security/java.security",
        "security.provider.3=SunPKCS11 /opt/app/pkcs11.cfg\n#security.provider.9=SunPKCS11 /no\n",
        VENDORS,
    )
    assert [(e.kind, e.details) for e in provider] == [
        ("sunpkcs11_provider", {"config": "/opt/app/pkcs11.cfg"})
    ]


def test_unrelated_yaml_with_library_key_is_not_sunpkcs11() -> None:
    assert parse_text_evidence("/a/b.yaml", "name: x\nlibrary: react\nslot: 2\n", VENDORS) == []


def test_openssl_pkcs11_module_path() -> None:
    found = parse_text_evidence(
        "/etc/ssl/openssl.cnf", "[pkcs11_section]\nMODULE_PATH = /usr/lib/libcknfast.so\n", VENDORS
    )
    assert [(e.kind, e.vendor) for e in found] == [("openssl_pkcs11", "Entrust")]


def test_pkcs11_uri_pin_is_redacted_everywhere(tmp_path: Path) -> None:
    (tmp_path / "app.properties").write_text(
        "key.uri=pkcs11:token=prod-signer;object=root-ca;type=private?pin-value=SuperSecret9\n"
        "other=pkcs11:token=t2?pin-source=file:/etc/pin\n"
    )
    result = _collect(tmp_path)
    blob = result.raw + repr(result.claims).encode() + repr(result.errors).encode()
    assert b"SuperSecret9" not in blob
    assert b"/etc/pin" not in blob
    details = [e["details"] for e in json.loads(result.raw)["evidence"]]
    assert details[0]["token"] == "prod-signer" and details[0]["pin-value"] == REDACTED
    assert details[1]["pin-source"] == REDACTED


def test_vendor_library_found_by_filename_and_claim_shape(tmp_path: Path) -> None:
    lib = tmp_path / "opt" / "nfast" / "libcknfast.so"
    lib.parent.mkdir(parents=True)
    lib.write_bytes(b"\x7fELF")
    result = _collect(tmp_path)
    assert not result.partial
    assert len(result.claims) == 1
    claim = result.claims[0]
    assert claim.name is None and claim.oid is None and claim.primitive is None
    assert claim.confidence.name == "HEURISTIC"
    assert claim.locus.path == str(lib)  # type: ignore[union-attr]


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "libsofthsm2.so").write_bytes(b"x")
    scan = tmp_path / "scan"
    scan.mkdir()
    os.symlink(outside, scan / "linked_dir")
    os.symlink(outside / "libsofthsm2.so", scan / "libsofthsm2.so")
    assert _collect(scan).claims == []


def test_oversized_text_file_is_skipped_with_a_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence_mod, "MAX_TEXT_BYTES", 10)
    (tmp_path / "big.cfg").write_text("library = /x/libsofthsm2.so\n" * 5)
    result = _collect(tmp_path)
    assert result.partial and not result.errors[0].fatal
    assert result.claims == []


def test_file_cap_marks_the_scan_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence_mod, "MAX_FILES", 3)
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("x")
    _, notes = scan_tree(tmp_path, VENDORS)
    assert any("cap" in n for n in notes)


def test_missing_target_degrades() -> None:
    result = _collect(Path("/nonexistent/qavach"))
    assert result.partial and result.errors[0].fatal


def test_single_file_target(tmp_path: Path) -> None:
    f = tmp_path / "sun.cfg"
    f.write_text("library = /lib/libsofthsm2.so\nslotListIndex = 0\n")
    result = _collect(f)
    assert len(result.claims) == 1
    assert json.loads(result.raw)["evidence"][0]["vendor"] == "OpenDNSSEC"


def test_binary_junk_in_a_text_named_file_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "x.cfg").write_bytes(os.urandom(4096))
    assert _collect(tmp_path).errors == []
