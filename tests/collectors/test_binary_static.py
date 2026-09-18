"""T-036b — `binary.static`: real ELF built with gcc against libcrypto, a
real PE and Mach-O from this host where present, synthesised ones for the
cases no host file covers, and hostile-input behaviour."""

from __future__ import annotations

import datetime
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.binary import (
    BinaryCollector,
    BinaryKnowledge,
    find_constants,
    formats,
    sniff,
)
from qavach_collectors.binary import collector as collector_mod
from qavach_collectors.binary.constants import aes_sbox, md5_t, sha256_k, sha512_k
from qavach_core.normalize import AliasTable, CryptographyRegistry, resolve_algorithm
from qavach_core.normalize.resolve import RawAlgorithmClaim, ResolvedAlgorithm

ROOT = Path(__file__).parent.parent.parent
KNOWLEDGE_DATA = yaml.safe_load((ROOT / "config/knowledge/binary_crypto.yaml").read_text())
KNOWLEDGE = BinaryKnowledge.from_dict(KNOWLEDGE_DATA)
HAVE_GCC = shutil.which("gcc") is not None and Path("/usr/include/openssl/evp.h").exists()

_SETUPTOOLS_EXE = next(
    iter(
        Path("/var/lib/flatpak/runtime").glob("**/setuptools/cli-64.exe")
        if Path("/var/lib/flatpak/runtime").exists()
        else []
    ),
    None,
)
_DYLIB = Path("/opt/zaproxy/.install4j/libi4jinst.dylib")


def _collect(path: Path):  # type: ignore[no-untyped-def]
    return BinaryCollector(knowledge=KNOWLEDGE).collect(
        Target(type=TargetType.HOST, ref=str(path)), RunContext(scan_run_id="r")
    )


def _c_array(name: str, values: tuple[int, ...], ctype: str) -> str:
    body = ",".join(f"{v}ULL" if "64" in ctype else f"{v}U" for v in values)
    return f"static const volatile {ctype} {name}[{len(values)}] = {{{body}}};\n"


@pytest.fixture(scope="module")
def real_elf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not HAVE_GCC:
        pytest.skip("no gcc/openssl headers")
    d = tmp_path_factory.mktemp("elf")
    src = d / "t.c"
    src.write_text(
        "#include <openssl/evp.h>\n#include <openssl/rsa.h>\n#include <openssl/md5.h>\n"
        + _c_array("k256", sha256_k(), "unsigned int")
        + _c_array("k512", sha512_k(), "unsigned long long")
        + "int main(void){ RSA *r = RSA_new(); "
        "const EVP_CIPHER *c = EVP_aes_256_gcm(); const EVP_MD *m = EVP_md5(); "
        "return (r==0)+(c==0)+(m==0)+k256[0]+k512[0]; }\n"
    )
    out = d / "t"
    subprocess.run(
        ["gcc", "-Wno-deprecated-declarations", "-o", str(out), str(src), "-lcrypto"], check=True
    )
    return out


def test_constants_are_the_published_values() -> None:
    assert aes_sbox()[:8].hex() == "637c777bf26b6fc5" and len(set(aes_sbox())) == 256
    assert (sha256_k()[0], sha256_k()[63]) == (0x428A2F98, 0xC67178F2)
    assert (sha512_k()[0], sha512_k()[79]) == (0x428A2F98D728AE22, 0x6C44198C4A475817)
    assert (md5_t()[0], md5_t()[63]) == (0xD76AA478, 0xEB86D391)


@pytest.mark.parametrize("big_endian", [False, True])
def test_constant_tables_found_in_either_byte_order(tmp_path: Path, big_endian: bool) -> None:
    fmt = (">" if big_endian else "<") + "I" * 8
    blob = b"\x00" * 100 + struct.pack(fmt, *sha256_k()[:8]) + b"\xff" * 50
    (tmp_path / "f.bin").write_bytes(blob)
    hits, note = find_constants(tmp_path / "f.bin")
    assert note is None
    assert [(h.name, h.parameter_set, h.offset) for h in hits] == [("SHA-2", "256", 100)]


def test_real_elf_imports_libs_and_constants(real_elf: Path) -> None:
    result = _collect(real_elf)
    assert not result.partial, result.errors
    by = {(c.name, c.parameter_set, c.mode, c.confidence.name) for c in result.claims}
    assert ("AES", "256", "gcm", "ARTEFACT") in by
    assert ("MD5", None, None, "ARTEFACT") in by
    assert ("RSA", None, None, "ARTEFACT") in by
    assert ("ECDSA", None, None, "DEPENDENCY") in by  # libcrypto capability
    assert ("SHA-2", "256", None, "PATTERN") in by
    assert ("SHA-2", "512", None, "PATTERN") in by
    report = json.loads(result.raw)["binaries"][0]
    assert report["format"] == "elf"
    assert any(lib.startswith("libcrypto") for lib in report["libraries"])
    assert report["coverage"]["disassembly"] is False
    assert report["coverage"]["signature"] == "not-applicable"


def test_real_elf_without_crypto_yields_no_claims(tmp_path: Path) -> None:
    if not HAVE_GCC:
        pytest.skip("no gcc")
    src = tmp_path / "p.c"
    src.write_text("int main(void){return 0;}\n")
    subprocess.run(["gcc", "-o", str(tmp_path / "p"), str(src)], check=True)
    assert _collect(tmp_path / "p").claims == []


def test_static_stripped_elf_reports_partial_import_coverage(tmp_path: Path) -> None:
    if not HAVE_GCC:
        pytest.skip("no gcc")
    src = tmp_path / "s.c"
    src.write_text("int main(void){return 0;}\n")
    r = subprocess.run(["gcc", "-static", "-o", str(tmp_path / "s"), str(src)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("no static libc")
    report = json.loads(_collect(tmp_path / "s").raw)["binaries"][0]
    assert report["coverage"]["imports"] == "partial-or-absent"


@pytest.mark.skipif(_SETUPTOOLS_EXE is None, reason="no real PE on this host")
def test_real_pe_imports_parse() -> None:
    assert _SETUPTOOLS_EXE is not None
    report = json.loads(_collect(_SETUPTOOLS_EXE).raw)["binaries"][0]
    assert report["format"] == "pe"
    assert "KERNEL32.dll" in report["libraries"]
    assert report["coverage"]["imports"] == "full"
    assert report["coverage"]["signature"] == "not-present"


def _signed_pe(tmp_path: Path) -> tuple[Path, str]:
    import pefile

    assert _SETUPTOOLS_EXE is not None
    now = datetime.datetime.now(datetime.UTC)

    def cert(subject: str, issuer: str, key, signer_key, ca: bool):  # type: ignore[no-untyped-def]
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(signer_key, hashes.SHA256())
        )

    ca_key = rsa.generate_private_key(65537, 2048)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = cert("Test Root CA", "Test Root CA", ca_key, ca_key, True)
    leaf = cert("Test Publisher", "Test Root CA", leaf_key, ca_key, False)
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"authenticode-placeholder")
        .add_signer(leaf, leaf_key, hashes.SHA256())
        .add_certificate(ca_cert)
        .sign(serialization.Encoding.DER, [])
    )
    data = _SETUPTOOLS_EXE.read_bytes()
    while len(data) % 8:
        data += b"\x00"
    offset = len(data)
    pe = pefile.PE(data=data)
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    length = 8 + len(der)
    padded = length + (-length) % 8
    entry.VirtualAddress, entry.Size = offset, padded
    patched = pe.write()
    pe.close()
    blob = struct.pack("<IHH", length, 0x0200, 0x0002) + der + b"\x00" * (padded - length)
    out = tmp_path / "signed.exe"
    out.write_bytes(bytes(patched) + blob)
    return out, "Test Publisher"


@pytest.mark.skipif(_SETUPTOOLS_EXE is None, reason="no real PE on this host")
def test_pe_authenticode_chain_is_reconstructed(tmp_path: Path) -> None:
    path, publisher = _signed_pe(tmp_path)
    result = _collect(path)
    report = json.loads(result.raw)["binaries"][0]
    assert report["coverage"]["signature"] == "parsed"
    chains = report["signing_chains"]
    assert len(chains) == 1 and chains[0]["complete"] is True
    assert chains[0]["subjects"][0] == f"CN={publisher}"
    sig = {(c.name, c.parameter_set) for c in result.claims if c.primitive == "signature"}
    assert ("ECDSA", "secp256r1") in sig and ("RSA", "2048") in sig


@pytest.mark.skipif(_SETUPTOOLS_EXE is None, reason="no real PE on this host")
def test_pe_certificate_table_pointing_outside_the_file_is_not_trusted(tmp_path: Path) -> None:
    import pefile

    assert _SETUPTOOLS_EXE is not None
    pe = pefile.PE(str(_SETUPTOOLS_EXE))
    e = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    e.VirtualAddress, e.Size = 0x7FFFFFF0, 0x1000
    out = tmp_path / "evil.exe"
    out.write_bytes(bytes(pe.write()))
    pe.close()
    result = _collect(out)
    assert json.loads(result.raw)["binaries"][0]["coverage"]["signature"] == "present-not-parsed"
    assert not [c for c in result.claims if c.primitive == "signature"]


def _macho_with_dylib(path: str) -> bytes:
    name = path.encode() + b"\x00"
    name += b"\x00" * (-(24 + len(name)) % 8)
    cmd = struct.pack("<IIIIII", 0xC, 24 + len(name), 24, 2, 0x10000, 0x10000) + name
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 6, 1, len(cmd), 0, 0)
    return header + cmd


def test_synthetic_macho_dependent_dylib_is_read(tmp_path: Path) -> None:
    f = tmp_path / "lib.dylib"
    f.write_bytes(_macho_with_dylib("/usr/local/lib/libcrypto.3.dylib"))
    result = _collect(f)
    report = json.loads(result.raw)["binaries"][0]
    assert report["format"] == "macho"
    assert "/usr/local/lib/libcrypto.3.dylib" in report["libraries"]
    assert any(c.name == "AES" and c.confidence.name == "DEPENDENCY" for c in result.claims)
    assert report["coverage"]["imports"] == "partial-or-absent"


@pytest.mark.skipif(not _DYLIB.exists(), reason="no real Mach-O on this host")
def test_real_universal_macho_parses() -> None:
    report = json.loads(_collect(_DYLIB).raw)["binaries"][0]
    assert report["format"] == "macho"
    assert any("libSystem" in lib for lib in report["libraries"])


def test_java_class_is_not_mistaken_for_a_fat_macho(tmp_path: Path) -> None:
    f = tmp_path / "A.class"
    f.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 32)
    assert sniff(f) is None


@pytest.mark.parametrize(
    "content",
    [
        b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9,
        b"MZ" + os.urandom(300),
        b"\xcf\xfa\xed\xfe" + b"\xff" * 40,
    ],
)
def test_malformed_binaries_degrade_without_raising(tmp_path: Path, content: bytes) -> None:
    (tmp_path / "bad").write_bytes(content)
    result = _collect(tmp_path)
    assert result.claims == []
    assert result.partial and not result.errors[0].fatal


def test_oversized_binary_is_not_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "f"
    f.write_bytes(_macho_with_dylib("/usr/lib/libcrypto.3.dylib"))
    monkeypatch.setattr(formats, "MAX_PARSE_BYTES", 10)
    result = _collect(f)
    assert result.claims == [] and result.partial


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "lib.dylib").write_bytes(_macho_with_dylib("/x/libcrypto.3.dylib"))
    scan = tmp_path / "scan"
    scan.mkdir()
    os.symlink(out / "lib.dylib", scan / "lib.dylib")
    os.symlink(out, scan / "dir")
    assert _collect(scan).claims == []


def test_file_cap_marks_scan_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector_mod, "MAX_FILES", 2)
    for i in range(5):
        (tmp_path / f"f{i}").write_bytes(b"x")
    result = _collect(tmp_path)
    assert result.partial and "cap" in result.errors[0].message


def test_missing_target_and_supports() -> None:
    assert _collect(Path("/nonexistent/qavach")).errors[0].fatal
    c = BinaryCollector(knowledge=KNOWLEDGE)
    assert c.supports(Target(type=TargetType.HOST, ref="/"))
    assert not c.supports(Target(type=TargetType.REPOSITORY, ref="/"))


def test_every_name_in_the_knowledge_table_resolves() -> None:
    registry = CryptographyRegistry.from_dict(
        json.loads(
            (ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text()
        )
    )
    aliases = AliasTable.from_dict(
        yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text())
    )
    names = {e["name"] for e in KNOWLEDGE_DATA["symbols"]}
    names |= {f for e in KNOWLEDGE_DATA["libraries"] for f in e["provides"]}
    names |= {"AES", "SHA-2", "MD5"}
    for name in sorted(names):
        resolved = resolve_algorithm(
            RawAlgorithmClaim(name=name, oid=None), registry=registry, aliases=aliases
        )
        assert isinstance(resolved, ResolvedAlgorithm), name
