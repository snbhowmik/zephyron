"""Static readers for ELF, PE and Mach-O. T-036b.

Pure-Python parsers only (pyelftools, pefile, macholib): the input is a
hostile compiled binary, and a memory-safe parser turns a malformed header
into an exception rather than memory corruption. Third-party parsers can
still raise anything on crafted input, so every read is wrapped and a
failure becomes a note, never a crash (`SECURITY.md §9`). Files above
`MAX_PARSE_BYTES` are not parsed.

What each format yields — stated because the coverage report must not
imply more than was read:

* **ELF** — `DT_NEEDED` libraries and undefined dynamic symbols. A static or
  stripped binary has neither; `imports_complete` is then False.
* **PE** — import and delay-import DLLs and function names, plus the
  Authenticode certificate table.
* **Mach-O** — dependent dylibs only. macholib does not decode the symbol
  table, so symbols are not read (`imports_complete` is False). Code
  signatures are detected, not parsed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_PARSE_BYTES = 128 * 1024 * 1024
MAX_SYMBOLS = 50_000

ELF, PE, MACHO = "elf", "pe", "macho"

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
}
_FAT_MAGIC = b"\xca\xfe\xba\xbe"


@dataclass(frozen=True, slots=True)
class BinaryInfo:
    format: str
    libraries: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    imports_complete: bool = False
    signature: str = "not-present"
    """`not-present`, `parsed`, `present-not-parsed` or `not-applicable`."""
    authenticode_der: bytes | None = None
    authenticode_offset: int = 0
    notes: list[str] = field(default_factory=list)


def sniff(path: Path) -> str | None:
    """Format from magic bytes, or None. Reads four/eight bytes only."""
    try:
        with path.open("rb") as handle:
            head = handle.read(8)
    except OSError:
        return None
    if head[:4] == b"\x7fELF":
        return ELF
    if head[:2] == b"MZ":
        return PE
    if head[:4] in _MACHO_MAGICS:
        return MACHO
    if head[:4] == _FAT_MAGIC and len(head) == 8:
        # Java class files share this magic; their next u32 is the class
        # version (>= 45), a fat header's is the architecture count.
        (count,) = struct.unpack(">I", head[4:8])
        if 1 <= count < 45:
            return MACHO
    return None


def read_binary(path: Path, kind: str) -> BinaryInfo:
    try:
        if path.stat().st_size > MAX_PARSE_BYTES:
            return BinaryInfo(kind, notes=[f"larger than {MAX_PARSE_BYTES} bytes, not parsed"])
        if kind == ELF:
            return _read_elf(path)
        if kind == PE:
            return _read_pe(path)
        return _read_macho(path)
    except Exception as exc:  # noqa: BLE001 — third-party parsers on hostile input may raise anything
        return BinaryInfo(kind, notes=[f"could not parse as {kind}: {exc.__class__.__name__}"])


def _read_elf(path: Path) -> BinaryInfo:
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile

    libraries: list[str] = []
    symbols: list[str] = []
    notes: list[str] = []
    with path.open("rb") as handle:
        elf: Any = ELFFile(handle)
        dynamic: Any = elf.get_section_by_name(".dynamic")
        if isinstance(dynamic, DynamicSection):
            tags: list[Any] = list(dynamic.iter_tags())
            libraries = [str(tag.needed) for tag in tags if tag.entry.d_tag == "DT_NEEDED"]
        dynsym = elf.get_section_by_name(".dynsym")
        complete = dynsym is not None
        if dynsym is not None:
            for symbol in dynsym.iter_symbols():
                if symbol["st_shndx"] == "SHN_UNDEF" and symbol.name:
                    symbols.append(symbol.name)
                    if len(symbols) >= MAX_SYMBOLS:
                        notes.append(f"symbol cap of {MAX_SYMBOLS} reached")
                        complete = False
                        break
        else:
            notes.append("no dynamic symbol table (static or stripped): imports not visible")
    return BinaryInfo(
        ELF,
        tuple(libraries),
        tuple(symbols),
        imports_complete=complete,
        signature="not-applicable",
        notes=notes,
    )


def _read_pe(path: Path) -> BinaryInfo:
    import pefile

    libraries: list[str] = []
    symbols: list[str] = []
    notes: list[str] = []
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )
        for attribute in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in getattr(pe, attribute, []):
                libraries.append(entry.dll.decode("ascii", errors="replace"))
                for imported in entry.imports:
                    if imported.name and len(symbols) < MAX_SYMBOLS:
                        symbols.append(imported.name.decode("ascii", errors="replace"))
        der, offset, signature = _authenticode(pe, path, notes)
    finally:
        pe.close()
    return BinaryInfo(
        PE,
        tuple(libraries),
        tuple(symbols),
        imports_complete=True,
        signature=signature,
        authenticode_der=der,
        authenticode_offset=offset,
        notes=notes,
    )


_WIN_CERT_PKCS_SIGNED_DATA = 0x0002


def _authenticode(pe: object, path: Path, notes: list[str]) -> tuple[bytes | None, int, str]:
    """The PE certificate table (`IMAGE_DIRECTORY_ENTRY_SECURITY`): its
    `VirtualAddress` is a *file offset*, not an RVA. Each `WIN_CERTIFICATE`
    is `dwLength u32, wRevision u16, wCertificateType u16, bCertificate[]`."""
    import pefile

    assert isinstance(pe, pefile.PE)
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    offset, size = directory.VirtualAddress, directory.Size
    if offset == 0 or size == 0:
        return None, 0, "not-present"
    file_size = path.stat().st_size
    if size < 8 or offset + size > file_size:
        notes.append("certificate table points outside the file")
        return None, 0, "present-not-parsed"
    with path.open("rb") as handle:
        handle.seek(offset)
        header = handle.read(8)
        length, _revision, cert_type = struct.unpack("<IHH", header)
        if cert_type != _WIN_CERT_PKCS_SIGNED_DATA or not 8 < length <= size:
            notes.append("certificate table is not an Authenticode PKCS#7 blob")
            return None, 0, "present-not-parsed"
        return handle.read(length - 8), offset, "parsed"


def _read_macho(path: Path) -> BinaryInfo:
    from macholib import mach_o
    from macholib.MachO import MachO

    dependent = {
        mach_o.LC_LOAD_DYLIB,
        mach_o.LC_LOAD_WEAK_DYLIB,
        mach_o.LC_REEXPORT_DYLIB,
        mach_o.LC_LOAD_UPWARD_DYLIB,
    }
    libraries: list[str] = []
    signed = False
    macho = MachO(str(path))
    for header in macho.headers:
        for load_command, _command, data in header.commands:
            if load_command.cmd in dependent:
                name = data.decode("utf-8", errors="replace").rstrip("\x00")
                if name not in libraries:
                    libraries.append(name)
            elif load_command.cmd == 0x1D:  # LC_CODE_SIGNATURE
                signed = True
    return BinaryInfo(
        MACHO,
        tuple(libraries),
        (),
        imports_complete=False,
        signature="present-not-parsed" if signed else "not-present",
        notes=["Mach-O: dependent dylibs only; symbol table and code signature are not decoded"],
    )
