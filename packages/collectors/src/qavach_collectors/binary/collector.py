"""`binary.static` — shallow static inspection of compiled binaries. T-036b.

**Scope, stated honestly (it is also written into every result's
`coverage`).** This reads import tables, dependent-library lists, a handful of
well-known constant tables and a PE Authenticode chain. It does **no**
disassembly, symbolic execution or data-flow: a binary that resolves its
algorithm at run time (`EVP_get_cipherbyname(argv[1])`, CNG algorithm-id
strings) shows only the library it links. `PRD.md §6` calls deep binary
crypto detection a research problem and out of scope; this collector stays on
the evidence side of that line and says where it stops (`NOTE.md` OQ-16).

Confidence: imported symbol `ARTEFACT`, library capability `DEPENDENCY`,
constant table `PATTERN`, signing-chain public keys `ARTEFACT`.

Untrusted input: the walk never follows symlinks, and file count, per-file
size and symbol count are capped. Parsing containment is the caller's — see
`NOTE.md` OQ-16.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from qavach_core.model import ConfidenceTier, FileLocus

from qavach_collectors.base import (
    CollectorError,
    CollectorResult,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)
from qavach_collectors.binary.constants import find_constants
from qavach_collectors.binary.formats import PE, BinaryInfo, read_binary, sniff
from qavach_collectors.tls.chain import reconstruct_chains
from qavach_collectors.tls.pkcs7 import _to_discovered_certificate

MAX_FILES = 50_000
MAX_DEPTH = 16


@dataclass(frozen=True, slots=True)
class SymbolRule:
    pattern: re.Pattern[str]
    name: str
    primitive: str | None
    parameter_set: str | None
    mode: str | None


@dataclass(frozen=True, slots=True)
class LibraryRule:
    pattern: re.Pattern[str]
    provides: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BinaryKnowledge:
    symbols: tuple[SymbolRule, ...]
    libraries: tuple[LibraryRule, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BinaryKnowledge:
        return cls(
            symbols=tuple(
                SymbolRule(
                    re.compile(str(e["pattern"])),
                    str(e["name"]),
                    e.get("primitive"),
                    e.get("parameter_set"),
                    e.get("mode"),
                )
                for e in data["symbols"]
            ),
            libraries=tuple(
                LibraryRule(re.compile(str(e["pattern"]), re.IGNORECASE), tuple(e["provides"]))
                for e in data["libraries"]
            ),
        )


def _expand(template: str | None, match: re.Match[str]) -> str | None:
    if template is None:
        return None
    return re.sub(r"\{(\d)\}", lambda m: match.group(int(m.group(1))) or "", template) or None


def claims_for_binary(
    info: BinaryInfo, constants: list[Any], path: str, knowledge: BinaryKnowledge
) -> list[RawClaim]:
    claims: list[RawClaim] = []
    seen: set[tuple[object, ...]] = set()

    def add(claim: RawClaim) -> None:
        key = (claim.name, claim.primitive, claim.parameter_set, claim.mode, claim.confidence)
        if key not in seen:
            seen.add(key)
            claims.append(claim)

    locus = FileLocus(path=path, offset=0)
    for symbol in info.symbols:
        for rule in knowledge.symbols:
            match = rule.pattern.match(symbol)
            if match:
                add(
                    RawClaim(
                        locus=locus,
                        name=rule.name,
                        primitive=rule.primitive,
                        parameter_set=_expand(rule.parameter_set, match),
                        mode=_expand(rule.mode, match),
                        detection_method="artefact",
                        confidence=ConfidenceTier.ARTEFACT,
                    )
                )
                break
    for library in info.libraries:
        base = Path(library.replace("\\", "/")).name
        for library_rule in knowledge.libraries:
            if library_rule.pattern.match(base):
                for family in library_rule.provides:
                    add(
                        RawClaim(
                            locus=locus,
                            name=family,
                            detection_method="dependency",
                            confidence=ConfidenceTier.DEPENDENCY,
                        )
                    )
                break
    for hit in constants:
        add(
            RawClaim(
                locus=FileLocus(path=path, offset=hit.offset),
                name=hit.name,
                primitive=hit.primitive,
                parameter_set=hit.parameter_set,
                detection_method="pattern",
                confidence=ConfidenceTier.PATTERN,
            )
        )
    return claims


def signing_certificates(info: BinaryInfo, path: str) -> list[x509.Certificate]:
    if info.authenticode_der is None:
        return []
    try:
        return pkcs7.load_der_pkcs7_certificates(info.authenticode_der)
    except ValueError:
        return []


# QAVACH-OPEN: OQ-16 — execution mode / agent-collector membership undecided.
class BinaryCollector:
    name = "binary.static"
    version = "1.0.0"
    default_confidence = ConfidenceTier.ARTEFACT
    requires_sandbox = False
    requires_network = False

    def __init__(self, *, knowledge: BinaryKnowledge) -> None:
        self._knowledge = knowledge

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        root = Path(target.ref)
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=("binary.static", target.ref),
            exit_code=None,
            duration_seconds=0.0,
        )
        if not root.exists():
            return CollectorResult(
                raw=b"",
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=tool,
                errors=[CollectorError(message=f"{target.ref} does not exist", fatal=True)],
                partial=True,
            )

        claims: list[RawClaim] = []
        report: list[dict[str, Any]] = []
        notes: list[str] = []
        for path in self._candidates(root, notes):
            kind = sniff(path)
            if kind is None:
                continue
            info = read_binary(path, kind)
            constants, constants_note = find_constants(path)
            file_notes = list(info.notes) + ([constants_note] if constants_note else [])
            claims.extend(claims_for_binary(info, constants, str(path), self._knowledge))

            chain_report: list[dict[str, Any]] = []
            if kind == PE:
                certs = signing_certificates(info, str(path))
                discovered = [_to_discovered_certificate(c, path=str(path)) for c in certs]
                chain_report = [
                    {
                        "subjects": [c.subject for c in chain.certificates],
                        "complete": chain.is_complete,
                    }
                    for chain in reconstruct_chains(discovered)
                ]
                claims.extend(
                    RawClaim(
                        locus=FileLocus(path=str(path), offset=info.authenticode_offset),
                        name=d.public_key_algorithm and _CERT_NAME.get(d.public_key_algorithm),
                        primitive="signature",
                        parameter_set=d.public_key_curve
                        or (str(d.public_key_bits) if d.public_key_bits else None),
                        detection_method="artefact",
                        confidence=ConfidenceTier.ARTEFACT,
                    )
                    for d in discovered
                    if d.public_key_algorithm in _CERT_NAME
                )
            report.append(
                {
                    "path": str(path),
                    "format": kind,
                    "libraries": list(info.libraries),
                    "symbols_read": len(info.symbols),
                    "coverage": {
                        "imports": "full" if info.imports_complete else "partial-or-absent",
                        "constants": constants_note is None,
                        "signature": info.signature,
                        "disassembly": False,
                    },
                    "signing_chains": chain_report,
                    "notes": file_notes,
                }
            )
            notes.extend(
                f"{path}: {n}" for n in file_notes if "not parsed" in n or "could not" in n
            )

        raw = json.dumps({"binaries": report, "notes": notes}).encode()
        return CollectorResult(
            raw=raw,
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=tool,
            errors=[CollectorError(message=n, fatal=False) for n in notes],
            partial=bool(notes),
        )

    def _candidates(self, root: Path, notes: list[str]) -> Any:
        if root.is_file():
            yield root
            return
        seen = 0
        base_depth = len(root.parts)
        for directory, dirs, files in os.walk(root, followlinks=False):
            if len(Path(directory).parts) - base_depth >= MAX_DEPTH:
                dirs[:] = []
            for filename in files:
                seen += 1
                if seen > MAX_FILES:
                    notes.append(f"file cap of {MAX_FILES} reached; the scan is incomplete")
                    return
                path = Path(directory) / filename
                if not path.is_symlink():
                    yield path


_CERT_NAME = {"RSA": "RSA", "ECDSA": "ECDSA", "Ed25519": "EdDSA", "Ed448": "EdDSA", "DSA": "DSA"}
