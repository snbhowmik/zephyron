"""ARCH.md §2.2 `hsm.evidence` — PKCS#11 / HSM evidence from the filesystem.
T-041 / `PRD.md FR-150`.

**Runs exclusively via the deployed agent** (`ARCH.md §2.3`, §3a): it reads a
live host's configuration. `Target.type` is `HOST`, `target.ref` a directory
(or file) on the agent's host.

**What this reports, and what it does not.** Live slot enumeration needs
vendor credentials and a physical module and is out of scope (`PRD.md §6`).
This collector reports that an HSM/PKCS#11 *boundary* is present and points
at where — it never claims an algorithm, a key or a key size, because it
observed none. Every finding is emitted as a claim with **no algorithm
name**, which resolves downstream to `UNKNOWN` (invariant I8): the boundary
is a coverage gap to be closed by the operator, never a green tick.

Evidence kinds:

* `vendor_library` — a PKCS#11 client library on disk (`hsm_vendors.yaml`).
* `p11kit_module` — a p11-kit `*.module` file (`module: <path>`).
* `sunpkcs11_config` — a SunPKCS11 provider config (`library =`, `slot =`).
* `sunpkcs11_provider` — a `security.provider.N=SunPKCS11 …` line.
* `openssl_pkcs11` — `MODULE_PATH` / `pkcs11-module-path` in OpenSSL config.
* `pkcs11_uri` — an RFC 7512 `pkcs11:` URI in application config.

**Credentials (`SECURITY.md §6`).** A `pkcs11:` URI may carry `pin-value=`;
a SunPKCS11 or OpenSSL config may carry a PIN. Those values are redacted at
parse time, before the evidence object exists, so a PIN cannot reach the
raw payload, a claim, a log or the wire.

**Untrusted input (`SECURITY.md §9`).** The host's files are not trusted:
the walk never follows symlinks, caps file count/size/depth, and reads only
recognised text-config names.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

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

MAX_FILES = 20_000
MAX_DEPTH = 12
MAX_TEXT_BYTES = 1 * 1024 * 1024
_TEXT_SUFFIXES = (
    ".module",
    ".cfg",
    ".cnf",
    ".conf",
    ".properties",
    ".xml",
    ".yaml",
    ".yml",
    ".json",
    ".ini",
    ".security",
    ".env",
    ".toml",
)
_TEXT_NAMES = ("java.security", "openssl.cnf", "pkcs11.conf")
REDACTED = "<redacted>"

_URI_RE = re.compile(r"pkcs11:[A-Za-z0-9._~%!$&'()*+,;=:@/?-]+")
_PIN_ATTR_RE = re.compile(r"(pin-value|pin-source)=[^;&?\s\"']*", re.IGNORECASE)
_KV_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*[=:]\s*(.*?)\s*$")
_PROVIDER_RE = re.compile(r"^\s*security\.provider\.\d+\s*=\s*(SunPKCS11\b.*?)\s*$")
_PIN_KEYS = {"pin", "userpin", "user-pin", "pin-value", "so-pin", "sopin", "password"}
_SLOT_KEYS = {"slot", "slotlistindex", "name", "description", "attributes"}


@dataclass(frozen=True, slots=True)
class HsmEvidence:
    kind: str
    path: str
    line: int
    vendor: str | None = None
    product: str | None = None
    library_class: str | None = None
    module_path: str | None = None
    details: dict[str, str] = field(default_factory=dict)

    @property
    def is_boundary(self) -> bool:
        """`system_trust` modules (p11-kit-trust) expose the OS trust-anchor
        store, not an HSM — recorded, never reported as a crypto boundary."""
        return self.library_class != "system_trust"


@dataclass(frozen=True, slots=True)
class VendorLibrary:
    vendor: str
    product: str
    library_class: str


def load_vendor_table(data: dict[str, Any]) -> dict[str, VendorLibrary]:
    return {
        str(entry["file"]).lower(): VendorLibrary(
            vendor=str(entry["vendor"]),
            product=str(entry["product"]),
            library_class=str(entry["class"]),
        )
        for entry in data["libraries"]
    }


def redact_uri(uri: str) -> str:
    return _PIN_ATTR_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", uri)


def _uri_details(uri: str) -> dict[str, str]:
    body = uri.removeprefix("pkcs11:")
    details: dict[str, str] = {}
    for part in re.split(r"[;?&]", body):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key = key.lower()
        if key in ("pin-value", "pin-source"):
            details[key] = REDACTED
        elif key in (
            "token",
            "manufacturer",
            "library-manufacturer",
            "slot-id",
            "id",
            "library-description",
            "model",
            "serial",
        ):
            details[key] = value
    return details


def _vendor_for(module_path: str, vendors: dict[str, VendorLibrary]) -> VendorLibrary | None:
    return vendors.get(Path(module_path.replace("\\", "/")).name.lower())


def _is_text_candidate(name: str) -> bool:
    lowered = name.lower()
    return lowered in _TEXT_NAMES or lowered.endswith(_TEXT_SUFFIXES)


def parse_text_evidence(
    path: str, text: str, vendors: dict[str, VendorLibrary]
) -> list[HsmEvidence]:
    """Evidence from one text config file. Pure — no I/O."""
    found: list[HsmEvidence] = []
    name = Path(path).name.lower()
    lines = text.splitlines()

    sun_cfg_details: dict[str, str] = {}
    sun_cfg_library: tuple[int, str] | None = None

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # `x-*` attributes in a p11-kit .module file are p11-kit's own
        # directives, not slot references in application config.
        if not name.endswith(".module"):
            for uri in _URI_RE.findall(line):
                found.append(HsmEvidence("pkcs11_uri", path, number, details=_uri_details(uri)))

        provider = _PROVIDER_RE.match(line)
        if provider is not None:
            argument = provider.group(1).removeprefix("SunPKCS11").strip()
            found.append(
                HsmEvidence(
                    "sunpkcs11_provider",
                    path,
                    number,
                    details={"config": argument} if argument else {},
                )
            )
            continue

        kv = _KV_RE.match(line)
        if kv is None:
            continue
        key, value = kv.group(1), kv.group(2).strip().strip("\"'")
        lowered = key.lower()

        if name.endswith(".module") and lowered == "module" and value:
            vendor = _vendor_for(value, vendors)
            found.append(_library_evidence("p11kit_module", path, number, value, vendor))
        elif lowered in ("module_path", "pkcs11-module-path", "pkcs11_module_path") and value:
            vendor = _vendor_for(value, vendors)
            found.append(_library_evidence("openssl_pkcs11", path, number, value, vendor))
        elif lowered == "library" and value:
            sun_cfg_library = (number, value)
        elif lowered in _SLOT_KEYS:
            sun_cfg_details[lowered] = value
        elif lowered in _PIN_KEYS:
            pass  # never retained — see module docstring

    if sun_cfg_library is not None and _looks_like_sunpkcs11(
        name, sun_cfg_library[1], sun_cfg_details
    ):
        number, library = sun_cfg_library
        vendor = _vendor_for(library, vendors)
        evidence = _library_evidence("sunpkcs11_config", path, number, library, vendor)
        found.append(
            HsmEvidence(
                evidence.kind,
                evidence.path,
                evidence.line,
                evidence.vendor,
                evidence.product,
                evidence.library_class,
                evidence.module_path,
                details=sun_cfg_details,
            )
        )
    return found


def _looks_like_sunpkcs11(name: str, library: str, details: dict[str, str]) -> bool:
    """A generic `library:` key appears in unrelated YAML/JSON; require a
    shared-object value and either a `.cfg` file or a slot selector."""
    lowered = library.lower()
    is_shared_object = lowered.endswith((".so", ".dll", ".dylib")) or ".so." in lowered
    has_selector = "slot" in details or "slotlistindex" in details
    return is_shared_object and (name.endswith(".cfg") or has_selector)


def _library_evidence(
    kind: str, path: str, line: int, module_path: str, vendor: VendorLibrary | None
) -> HsmEvidence:
    return HsmEvidence(
        kind,
        path,
        line,
        vendor=vendor.vendor if vendor else None,
        product=vendor.product if vendor else None,
        library_class=vendor.library_class if vendor else None,
        module_path=module_path,
    )


def scan_tree(root: Path, vendors: dict[str, VendorLibrary]) -> tuple[list[HsmEvidence], list[str]]:
    """Walks `root` (never following symlinks) and returns evidence plus
    human-readable notes about anything skipped or capped."""
    evidence: list[HsmEvidence] = []
    notes: list[str] = []
    seen = 0

    if root.is_file():
        walk: list[tuple[str, list[str], list[str]]] = [(str(root.parent), [], [root.name])]
    else:
        walk = list(_bounded_walk(root))

    for directory, _dirs, files in walk:
        for filename in files:
            seen += 1
            if seen > MAX_FILES:
                notes.append(f"file cap of {MAX_FILES} reached; the scan is incomplete")
                return evidence, notes
            full = Path(directory) / filename
            if full.is_symlink():
                continue
            vendor = vendors.get(filename.lower())
            if vendor is not None:
                evidence.append(
                    HsmEvidence(
                        "vendor_library",
                        str(full),
                        0,
                        vendor.vendor,
                        vendor.product,
                        vendor.library_class,
                        str(full),
                    )
                )
            if _is_text_candidate(filename):
                try:
                    if full.stat().st_size > MAX_TEXT_BYTES:
                        notes.append(f"{full}: larger than {MAX_TEXT_BYTES} bytes, not read")
                        continue
                    text = full.read_bytes().decode("utf-8", errors="replace")
                except OSError as exc:
                    notes.append(f"{full}: unreadable ({exc.__class__.__name__})")
                    continue
                evidence.extend(parse_text_evidence(str(full), text, vendors))
    return evidence, notes


def _bounded_walk(root: Path) -> Any:
    base_depth = len(root.parts)
    for directory, dirs, files in os.walk(root, followlinks=False):
        if len(Path(directory).parts) - base_depth >= MAX_DEPTH:
            dirs[:] = []
        yield directory, dirs, files


class HsmEvidenceCollector:
    name = "hsm.evidence"
    version = "1.0.0"
    # ARCH.md §2.2 names an `EVIDENCE` tier the ConfidenceTier enum does not
    # have (QAVACH-OPEN: OQ-15). HEURISTIC is the lowest tier: nothing about
    # cryptography was observed, only that a module is present.
    default_confidence = ConfidenceTier.HEURISTIC
    requires_sandbox = False
    requires_network = False

    def __init__(self, *, vendors: dict[str, VendorLibrary]) -> None:
        self._vendors = vendors

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        root = Path(target.ref)
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=("hsm.evidence", target.ref),
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

        evidence, notes = scan_tree(root, self._vendors)
        claims = [
            RawClaim(
                locus=FileLocus(path=item.path, offset=item.line),
                name=None,
                detection_method="evidence",
                confidence=self.default_confidence,
            )
            for item in evidence
            if item.is_boundary
        ]
        raw = json.dumps({"evidence": [asdict(item) for item in evidence], "notes": notes}).encode()
        return CollectorResult(
            raw=raw,
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=tool,
            errors=[CollectorError(message=note, fatal=False) for note in notes],
            partial=bool(notes),
        )
