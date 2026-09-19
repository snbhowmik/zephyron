"""ARCH.md §2.2 `ssh.hostkey`, local-file half: `sshd_config`. T-042a.

**Runs exclusively via the deployed agent** (`ARCH.md §2.3`, §3a): it reads a
host's `sshd_config`, which is never mounted into a sandbox. `Target.type` is
`HOST`; `ref` is the config file (or a directory containing `sshd_config`).
It registers under the name `ssh.hostkey` — the agent's scan spec knows it by
that name, and the network probe (`ssh.hostkey` in `collector.py`) never runs
agent-side, so the two never share a registry.

**What a config states is not what a connection negotiated.** These are
algorithms the administrator *permits*, reported at `ARTEFACT` tier, the same
capability-not-usage reading as the network probe's offered list. The value of
reading the file as well as probing is that it shows *why* (a `+3des-cbc`
someone added on purpose) and works when the port is firewalled.

**sshd semantics that are easy to get wrong** (`sshd_config(5)`):

* The **first** value obtained for a keyword wins, not the last — and an
  `Include` is expanded at the point it appears, so an early drop-in overrides
  a later line in the main file.
* Keywords are case-insensitive; `Keyword value` and `Keyword=value` both work.
* Everything after the first `Match` is conditional (per user/host/address),
  so it is **not** the host's baseline: those lines are skipped and counted.
* An algorithm list may start with `+` (append to the built-in default), `-`
  (remove from it) or `^` (place first). The built-in default is not
  enumerated here, so `+x` reports `x` as explicitly enabled, and `-`/`^`
  are recorded as notes: the file changes the default in a way this collector
  cannot fully resolve, and says so rather than guessing.
* With no directive at all, OpenSSH's default applies. That is reported as a
  note, never as an empty (safe-looking) result.

**Credentials.** `HostKey` names a *private* key. This collector never opens
it: it reads the sibling `<path>.pub` only, and a test makes the private file
unreadable to prove it.

**Untrusted input.** File size, `Include` depth and count are capped; only the
agent's own filesystem view is read.
"""

from __future__ import annotations

import glob
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
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
from qavach_collectors.ssh.collector import (
    _CIPHER,
    _KEX,
    _MAC,
    algorithm_claims,
    host_key_claim,
)
from qavach_collectors.ssh.probe import HostKey

MAX_CONFIG_BYTES = 256 * 1024
MAX_INCLUDE_DEPTH = 5
MAX_INCLUDED_FILES = 200

_ALGORITHM_KEYWORDS = {
    "kexalgorithms": _KEX,
    "ciphers": _CIPHER,
    "macs": _MAC,
}
_HOST_KEY_ALGORITHMS = "hostkeyalgorithms"

Reader = Callable[[Path], str | None]
Globber = Callable[[str], list[str]]


@dataclass(frozen=True, slots=True)
class Directive:
    keyword: str
    modifier: str
    values: tuple[str, ...]
    path: str
    line: int


@dataclass(slots=True)
class SshdConfig:
    directives: dict[str, Directive] = field(default_factory=dict)
    host_key_files: list[tuple[str, int, str]] = field(default_factory=list)
    """`(config path, line, private-key path)`."""
    match_lines_skipped: int = 0
    notes: list[str] = field(default_factory=list)
    files_read: int = 0


def _default_reader(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None


def _default_globber(pattern: str) -> list[str]:
    return sorted(glob.glob(pattern))


def _split_keyword(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    for i, char in enumerate(stripped):
        if char in " \t=":
            keyword, rest = stripped[:i], stripped[i:].lstrip(" \t=")
            return keyword.lower(), rest.strip().strip('"')
    return stripped.lower(), ""


def parse_sshd_config(
    path: Path,
    *,
    read: Reader = _default_reader,
    expand: Globber = _default_globber,
) -> SshdConfig:
    """Parses `path` and everything it `Include`s. `read`/`expand` are
    injectable so the semantics are testable without a filesystem."""
    config = SshdConfig()
    state = {"in_match": False}

    def visit(file: Path, depth: int) -> None:
        if config.files_read >= MAX_INCLUDED_FILES:
            config.notes.append(f"include cap of {MAX_INCLUDED_FILES} files reached")
            return
        text = read(file)
        if text is None:
            config.notes.append(f"{file}: unreadable or larger than {MAX_CONFIG_BYTES} bytes")
            return
        config.files_read += 1
        for number, line in enumerate(text.splitlines(), start=1):
            split = _split_keyword(line)
            if split is None:
                continue
            keyword, value = split
            if keyword == "match":
                state["in_match"] = True
                continue
            if keyword == "include":
                if depth >= MAX_INCLUDE_DEPTH:
                    config.notes.append(f"{file}:{number}: include depth cap reached")
                    continue
                for pattern in value.split():
                    for included in expand(pattern):
                        visit(Path(included), depth + 1)
                continue
            if state["in_match"]:
                config.match_lines_skipped += 1
                continue
            if keyword == "hostkey":
                config.host_key_files.append((str(file), number, value))
                continue
            if keyword in _ALGORITHM_KEYWORDS or keyword == _HOST_KEY_ALGORITHMS:
                if keyword in config.directives:
                    continue  # sshd: the first obtained value wins
                modifier = value[:1] if value[:1] in "+-^" else ""
                names = tuple(n for n in value.removeprefix(modifier).split(",") if n)
                config.directives[keyword] = Directive(keyword, modifier, names, str(file), number)
            elif keyword == "requiredrsasize" and keyword not in config.directives:
                config.directives[keyword] = Directive(keyword, "", (value,), str(file), number)

    visit(path, 0)
    return config


def _read_public_key(pub_path: Path, read: Reader) -> HostKey | None:
    text = read(pub_path)
    if text is None:
        return None
    parts = text.split()
    if len(parts) < 2:
        return None
    try:
        key = load_ssh_public_key(f"{parts[0]} {parts[1]}".encode("ascii"))
    except (ValueError, UnicodeEncodeError, UnsupportedAlgorithm):
        return None
    if isinstance(key, rsa.RSAPublicKey):
        return HostKey(parts[0], "RSA", key.key_size, None)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return HostKey(parts[0], "ECDSA", key.key_size, key.curve.name)
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return HostKey(parts[0], "EdDSA", None, None)
    if isinstance(key, dsa.DSAPublicKey):
        return HostKey(parts[0], "DSA", key.key_size, None)
    return None


def claims_from_config(
    config: SshdConfig, *, read: Reader = _default_reader, confidence: ConfidenceTier
) -> list[RawClaim]:
    claims: list[RawClaim] = []
    for keyword, table in _ALGORITHM_KEYWORDS.items():
        directive = config.directives.get(keyword)
        if directive is None or directive.modifier in ("-", "^"):
            continue
        claims += algorithm_claims(
            table,
            directive.values,
            locus=FileLocus(path=directive.path, offset=directive.line),
            confidence=confidence,
            with_mode=table is _CIPHER,
        )
    for config_path, line, private in config.host_key_files:
        pub = Path(private + ".pub")
        key = _read_public_key(pub, read)
        if key is not None:
            claims.append(
                host_key_claim(key, locus=FileLocus(path=str(pub), offset=0), confidence=confidence)
            )
        else:
            config.notes.append(f"{config_path}:{line}: no readable public key beside {private}")
    return claims


def _notes_for(config: SshdConfig) -> list[str]:
    notes = list(config.notes)
    for keyword in (*_ALGORITHM_KEYWORDS, _HOST_KEY_ALGORITHMS):
        directive = config.directives.get(keyword)
        if directive is None:
            notes.append(
                f"{keyword}: not set — OpenSSH's built-in default applies (not enumerated)"
            )
        elif directive.modifier in ("-", "^"):
            notes.append(
                f"{keyword}: '{directive.modifier}' modifies the built-in default; "
                "the resulting set is not resolved here"
            )
        elif directive.modifier == "+":
            notes.append(
                f"{keyword}: '+' adds to the built-in default; only the additions are listed"
            )
    if config.match_lines_skipped:
        notes.append(
            f"{config.match_lines_skipped} directive line(s) inside Match blocks skipped "
            "(conditional, not the host baseline)"
        )
    return notes


class SshdConfigCollector:
    name = "ssh.hostkey"
    version = "1.0.0"
    default_confidence = ConfidenceTier.ARTEFACT
    requires_sandbox = False
    requires_network = False

    def __init__(self, *, read: Reader = _default_reader, expand: Globber = _default_globber):
        self._read = read
        self._expand = expand

    def supports(self, target: Target) -> bool:
        """The agent offers every spec path to every collector; this one only
        claims a file named `sshd_config` or a directory that holds one, so it
        does not emit a fatal error for every certificate directory scanned."""
        if target.type is not TargetType.HOST:
            return False
        path = Path(target.ref)
        return path.name == "sshd_config" or (path.is_dir() and (path / "sshd_config").is_file())

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        start = time.monotonic()
        path = Path(target.ref)
        if path.is_dir():
            path = path / "sshd_config"
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=("ssh.hostkey", str(path)),
            exit_code=None,
            duration_seconds=0.0,
        )
        if self._read(path) is None:
            return CollectorResult(
                raw=b"",
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[],
                tool=tool,
                errors=[CollectorError(message=f"{path} is unreadable or too large", fatal=True)],
                partial=True,
            )
        config = parse_sshd_config(path, read=self._read, expand=self._expand)
        claims = claims_from_config(config, read=self._read, confidence=self.default_confidence)
        notes = _notes_for(config)
        raw = json.dumps(
            {
                "files_read": config.files_read,
                "directives": {
                    k: {
                        "modifier": d.modifier,
                        "values": d.values,
                        "source": f"{d.path}:{d.line}",
                    }
                    for k, d in config.directives.items()
                },
                "host_key_files": [private for _, _, private in config.host_key_files],
                "notes": notes,
            }
        ).encode()
        return CollectorResult(
            raw=raw,
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=("ssh.hostkey", str(path)),
                exit_code=0,
                duration_seconds=time.monotonic() - start,
            ),
            errors=[],
            partial=False,
        )
