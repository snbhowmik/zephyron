"""Parsers for what a deployed Java artefact carries about itself.
T-036a.

Three sources, three very different confidence levels, kept separate on
purpose:

1. `META-INF/MANIFEST.MF` — the artefact's own declared identity.
2. `META-INF/maven/<g>/<a>/pom.properties` — exact Maven coordinates,
   which become a purl and can be looked up against T-034's curated
   `crypto_libraries.yaml` for the same capability evidence `sbom.syft`
   produces from a lockfile. This is the highest-value source here: it
   is exact, it is present in essentially every Maven-built jar, and it
   works on an estate where nobody holds the repository (`IDEATION.md
   §5.1`'s whole premise for this collector).
3. `.class` constant pools — which JCA types a class references and
   which algorithm-shaped string literals it carries.

(3) deliberately stops short of proving the string reaches the call.
Tying `"AES/CBC/PKCS5Padding"` to the specific `Cipher.getInstance` that
consumes it is constant propagation — an analysis engine, which
`CLAUDE.md §1` says to delegate rather than build. Reading a documented
binary format's constant pool is parsing. So this reports co-occurrence
("this class references `javax.crypto.Cipher` *and* contains this
algorithm string") at `PATTERN` confidence, never at the `AST` tier a
real dataflow analysis would earn. `SECURITY.md §9`'s "prefer
deterministic parsing over large regexes" applies throughout: every
parser here is `split`/`startswith`-based with explicit bounds.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# JCA engine classes whose presence in a constant pool means the class
# genuinely references that API — a fact about the bytecode, not an
# inference. Internal JVM form (slashes), as the constant pool stores it.
JCA_ENGINE_CLASSES = (
    "javax/crypto/Cipher",
    "javax/crypto/Mac",
    "javax/crypto/KeyGenerator",
    "javax/crypto/KeyAgreement",
    "javax/crypto/SecretKeyFactory",
    "java/security/MessageDigest",
    "java/security/Signature",
    "java/security/KeyPairGenerator",
    "java/security/KeyFactory",
    "java/security/SecureRandom",
    "java/security/KeyStore",
)

# Standard JCA algorithm-spec strings (the `getInstance` argument
# vocabulary from the JCA Standard Algorithm Names specification), matched
# as exact literals or as the algorithm part of a `alg/mode/padding`
# transformation. Not a regex pack: a fixed list, compared with `==` and
# `split("/")`, per SECURITY.md §9.
JCA_ALGORITHM_NAMES = (
    "AES",
    "AESWrap",
    "ARCFOUR",
    "Blowfish",
    "ChaCha20",
    "ChaCha20-Poly1305",
    "DES",
    "DESede",
    "RC2",
    "RC4",
    "RSA",
    "DSA",
    "EC",
    "ECDSA",
    "ECDH",
    "Ed25519",
    "Ed448",
    "DiffieHellman",
    "MD2",
    "MD5",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "HmacMD5",
    "HmacSHA1",
    "HmacSHA224",
    "HmacSHA256",
    "HmacSHA384",
    "HmacSHA512",
    "PBKDF2WithHmacSHA1",
    "PBKDF2WithHmacSHA256",
    "SHA1withRSA",
    "SHA256withRSA",
    "SHA384withRSA",
    "SHA512withRSA",
    "SHA256withECDSA",
    "SHA384withECDSA",
    "MD5withRSA",
)

_JCA_ALGORITHM_SET = frozenset(JCA_ALGORITHM_NAMES)


@dataclass(frozen=True, slots=True)
class MavenCoordinates:
    group_id: str
    artifact_id: str
    version: str

    @property
    def purl(self) -> str:
        return f"pkg:maven/{self.group_id}/{self.artifact_id}@{self.version}"


@dataclass(frozen=True, slots=True)
class ClassCryptoReferences:
    engine_classes: tuple[str, ...]
    algorithm_strings: tuple[str, ...]


def parse_manifest(data: bytes) -> dict[str, str]:
    """`MANIFEST.MF` is RFC 822-ish: `Key: value`, with continuation
    lines starting with a single space. Only the main section is read —
    per-entry sections (after the first blank line) describe individual
    files, not the artefact's identity."""
    attributes: dict[str, str] = {}
    last_key: str | None = None

    for raw_line in data.decode("utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            break  # end of the main section
        if raw_line.startswith(" ") and last_key is not None:
            attributes[last_key] += raw_line[1:].strip()
            continue
        key, separator, value = raw_line.partition(":")
        if not separator:
            continue
        last_key = key.strip()
        attributes[last_key] = value.strip()

    return attributes


def parse_pom_properties(data: bytes) -> MavenCoordinates | None:
    values: dict[str, str] = {}
    for raw_line in data.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()

    group_id = values.get("groupId")
    artifact_id = values.get("artifactId")
    version = values.get("version")
    if not group_id or not artifact_id or not version:
        return None
    return MavenCoordinates(group_id=group_id, artifact_id=artifact_id, version=version)


_CLASS_MAGIC = 0xCAFEBABE
_CONSTANT_UTF8 = 1
_CONSTANT_INTEGER = 3
_CONSTANT_FLOAT = 4
_CONSTANT_LONG = 5
_CONSTANT_DOUBLE = 6
_CONSTANT_CLASS = 7
_CONSTANT_STRING = 8
_CONSTANT_FIELDREF = 9
_CONSTANT_METHODREF = 10
_CONSTANT_INTERFACE_METHODREF = 11
_CONSTANT_NAME_AND_TYPE = 12
_CONSTANT_METHOD_HANDLE = 15
_CONSTANT_METHOD_TYPE = 16
_CONSTANT_DYNAMIC = 17
_CONSTANT_INVOKE_DYNAMIC = 18
_CONSTANT_MODULE = 19
_CONSTANT_PACKAGE = 20

# Fixed payload sizes, in bytes, for every non-UTF8 constant-pool tag
# (JVM specification §4.4). Anything not listed is an unknown tag and
# aborts parsing rather than guessing a stride and desynchronising.
_FIXED_SIZES = {
    _CONSTANT_INTEGER: 4,
    _CONSTANT_FLOAT: 4,
    _CONSTANT_LONG: 8,
    _CONSTANT_DOUBLE: 8,
    _CONSTANT_CLASS: 2,
    _CONSTANT_STRING: 2,
    _CONSTANT_FIELDREF: 4,
    _CONSTANT_METHODREF: 4,
    _CONSTANT_INTERFACE_METHODREF: 4,
    _CONSTANT_NAME_AND_TYPE: 4,
    _CONSTANT_METHOD_HANDLE: 3,
    _CONSTANT_METHOD_TYPE: 2,
    _CONSTANT_DYNAMIC: 4,
    _CONSTANT_INVOKE_DYNAMIC: 4,
    _CONSTANT_MODULE: 2,
    _CONSTANT_PACKAGE: 2,
}


def extract_class_utf8_constants(data: bytes) -> list[str]:
    """Reads a `.class` file's constant pool and returns every
    `CONSTANT_Utf8` value. Returns `[]` for anything that isn't a well-
    formed class file rather than raising — a deployed artefact routinely
    contains files that merely end in `.class` — and every read is
    bounds-checked, since this is hostile input by `SECURITY.md §9`'s
    definition."""
    if len(data) < 10 or struct.unpack_from(">I", data, 0)[0] != _CLASS_MAGIC:
        return []

    constant_pool_count = struct.unpack_from(">H", data, 8)[0]
    offset = 10
    constants: list[str] = []
    index = 1

    while index < constant_pool_count:
        if offset >= len(data):
            return constants
        tag = data[offset]
        offset += 1

        if tag == _CONSTANT_UTF8:
            if offset + 2 > len(data):
                return constants
            length = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            if offset + length > len(data):
                return constants
            constants.append(data[offset : offset + length].decode("utf-8", errors="replace"))
            offset += length
        else:
            size = _FIXED_SIZES.get(tag)
            if size is None:
                return constants  # unknown tag: stop rather than desynchronise
            offset += size

        # CONSTANT_Long and CONSTANT_Double occupy two pool slots each
        # (JVM specification §4.4.5) — the single most common way a
        # hand-written class parser silently desynchronises.
        index += 2 if tag in (_CONSTANT_LONG, _CONSTANT_DOUBLE) else 1

    return constants


def find_class_crypto_references(data: bytes) -> ClassCryptoReferences:
    constants = extract_class_utf8_constants(data)
    engine_classes = sorted({c for c in constants if c in JCA_ENGINE_CLASSES})
    algorithm_strings = sorted({c for c in constants if _is_jca_algorithm_spec(c)})
    return ClassCryptoReferences(
        engine_classes=tuple(engine_classes), algorithm_strings=tuple(algorithm_strings)
    )


def _is_jca_algorithm_spec(value: str) -> bool:
    """An exact JCA algorithm name, or an `alg/mode/padding`
    transformation whose algorithm part is one. Deterministic `split`,
    no regex (`SECURITY.md §9`)."""
    if value in _JCA_ALGORITHM_SET:
        return True
    parts = value.split("/")
    return len(parts) == 3 and parts[0] in _JCA_ALGORITHM_SET
