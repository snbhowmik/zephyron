"""T-036a — `artefact/parse.py`. The class-constant tests run against a
class compiled by the real `javac`, not a hand-crafted byte blob: the
parts of a constant-pool parser most likely to be wrong (the
`CONSTANT_Long`/`CONSTANT_Double` two-slot rule, the real tag mix a
compiler emits) only appear in genuine compiler output."""

from __future__ import annotations

import pytest
from _java_fixture import (
    BOUNCYCASTLE_POM_PROPERTIES,
    CRYPTO_DEMO_SOURCE,
    JAVAC_AVAILABLE,
    MANIFEST,
    NO_CRYPTO_SOURCE,
    compile_class,
)
from qavach_collectors.artefact import (
    extract_class_utf8_constants,
    find_class_crypto_references,
    parse_manifest,
    parse_pom_properties,
)


def test_parses_a_real_manifest() -> None:
    attributes = parse_manifest(MANIFEST)
    assert attributes["Manifest-Version"] == "1.0"
    assert attributes["Implementation-Title"] == "payments-service"
    assert attributes["Implementation-Version"] == "4.2.1"


def test_manifest_continuation_lines_are_joined() -> None:
    """`MANIFEST.MF` wraps at 72 bytes with a leading-space continuation
    — a long Class-Path is the usual real-world case, and a parser that
    misses this silently truncates it."""
    manifest = (
        b"Manifest-Version: 1.0\r\n"
        b"Class-Path: lib/first-library-with-a-long-name.jar\r\n"
        b" lib/second-library.jar\r\n"
        b"\r\n"
    )
    attributes = parse_manifest(manifest)
    assert attributes["Class-Path"] == (
        "lib/first-library-with-a-long-name.jarlib/second-library.jar"
    )


def test_manifest_stops_at_the_per_entry_sections() -> None:
    """Everything after the first blank line describes individual files,
    not the artefact — including those would attribute a file's `Name:`
    to the artefact itself."""
    manifest = (
        b"Manifest-Version: 1.0\r\n"
        b"Main-Class: com.example.App\r\n"
        b"\r\n"
        b"Name: a/b.class\r\n"
        b"SHA-256-Digest: xyz\r\n"
    )
    attributes = parse_manifest(manifest)
    assert attributes == {"Manifest-Version": "1.0", "Main-Class": "com.example.App"}


def test_parses_pom_properties_into_coordinates_and_a_purl() -> None:
    coordinates = parse_pom_properties(BOUNCYCASTLE_POM_PROPERTIES)
    assert coordinates is not None
    assert coordinates.group_id == "org.bouncycastle"
    assert coordinates.artifact_id == "bcprov-jdk18on"
    assert coordinates.version == "1.78"
    assert coordinates.purl == "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"


def test_incomplete_pom_properties_yields_none() -> None:
    assert parse_pom_properties(b"groupId=org.example\n") is None


def test_non_class_data_yields_no_constants() -> None:
    assert extract_class_utf8_constants(b"not a class file") == []
    assert extract_class_utf8_constants(b"") == []


def test_truncated_class_file_does_not_raise() -> None:
    """Hostile input (`SECURITY.md §9`): a truncated class must return
    what was parsed so far, never crash the collector."""
    truncated = b"\xca\xfe\xba\xbe\x00\x00\x00\x41\x00\x20"  # header claims 32 entries, none follow
    assert extract_class_utf8_constants(truncated) == []


# --- Against a genuinely compiled class ---

pytestmark_javac = pytest.mark.skipif(not JAVAC_AVAILABLE, reason="no javac on PATH")


@pytest.fixture(scope="module")
def crypto_class_bytes(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    if not JAVAC_AVAILABLE:
        pytest.skip("no javac on PATH")
    return compile_class(
        CRYPTO_DEMO_SOURCE, "CryptoDemo", tmp_path=tmp_path_factory.mktemp("javac")
    )


@pytest.fixture(scope="module")
def plain_class_bytes(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    if not JAVAC_AVAILABLE:
        pytest.skip("no javac on PATH")
    return compile_class(NO_CRYPTO_SOURCE, "PlainDemo", tmp_path=tmp_path_factory.mktemp("javac"))


@pytestmark_javac
def test_finds_jca_engine_classes_and_algorithm_strings(crypto_class_bytes: bytes) -> None:
    references = find_class_crypto_references(crypto_class_bytes)
    assert set(references.engine_classes) == {
        "javax/crypto/Cipher",
        "java/security/MessageDigest",
    }
    assert set(references.algorithm_strings) == {"AES/CBC/PKCS5Padding", "SHA-256"}


@pytestmark_javac
def test_constant_pool_walk_survives_long_and_double_entries(crypto_class_bytes: bytes) -> None:
    """`CONSTANT_Long`/`CONSTANT_Double` each occupy *two* constant-pool
    slots (JVM spec §4.4.5). The fixture source contains both; a parser
    that treats them as one slot desynchronises and loses the constants
    that follow — so finding the trailing ones proves the stride is
    right."""
    constants = extract_class_utf8_constants(crypto_class_bytes)
    assert "AES/CBC/PKCS5Padding" in constants
    assert "SHA-256" in constants
    assert len(constants) > 10


@pytestmark_javac
def test_a_class_with_no_crypto_yields_nothing(plain_class_bytes: bytes) -> None:
    references = find_class_crypto_references(plain_class_bytes)
    assert references.engine_classes == ()
    assert references.algorithm_strings == ()
