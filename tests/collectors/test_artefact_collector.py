"""T-036a — `DeployedArtefactCollector` end to end, over a real WAR
containing a real nested JAR, a real `MANIFEST.MF`, a real
`pom.properties` and a genuinely `javac`-compiled class. This is the
shape `IDEATION.md §5.1` describes: what is actually deployed on a host,
with no repository, build system or lockfile available anywhere."""

from __future__ import annotations

from pathlib import Path

import pytest
from _java_fixture import (
    BOUNCYCASTLE_POM_PROPERTIES,
    CRYPTO_DEMO_SOURCE,
    JAVAC_AVAILABLE,
    MANIFEST,
    build_jar,
    compile_class,
)
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.artefact import (
    ArchiveLimits,
    DeployedArtefactCollector,
    inspect_artefact,
)
from qavach_collectors.sbom import CryptoLibraryMapping

FIXTURE_MAPPING = CryptoLibraryMapping.from_entries(
    [
        {
            "type": "maven",
            "namespace": "org.bouncycastle",
            "name": "bcprov-jdk18on",
            "provides": ["AES", "RSASSA-PKCS1", "ECDSA"],
        }
    ]
)

pytestmark = pytest.mark.skipif(not JAVAC_AVAILABLE, reason="no javac on PATH")


@pytest.fixture(scope="module")
def crypto_class_bytes(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    return compile_class(
        CRYPTO_DEMO_SOURCE, "CryptoDemo", tmp_path=tmp_path_factory.mktemp("javac")
    )


def _build_realistic_war(tmp_path: Path, crypto_class_bytes: bytes) -> Path:
    """A WAR shaped like a real deployment: app classes at
    `WEB-INF/classes`, dependencies as nested jars under
    `WEB-INF/lib`."""
    inner_jar = build_jar(
        {
            "META-INF/maven/org.bouncycastle/bcprov-jdk18on/pom.properties": (
                BOUNCYCASTLE_POM_PROPERTIES
            ),
            "org/bouncycastle/Dummy.class": b"\xca\xfe\xba\xbe",
        },
        path=tmp_path / "bcprov-jdk18on-1.78.jar",
    )
    return build_jar(
        {
            "META-INF/MANIFEST.MF": MANIFEST,
            "WEB-INF/classes/CryptoDemo.class": crypto_class_bytes,
            "WEB-INF/lib/bcprov-jdk18on-1.78.jar": inner_jar.read_bytes(),
            "WEB-INF/web.xml": b"<web-app/>",
        },
        path=tmp_path / "payments.war",
    )


def test_inspect_finds_manifest_coordinates_and_class_references(
    tmp_path: Path, crypto_class_bytes: bytes
) -> None:
    war = _build_realistic_war(tmp_path, crypto_class_bytes)
    inspection = inspect_artefact(war.read_bytes(), artefact_path=str(war))

    assert inspection.manifest["Implementation-Title"] == "payments-service"
    assert [c.purl for c in inspection.maven_coordinates] == [
        "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"
    ]
    assert len(inspection.class_findings) == 1
    entry_path, engine_classes, algorithm_strings = inspection.class_findings[0]
    assert entry_path.endswith("payments.war!/WEB-INF/classes/CryptoDemo.class")
    assert "javax/crypto/Cipher" in engine_classes
    assert "AES/CBC/PKCS5Padding" in algorithm_strings


def test_collect_produces_dependency_and_pattern_claims_at_different_tiers(
    tmp_path: Path, crypto_class_bytes: bytes
) -> None:
    """The two evidence sources must not be flattened into one
    confidence: exact Maven coordinates are DEPENDENCY-tier, while a
    string constant co-occurring with a JCA reference is PATTERN — the
    collector never claims the string provably reaches the call."""
    _build_realistic_war(tmp_path, crypto_class_bytes)

    collector = DeployedArtefactCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="run-1")
    )

    assert not result.partial
    assert result.errors == []

    dependency_claims = [c for c in result.claims if c.confidence.name == "DEPENDENCY"]
    pattern_claims = [c for c in result.claims if c.confidence.name == "PATTERN"]

    assert {c.name for c in dependency_claims} == {"AES", "RSASSA-PKCS1", "ECDSA"}
    assert {c.name for c in pattern_claims} == {"AES", "SHA-256"}

    aes_pattern = next(c for c in pattern_claims if c.name == "AES")
    assert aes_pattern.mode == "CBC"
    assert aes_pattern.padding == "PKCS5Padding"


def test_supports_only_host_targets() -> None:
    collector = DeployedArtefactCollector(crypto_libraries=FIXTURE_MAPPING)
    assert collector.supports(Target(type=TargetType.HOST, ref="/opt/tomcat"))
    assert not collector.supports(Target(type=TargetType.REPOSITORY, ref="/x"))


def test_directory_with_no_artefacts_yields_no_claims(tmp_path: Path) -> None:
    (tmp_path / "readme.txt").write_text("nothing to see")
    collector = DeployedArtefactCollector(crypto_libraries=FIXTURE_MAPPING)
    result = collector.collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="run-1")
    )
    assert result.claims == []
    assert not result.partial


def test_an_over_cap_artefact_degrades_that_artefact_only(
    tmp_path: Path, crypto_class_bytes: bytes
) -> None:
    """One oversized WAR must not lose the findings from a healthy one
    sitting next to it — `SECURITY.md §3`'s "failure is isolated",
    applied per artefact."""
    _build_realistic_war(tmp_path, crypto_class_bytes)
    build_jar(
        {f"padding{i}.bin": b"\x00" * (128 * 1024) for i in range(40)},
        path=tmp_path / "huge.jar",
    )

    collector = DeployedArtefactCollector(
        crypto_libraries=FIXTURE_MAPPING,
        archive_limits=ArchiveLimits(max_total_uncompressed_bytes=1024 * 1024),
    )
    result = collector.collect(
        Target(type=TargetType.HOST, ref=str(tmp_path)), RunContext(scan_run_id="run-1")
    )

    assert result.partial
    assert any(not e.fatal for e in result.errors)
    # The healthy WAR's findings survived the neighbouring failure.
    assert any(c.name == "AES" for c in result.claims)
