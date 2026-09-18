"""ARCH.md §2.3 / IDEATION.md §5.1 — the deployed-artefact collector
(A-20). T-036a.

'Priority over the source collector for the demo corpus — in an SI-built
Indian BFSI estate the customer usually does not hold the repository'
(`TASK.md` T-036a). That premise drives the design: everything here
reads what is actually *deployed* on the host, and never assumes a build
system, a lockfile or a source tree exists anywhere.

Runs via the deployed agent (`ARCH.md §2.3`), so `requires_sandbox` is
False and `Target.type` is `HOST` — `target.ref` is a directory on the
host, walked for `.war`/`.ear`/`.jar` files.

**Keystores "sitting beside" the artefacts** (`TASK.md` T-036a) are
deliberately *not* re-implemented here: `tls.store` (T-036) already walks
host paths with certfinder, and the agent runs both collectors over the
same scan-spec paths. Two collectors both claiming to have found the same
keystore would be exactly the "two divergent code paths claiming to
produce the same evidence" problem `ARCH.md §2.3` rules out elsewhere.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from packageurl import PackageURL
from qavach_core.model import ConfidenceTier, FileLocus

from qavach_collectors.artefact.archive import (
    ARCHIVE_EXTENSIONS,
    ArchiveLimitExceeded,
    ArchiveLimits,
    iter_archive_entries,
)
from qavach_collectors.artefact.parse import (
    MavenCoordinates,
    find_class_crypto_references,
    parse_manifest,
    parse_pom_properties,
)
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
from qavach_collectors.sbom.crypto_libraries import CryptoLibraryMapping

_MANIFEST_NAME = "META-INF/MANIFEST.MF"
_POM_PROPERTIES_SUFFIX = "/pom.properties"


@dataclass(frozen=True, slots=True)
class ArtefactInspection:
    artefact_path: str
    manifest: dict[str, str]
    maven_coordinates: tuple[MavenCoordinates, ...]
    class_findings: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]
    """`(class entry path, JCA engine classes referenced, algorithm
    strings present)` — kept as raw co-occurrence, never collapsed into a
    resolved claim here."""


def inspect_artefact(
    data: bytes, *, artefact_path: str, limits: ArchiveLimits | None = None
) -> ArtefactInspection:
    manifest: dict[str, str] = {}
    coordinates: list[MavenCoordinates] = []
    class_findings: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []

    for entry in iter_archive_entries(data, archive_path=artefact_path, limits=limits):
        if entry.name == _MANIFEST_NAME and not manifest:
            manifest = parse_manifest(entry.data)
        elif entry.name.endswith(_POM_PROPERTIES_SUFFIX):
            parsed = parse_pom_properties(entry.data)
            if parsed is not None:
                coordinates.append(parsed)
        elif entry.name.endswith(".class"):
            references = find_class_crypto_references(entry.data)
            if references.engine_classes or references.algorithm_strings:
                class_findings.append(
                    (entry.archive_path, references.engine_classes, references.algorithm_strings)
                )

    return ArtefactInspection(
        artefact_path=artefact_path,
        manifest=manifest,
        maven_coordinates=tuple(coordinates),
        class_findings=tuple(class_findings),
    )


class DeployedArtefactCollector:
    name = "artefact.deployed"
    version = "1.0.0"
    default_confidence = ConfidenceTier.ARTEFACT
    requires_sandbox = False
    requires_network = False

    def __init__(
        self,
        *,
        crypto_libraries: CryptoLibraryMapping,
        archive_limits: ArchiveLimits | None = None,
    ) -> None:
        self._crypto_libraries = crypto_libraries
        self._archive_limits = archive_limits or ArchiveLimits()

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.HOST

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        start = time.monotonic()
        root = Path(target.ref)
        claims: list[RawClaim] = []
        errors: list[CollectorError] = []
        inspected = 0

        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in ARCHIVE_EXTENSIONS:
                continue
            try:
                inspection = inspect_artefact(
                    path.read_bytes(), artefact_path=str(path), limits=self._archive_limits
                )
            except ArchiveLimitExceeded as exc:
                # A capped archive is a *degraded* result for that one
                # artefact, reported explicitly — never a silent truncation
                # and never a failure of the whole scan.
                errors.append(CollectorError(message=str(exc), fatal=False))
                continue
            except OSError as exc:
                errors.append(CollectorError(message=f"{path}: {exc}", fatal=False))
                continue

            inspected += 1
            claims.extend(
                _inspection_claims(
                    inspection,
                    crypto_libraries=self._crypto_libraries,
                    confidence=self.default_confidence,
                )
            )

        return CollectorResult(
            raw=b"",
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=ToolIdentity(
                name=self.name,
                version=self.version,
                invocation=(self.name, target.ref),
                exit_code=0,
                duration_seconds=time.monotonic() - start,
            ),
            errors=errors,
            partial=bool(errors),
        )


def _inspection_claims(
    inspection: ArtefactInspection,
    *,
    crypto_libraries: CryptoLibraryMapping,
    confidence: ConfidenceTier,
) -> list[RawClaim]:
    claims: list[RawClaim] = []

    # 1. Maven coordinates -> purl -> curated capability mapping (T-034).
    #    Same evidence `sbom.syft` produces from a lockfile, obtained here
    #    from the deployed jar itself — the whole point of this collector.
    for coordinates in inspection.maven_coordinates:
        try:
            purl = PackageURL.from_string(coordinates.purl)
        except ValueError:
            continue
        capabilities = crypto_libraries.lookup(purl)
        if not capabilities:
            continue
        claims.extend(
            RawClaim(
                locus=FileLocus(path=inspection.artefact_path, offset=0),
                name=capability,
                detection_method="dependency",
                confidence=ConfidenceTier.DEPENDENCY,
            )
            for capability in capabilities
        )

    # 2. Class constant-pool co-occurrence. PATTERN, never AST: this is
    #    "the string is in the same class as the API reference," not
    #    "the string reaches that call" (see parse.py's module docstring).
    for entry_path, engine_classes, algorithm_strings in inspection.class_findings:
        if not engine_classes:
            continue
        for algorithm in algorithm_strings:
            name, _, remainder = algorithm.partition("/")
            mode, _, padding = remainder.partition("/")
            claims.append(
                RawClaim(
                    locus=FileLocus(path=entry_path, offset=0),
                    name=name,
                    mode=mode or None,
                    padding=padding or None,
                    detection_method="pattern",
                    confidence=ConfidenceTier.PATTERN,
                )
            )

    return claims
