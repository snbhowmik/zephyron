"""`PRD.md FR-180` — ingest an externally produced CycloneDX CBOM
(1.4-1.7) as a first-class source. T-043.

A vendor's CBOM is a *claim about their product that QAVACH did not
observe*: `ATTESTED` tier, retained verbatim in `raw`, and — because the
author is a third party — the resulting assets are candidates for
`MigrationAuthority.VENDOR` (invariant I9) rather than something the
operator can necessarily change. Deciding that is the authority layer's
job (`reconcile/authority.py`); this collector only reports what the
document says and where it came from.

The document is **untrusted input** (`SECURITY.md §9`): the file is
size-capped *before* it is read into memory ("a 4 GB SARIF file is a DoS"),
parse failures — including `RecursionError` from pathologically nested
JSON — degrade rather than propagate, and each component is normalised on
its own, so one malformed component is reported individually instead of
discarding the rest of a vendor's document.

No sandbox: this is QAVACH parsing a file with its own code, no third-party
binary involved (contrast OQ-12).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from qavach_core.model import ConfidenceTier
from qavach_core.normalize import AliasTable, CryptographyRegistry, normalise_bom

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
from qavach_collectors.cbom_claims import normalised_to_raw_claims

DEFAULT_MAX_BYTES = 64 * 1024 * 1024

_RAW_FORMATS = {
    "1.4": RawFormat.CDX_1_4,
    "1.5": RawFormat.CDX_1_5,
    "1.6": RawFormat.CDX_1_6,
    "1.7": RawFormat.CDX_1_7,
}


class ExternalCbomCollector:
    name = "ingest.cbom"
    version = "1.0.0"
    default_confidence = ConfidenceTier.ATTESTED
    requires_sandbox = False
    requires_network = False

    def __init__(
        self,
        *,
        registry: CryptographyRegistry,
        aliases: AliasTable,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self._registry = registry
        self._aliases = aliases
        self._max_bytes = max_bytes

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.CBOM_UPLOAD

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        start = time.monotonic()
        path = Path(target.ref)
        # Provenance: which upload/vendor a claim came from, so identically
        # named relative paths in different vendors' CBOMs cannot collide.
        source_label = target.options.get("source", path.name)
        locus_prefix = f"{source_label}!"

        def result(
            *,
            raw: bytes = b"",
            claims: list[RawClaim] | None = None,
            errors: list[CollectorError] | None = None,
            fmt: RawFormat = RawFormat.QAVACH_NATIVE,
        ) -> CollectorResult:
            errs = errors or []
            return CollectorResult(
                raw=raw,
                raw_format=fmt,
                claims=claims or [],
                tool=ToolIdentity(
                    name=self.name,
                    version=self.version,
                    invocation=(self.name, path.name),
                    exit_code=0 if not any(e.fatal for e in errs) else None,
                    duration_seconds=time.monotonic() - start,
                ),
                errors=errs,
                partial=bool(errs),
            )

        try:
            size = path.stat().st_size
        except OSError as exc:
            return result(errors=[CollectorError(message=f"{path}: {exc}", fatal=True)])
        if size > self._max_bytes:
            return result(
                errors=[
                    CollectorError(
                        message=f"{path.name}: {size} bytes exceeds the {self._max_bytes}-byte cap "
                        "(SECURITY.md §9) — refusing to read it",
                        fatal=True,
                    )
                ]
            )

        raw = path.read_bytes()
        try:
            document: Any = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            return result(
                raw=raw,
                errors=[CollectorError(message=f"not valid CycloneDX JSON: {exc}", fatal=True)],
            )
        if not isinstance(document, dict):
            return result(
                raw=raw,
                errors=[CollectorError(message="CBOM root is not a JSON object", fatal=True)],
            )

        spec_version = document.get("specVersion")
        fmt = _RAW_FORMATS.get(str(spec_version))
        if fmt is None:
            return result(
                raw=raw,
                errors=[
                    CollectorError(
                        message=f"unsupported CycloneDX specVersion {spec_version!r} "
                        f"(supported: {sorted(_RAW_FORMATS)})",
                        fatal=True,
                    )
                ],
            )

        claims: list[RawClaim] = []
        errors: list[CollectorError] = []
        components = document.get("components") or []
        if not isinstance(components, list):
            return result(
                raw=raw,
                fmt=fmt,
                errors=[CollectorError(message="`components` is not a list", fatal=True)],
            )

        for index, component in enumerate(components):
            if not isinstance(component, dict) or component.get("type") != "cryptographic-asset":
                continue
            single = {
                "bomFormat": "CycloneDX",
                "specVersion": spec_version,
                "components": [component],
            }
            try:
                normalised = normalise_bom(single, registry=self._registry, aliases=self._aliases)
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                label = component.get("bom-ref") or component.get("name") or f"#{index}"
                errors.append(
                    CollectorError(
                        message=f"component {label!r} skipped: {type(exc).__name__}: {exc}",
                        fatal=False,
                    )
                )
                continue
            for item in normalised:
                claims.extend(
                    normalised_to_raw_claims(
                        item,
                        target=target,
                        confidence=self.default_confidence,
                        locus_prefix=locus_prefix,
                    )
                )

        return result(raw=raw, claims=claims, errors=errors, fmt=fmt)
