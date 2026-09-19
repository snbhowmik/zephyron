"""CycloneDX 1.7 CBOM export. T-090 / ARCH.md 10 / invariant I5.

**The CBOM is a standards artefact other tools consume, so it carries the
inventory - not QAVACH's opinions.** Risk scores, Mosca inputs, CARAF outcomes,
recommendations and roadmap position live in the Crypto Risk Register
(`register.py`), which references components by `bom-ref`. The only QAVACH data
in the CBOM is a small set of `qavach:` properties describing the *inventory's
own quality* (`DOCUMENTED_PROPERTIES`, documented in
`docs/CUSTOM_PROPERTIES.md`); `purity.py` and `make schema-check` fail the build
if anything else appears.

Mappings (each read from the 1.7 schema, not assumed):

* occurrences -> `evidence.occurrences[]` (`location`, `line`, `additionalContext`);
* provenance  -> `evidence.identity[].methods[]` (the schema's `technique` enum);
* **no `purl` on `cryptographic-asset` components** - a purl identifies a
  package, and an algorithm is not one;
* `bom-ref` is derived from the asset identity, so the same asset has the same
  reference in the CBOM and in the register, and across runs.

Deterministic (NFR-09): sorted components and occurrences, a `serialNumber`
that is a UUIDv5 of the content, and a caller-supplied timestamp - no clock.

Scope (`ARCH.md 10.1`) is a *query* on the already-reconciled asset set: the
caller filters assets and passes `scope`; this function never re-merges.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from qavach_core.model.asset import CryptoAsset, Occurrence
from qavach_core.model.enums import AssetType, ConfidenceTier, CryptoFunction
from qavach_core.model.identity import AssetIdentity
from qavach_core.model.locus import (
    CloudLocus,
    ContainerLocus,
    DependencyLocus,
    FileLocus,
    HostLocus,
    HsmLocus,
    Locus,
    NetworkLocus,
    RuntimeLocus,
    SourceLocus,
)

SPEC_VERSION = "1.7"
QAVACH_NAME = "QAVACH"
DOCUMENTED_PROPERTIES = frozenset(
    {
        "qavach:disputed",
        "qavach:concluded-confidence",
        "qavach:scope",
        "qavach:downgraded-from",
    }
)
"""The complete, closed list of `qavach:` property names the CBOM may contain."""

_CONFIDENCE = {
    ConfidenceTier.RUNTIME: 1.0,
    ConfidenceTier.ARTEFACT: 0.9,
    ConfidenceTier.ATTESTED: 0.8,
    ConfidenceTier.DEPENDENCY: 0.6,
    ConfidenceTier.AST: 0.5,
    ConfidenceTier.PATTERN: 0.3,
    ConfidenceTier.HEURISTIC: 0.1,
}
_TECHNIQUE = {
    "ast": "ast-fingerprint",
    "source-code-analysis": "source-code-analysis",
    "pattern": "source-code-analysis",
    "dependency": "manifest-analysis",
    "manifest-analysis": "manifest-analysis",
    "runtime": "instrumentation",
    "instrumentation": "instrumentation",
    "artefact": "binary-analysis",
    "attested": "attestation",
}
_CRYPTO_FUNCTIONS = {
    CryptoFunction.KEY_ENCAPSULATION: ["encapsulate", "decapsulate"],
    CryptoFunction.KEY_AGREEMENT: ["keyderive"],
    CryptoFunction.ENCRYPTION: ["encrypt", "decrypt"],
    CryptoFunction.SIGNATURE: ["sign", "verify"],
    CryptoFunction.MAC: ["tag"],
    CryptoFunction.HASH: ["digest"],
    CryptoFunction.KDF: ["keyderive"],
    CryptoFunction.DRBG: ["generate"],
}
_PRIMITIVE = {
    CryptoFunction.KEY_ENCAPSULATION: "kem",
    CryptoFunction.KEY_AGREEMENT: "key-agree",
    CryptoFunction.SIGNATURE: "signature",
    CryptoFunction.MAC: "mac",
    CryptoFunction.HASH: "hash",
    CryptoFunction.KDF: "kdf",
    CryptoFunction.DRBG: "drbg",
}
_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
_PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw"}


def bom_ref(identity: AssetIdentity) -> str:
    return f"crypto/{identity.kind.value}/{identity.key}"


def _primitive(asset: CryptoAsset) -> str:
    if asset.function is None:
        return "unknown"
    if asset.function is CryptoFunction.ENCRYPTION:
        family = asset.algorithm_family
        if family.startswith("RSAES"):
            return "pke"
        if family.startswith("ChaCha") or family == "RC4":
            return "stream-cipher"
        mode = (asset.mode or "").lower()
        if mode in {"gcm", "ccm"}:
            return "ae"
        return "block-cipher" if mode else "unknown"
    return _PRIMITIVE.get(asset.function, "unknown")


def location_of(locus: Locus) -> tuple[str, int | None, str | None]:
    """`(location, line, additionalContext)`. `FileLocus.offset` carries the line
    number by convention (`NOTE.md` LOCUS-01)."""
    if isinstance(locus, SourceLocus):
        return locus.path, locus.start_line, f"repo={locus.repo} commit={locus.commit}"
    if isinstance(locus, FileLocus):
        return locus.path, (locus.offset or None), None
    if isinstance(locus, NetworkLocus):
        return f"{locus.host}:{locus.port}", None, f"protocol={locus.protocol}"
    if isinstance(locus, CloudLocus):
        return locus.resource_arn, None, f"provider={locus.provider} account={locus.account}"
    if isinstance(locus, ContainerLocus):
        return locus.path, None, f"image={locus.image_digest} layer={locus.layer_digest}"
    if isinstance(locus, DependencyLocus):
        return locus.dependency_path, None, f"dependency={locus.purl}"
    if isinstance(locus, RuntimeLocus):
        return locus.module, None, f"process={locus.process}"
    if isinstance(locus, HsmLocus):
        return locus.module_path, None, f"slot={locus.slot_ref}"
    if isinstance(locus, HostLocus):
        return locus.path, (locus.offset or None), f"host={locus.host_identity}"
    raise TypeError(f"unsupported locus {type(locus).__name__}")


def _occurrence(occ: Occurrence) -> dict[str, Any]:
    location, line, context = location_of(occ.locus)
    item: dict[str, Any] = {"location": location}
    if line is not None:
        item["line"] = line
    extra = f"collector={occ.collector} tool={occ.tool_version} raw={occ.raw_ref}"
    item["additionalContext"] = f"{context}; {extra}" if context else extra
    return item


def _component(asset: CryptoAsset, known_families: frozenset[str] | None) -> dict[str, Any]:
    name = asset.algorithm_family + (f"-{asset.parameter_set}" if asset.parameter_set else "")
    crypto: dict[str, Any] = {"assetType": asset.asset_type.value}
    if asset.asset_type is AssetType.ALGORITHM:
        props: dict[str, Any] = {
            "primitive": _primitive(asset),
            "cryptoFunctions": _CRYPTO_FUNCTIONS[asset.function] if asset.function else ["unknown"],
        }
        if known_families is None or asset.algorithm_family in known_families:
            props["algorithmFamily"] = asset.algorithm_family
        if asset.parameter_set:
            props["parameterSetIdentifier"] = asset.parameter_set
        if asset.curve:
            props["curve"] = asset.curve
        if asset.mode and asset.mode.lower() in _MODES:
            props["mode"] = asset.mode.lower()
        if asset.padding and asset.padding.lower() in _PADDINGS:
            props["padding"] = asset.padding.lower()
        crypto["algorithmProperties"] = props
    if asset.oid:
        crypto["oid"] = asset.oid

    occurrences = sorted(
        (_occurrence(o) for o in asset.occurrences),
        key=lambda o: (o["location"], o.get("line", 0), o["additionalContext"]),
    )
    methods = sorted(
        {
            (
                _TECHNIQUE.get(o.detection_method, "other"),
                _CONFIDENCE[o.confidence],
                o.collector,
            )
            for o in asset.occurrences
        }
    )
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref(asset.identity),
        "name": name,
        "cryptoProperties": crypto,
        "evidence": {
            "occurrences": occurrences,
            "identity": [
                {
                    "field": "name",
                    "confidence": _CONFIDENCE[asset.concluded_from],
                    "concludedValue": name,
                    "methods": [
                        {"technique": t, "confidence": c, "value": f"{collector}"}
                        for t, c, collector in methods
                    ],
                    "tools": sorted(
                        {f"tool/{o.collector}" for o in asset.occurrences},
                    ),
                }
            ],
        },
    }
    properties = []
    if asset.disputed:
        properties.append({"name": "qavach:disputed", "value": "true"})
    properties.append(
        {"name": "qavach:concluded-confidence", "value": asset.concluded_from.name.lower()}
    )
    component["properties"] = properties
    return component


def build_cbom(
    assets: Iterable[CryptoAsset],
    *,
    timestamp: datetime,
    qavach_version: str,
    scope: str = "root",
    known_families: frozenset[str] | None = None,
) -> dict[str, Any]:
    """`known_families`: the Cryptography Registry's family names, so a family the
    registry does not list is omitted rather than making the document
    schema-invalid. `None` includes every family (caller's risk)."""
    ordered = sorted(assets, key=lambda a: bom_ref(a.identity))
    components = [_component(a, known_families) for a in ordered]

    tools: dict[str, dict[str, Any]] = {
        f"tool/{QAVACH_NAME.lower()}": {
            "type": "application",
            "bom-ref": f"tool/{QAVACH_NAME.lower()}",
            "name": QAVACH_NAME,
            "version": qavach_version,
        }
    }
    for asset in ordered:
        for occ in asset.occurrences:
            ref = f"tool/{occ.collector}"
            tools.setdefault(
                ref,
                {
                    "type": "application",
                    "bom-ref": ref,
                    "name": occ.collector,
                    "version": occ.tool_version,
                },
            )

    body: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "tools": {"components": [tools[k] for k in sorted(tools)]},
            "properties": [{"name": "qavach:scope", "value": scope}],
        },
        "components": components,
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'qavach:cbom:' + digest)}",
        **body,
    }


def component_refs(bom: Mapping[str, Any]) -> set[str]:
    return {c["bom-ref"] for c in bom.get("components", [])}


def downgrade_to_1_6(bom: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """T-093. A CycloneDX 1.6 rendering of a 1.7 CBOM for consumers that have not
    moved on. Returns `(document, losses)`; nothing is dropped without being
    listed, and the document says it was downgraded (`qavach:downgraded-from`).

    What 1.7 has that 1.6 does not, for cryptographic assets: the
    `algorithmFamily` registry enum (the family survives in the component
    `name`) and the `key-wrap` primitive (mapped to `other`). Everything else
    this exporter emits is common to both, and the result is validated against
    the vendored 1.6 schema by `make schema-check`.
    """
    doc: dict[str, Any] = json.loads(json.dumps(bom))
    losses: list[str] = []
    doc["specVersion"] = "1.6"
    if "$schema" in doc:
        doc["$schema"] = "http://cyclonedx.org/schema/bom-1.6.schema.json"
    for component in doc.get("components", []):
        props = component.get("cryptoProperties", {}).get("algorithmProperties")
        if not props:
            continue
        if "algorithmFamily" in props:
            losses.append(
                f"{component['bom-ref']}: algorithmFamily {props.pop('algorithmFamily')!r} "
                "(1.7-only; kept in the component name)"
            )
        if props.get("primitive") == "key-wrap":
            props["primitive"] = "other"
            losses.append(f"{component['bom-ref']}: primitive key-wrap mapped to other")
    doc.setdefault("metadata", {}).setdefault("properties", []).append(
        {"name": "qavach:downgraded-from", "value": SPEC_VERSION}
    )
    body = {k: v for k, v in doc.items() if k not in ("serialNumber", "$schema")}
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    doc["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'qavach:cbom:' + digest)}"
    return doc, sorted(losses)
