"""The production collector registry registers only what can run, and says why not."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import demo  # noqa: E402
from qavach_worker.registry import build_central_registry  # noqa: E402

KNOWLEDGE, _POLICY, _PQC = demo.load_knowledge()
CONFIG = ROOT / "config"


def build(**kw):  # type: ignore[no-untyped-def]
    return build_central_registry(
        CONFIG, registry=KNOWLEDGE.registry, aliases=KNOWLEDGE.aliases, **kw
    )


def names(c) -> set[str]:  # type: ignore[no-untyped-def]
    return {x.name for x in c.registry}


def test_with_every_image_built_all_central_collectors_register() -> None:
    c = build(image_id=lambda tag: "sha256:" + "a" * 64)
    assert {
        "source_scan.cdxgen",
        "source_scan.opengrep",
        "source_scan.cbomkit",
        "sbom.syft",
        "runtime.tracebom",
        "container.theia",
        "tls.endpoint",
        "ssh.hostkey",
        "ingest.cbom",
        "binary.static",
    } == names(c)


def test_an_unbuilt_image_is_skipped_with_a_reason_not_registered_to_fail() -> None:
    c = build(image_id=lambda tag: None if "opengrep" in tag else "sha256:" + "b" * 64)
    assert "source_scan.opengrep" not in names(c)
    assert "make build-images" in c.skipped["source_scan.opengrep"]
    assert "source_scan.cdxgen" in names(c)


def test_no_container_engine_leaves_only_the_network_and_file_collectors() -> None:
    c = build(engine_available=False)
    assert names(c) == {"tls.endpoint", "ssh.hostkey", "ingest.cbom", "binary.static"}
    assert all(
        "no container engine" in c.skipped[n]
        for n in ("source_scan.cdxgen", "sbom.syft", "runtime.tracebom")
    )


def test_credentialed_and_agent_only_collectors_are_never_registered_centrally() -> None:
    c = build(image_id=lambda tag: "sha256:" + "c" * 64)
    for n in ("cloud.aws", "ad.adcs", "tls.store", "hsm.evidence", "artefact.deployed"):
        assert n not in names(c) and n in c.skipped


def test_a_scan_request_survives_the_queue_payload_round_trip() -> None:
    from datetime import date

    from qavach_collectors import Target, TargetType
    from qavach_worker import ScanRequest
    from qavach_worker.jobs import from_payload, to_payload

    original = ScanRequest(
        target=Target(type=TargetType.REPOSITORY, ref="/r", options={"cmd": "x"}),
        scan_id="s1",
        z_scenario="aggressive",
        as_of=date(2026, 9, 20),
        capacity_per_quarter=4,
        actor="api",
    )
    assert from_payload(to_payload(original)) == original


def test_a_pinned_ref_falls_back_to_the_bare_digest_on_a_host_loaded_from_a_bundle(
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """`docker load` restores the image but not its `repo@sha256:` name; the bare
    `sha256:<digest>` names the same bytes (containerd image store) and the sandbox
    accepts it. If the digest is not local either, the original ref is kept."""
    import qavach_worker.registry as reg

    digest = "a" * 64
    pinned = f"ghcr.io/x/y@sha256:{digest}"

    def local(present: set[str]):  # type: ignore[no-untyped-def]
        return lambda ref, engine="docker": ref if ref in present else None

    monkeypatch.setattr(reg, "local_image_id", local({pinned}))
    assert reg.resolve_local_ref(pinned) == pinned  # normal host: name resolves
    monkeypatch.setattr(reg, "local_image_id", local({f"sha256:{digest}"}))
    assert reg.resolve_local_ref(pinned) == f"sha256:{digest}"  # bundle-loaded host
    monkeypatch.setattr(reg, "local_image_id", local(set()))
    assert reg.resolve_local_ref(pinned) == pinned  # not present at all: unchanged
    assert reg.resolve_local_ref("qavach/x:dev") == "qavach/x:dev"  # not a digest pin
