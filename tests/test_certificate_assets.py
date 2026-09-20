"""OQ-20 / I2, end to end: a root CA and an ephemeral leaf with the *same*
RSA-2048 algorithm are two assets and score in opposite directions.

Real X.509 certificates (generated here with `cryptography`) go through the real
TLS-endpoint parser, the real claim builder, the assembler, scoring, storage and
CBOM export - nothing about the certificates' roles is hand-set.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from qavach_collectors.tls.collector import _cert_claims
from qavach_collectors.tls.endpoint import parse_certificate_pem
from qavach_core.context import parse_systems_csv
from qavach_core.export import build_cbom, cbom_violations, downgrade_to_1_6
from qavach_core.model import ConfidenceTier, NetworkLocus
from qavach_core.model.enums import AssetType, FindingClass
from qavach_core.pipeline import (
    ClaimInput,
    artefact_lifetime_of,
    assemble,
)
from qavach_core.risk import AssetRiskInput, score_asset
from qavach_storage import Repository, create_all, make_engine, session_factory

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/demo.py")
assert _spec and _spec.loader
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

KNOWLEDGE, POLICY, _PQC = demo.load_knowledge()
AS_OF = date(2026, 9, 20)
NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pair() -> tuple[bytes, bytes]:
    """`(root_pem, leaf_pem)`: both RSA-2048, root valid 20 y, leaf 90 days."""
    root_key = rsa.generate_private_key(65537, 2048)
    leaf_key = rsa.generate_private_key(65537, 2048)
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("Acme Offline Root"))
        .issuer_name(_name("Acme Offline Root"))
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(NOW + timedelta(days=365 * 20))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("pay.acme.example"))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=89))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return root.public_bytes(pem), leaf.public_bytes(pem)


def claims_for(*pems: bytes) -> list[ClaimInput]:
    locus = NetworkLocus(
        host="pay.acme.example", port=443, sni="pay.acme.example", protocol="TLSv1.3"
    )
    out = []
    for pem in pems:
        for raw in _cert_claims(
            parse_certificate_pem(pem), locus=locus, confidence=ConfidenceTier.RUNTIME
        ):
            out.append(
                ClaimInput(
                    name=raw.name,
                    primitive=raw.primitive,
                    parameter_set=raw.parameter_set,
                    certificate=raw.certificate,
                    locus=raw.locus,
                    collector="tls.endpoint",
                    tool_version="0",
                    confidence=raw.confidence,
                    detection_method=raw.detection_method,
                    raw_ref="tls.endpoint:test",
                    observed_at=NOW,
                )
            )
    return out


def assembled() -> list:  # type: ignore[type-arg]
    return list(assemble(claims_for(*make_pair()), KNOWLEDGE).assets)


def test_two_certificates_with_one_algorithm_stay_two_assets_with_their_roles() -> None:
    assets = assembled()
    assert len(assets) == 2
    assert {a.asset_type for a in assets} == {AssetType.CERTIFICATE}
    roles = {a.certificate.role for a in assets if a.certificate}
    assert roles == {"root", "leaf"}
    assert {a.algorithm_family for a in assets} == {assets[0].algorithm_family}  # same algorithm
    assert all(a.finding_class is FindingClass.QUANTUM_VULNERABLE for a in assets)


def test_the_root_ca_outlives_the_leaf_by_years_in_the_derived_lifetime() -> None:
    by_role = {a.certificate.role: a for a in assembled() if a.certificate}
    root_years = artefact_lifetime_of(by_role["root"], AS_OF)
    leaf_years = artefact_lifetime_of(by_role["leaf"], AS_OF)
    assert root_years and 19 < root_years < 21
    assert leaf_years is not None and leaf_years < 0.3


def test_I2_the_same_algorithm_scores_opposite_urgency_for_a_root_and_an_ephemeral_leaf() -> None:
    imported = parse_systems_csv((ROOT / "tests/fixtures/demo/systems.csv").read_text(), POLICY)
    system = imported.systems[0]
    scored = {}
    for a in assembled():
        assert a.certificate
        scored[a.certificate.role] = score_asset(
            AssetRiskInput(
                identity=a.identity,
                finding_class=a.finding_class,
                also_quantum_vulnerable=False,
                function=a.function,
                authority=a.migration_authority,
                loci=tuple(o.locus for o in a.occurrences),
                system=system,
                artefact_lifetime_years=artefact_lifetime_of(a, AS_OF),
            ),
            policy=POLICY,
            as_of=AS_OF,
        )
    root, leaf = scored["root"], scored["leaf"]
    assert root.mosca and leaf.mosca
    assert root.mosca.x_integ > 10 and leaf.mosca.x_integ == 0
    # the leaf's short life leaves nothing for a future forger; the root's does not
    assert root.mosca.gap_years is not None and leaf.mosca.gap_years is not None
    assert root.mosca.gap_years > leaf.mosca.gap_years
    # X differs by ~20 years and nothing else does, so the gap differs by exactly that
    assert abs((root.mosca.gap_years - leaf.mosca.gap_years) - root.mosca.x_integ) < 1e-6
    rank = {"planned": 0, "imminent": 1, "overdue": 2}
    assert rank[root.band.value] >= rank[leaf.band.value]
    assert root.band.value == "overdue"


def test_a_reissued_ca_with_the_same_key_is_one_asset_keeping_the_longest_lived_cert() -> None:
    root_pem, _ = make_pair()
    [claim] = claims_for(root_pem)
    assert claim.certificate is not None
    reissued = replace(
        claim.certificate,
        sha256_fingerprint="f" * 64,  # a different certificate, same SPKI
        not_after=claim.certificate.not_after + timedelta(days=900),
    )
    twin = replace(claim, certificate=reissued, raw_ref="tls.endpoint:reissue")
    [asset] = assemble([claim, twin], KNOWLEDGE).assets
    assert len(asset.occurrences) == 2
    assert asset.certificate is not None and asset.certificate.not_after == reissued.not_after


def test_certificate_facts_survive_storage_and_appear_in_simulation_rows() -> None:
    engine = make_engine("sqlite://")
    create_all(engine)
    assets = assembled()
    with session_factory(engine)() as session:
        repo = Repository(session)
        repo.create_scan(
            scan_id="s1",
            target_ref="t",
            policy=POLICY,
            z_scenario="nominal",
            as_of=AS_OF.isoformat(),
            now=NOW,
        )
        repo.save_assets("s1", assets)
        session.commit()
        loaded = {a.identity.key: a for a in repo.load_assets("s1")}
        for a in assets:
            assert loaded[a.identity.key].certificate == a.certificate
        rows = repo.simulation_rows("s1")
        assert {r["certificate"]["is_ca"] for r in rows} == {True, False}


def test_the_cbom_carries_certificate_properties_validates_and_has_no_risk_data() -> None:
    from schema_check import cbom_validator, errors_of, known_families

    cbom = build_cbom(
        assembled(), timestamp=NOW, qavach_version="0.1.0", known_families=known_families()
    )
    certs = [c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate"]
    assert len(certs) == 2
    names = {c["name"] for c in certs}
    assert names == {"CN=Acme Offline Root", "CN=pay.acme.example"}
    ca_flags = {
        c["cryptoProperties"]["certificateProperties"]["certificateExtensions"][0][
            "commonExtensionValue"
        ]
        for c in certs
    }
    assert ca_flags == {"CA:TRUE", "CA:FALSE"}
    assert errors_of(cbom_validator(), cbom) == []
    assert cbom_violations(cbom) == []
    down, losses = downgrade_to_1_6(cbom)
    assert any("fingerprint" in loss for loss in losses)
    for c in down["components"]:
        assert "fingerprint" not in c["cryptoProperties"].get("certificateProperties", {})
