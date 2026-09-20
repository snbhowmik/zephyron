"""Claims -> assets. Nothing dropped, unknowns kept, and the real-data
regressions T-024 found (OID/primitive fragmentation, fixed parameters)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from qavach_core.model.enums import ConfidenceTier, CryptoFunction, FindingClass, MigrationAuthority
from qavach_core.model.locus import FileLocus, NetworkLocus
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_core.pipeline import AssembleKnowledge, ClaimInput, FamilyFunctions, assemble
from qavach_core.reconcile import AuthorityContext
from qavach_core.risk import ClassificationRules

ROOT = Path(__file__).parent.parent.parent
NOW = datetime(2026, 9, 20, tzinfo=UTC)
REGISTRY = CryptographyRegistry.from_dict(
    json.loads((ROOT / "config/knowledge/cdx-crypto-registry/cryptography-defs.json").read_text())
)
FUNCTIONS_DOC = yaml.safe_load((ROOT / "config/knowledge/family_functions.yaml").read_text())
K = AssembleKnowledge(
    registry=REGISTRY,
    aliases=AliasTable.from_dict(
        yaml.safe_load((ROOT / "config/knowledge/aliases.yaml").read_text())
    ),
    rules=ClassificationRules.from_dict(
        yaml.safe_load((ROOT / "config/knowledge/classification_rules.yaml").read_text())
    ),
    family_functions=FamilyFunctions.from_dict(FUNCTIONS_DOC),
)


def claim(
    name: str | None,
    *,
    path: str = "a.py",
    line: int = 1,
    collector: str = "t",
    tier: ConfidenceTier = ConfidenceTier.AST,
    **kw,
):  # type: ignore[no-untyped-def]
    return ClaimInput(
        name=name,
        locus=FileLocus(path=path, offset=line),
        collector=collector,
        tool_version="1",
        confidence=tier,
        detection_method="ast",
        raw_ref="r",
        observed_at=NOW,
        **kw,
    )


def one(claims, **kw):  # type: ignore[no-untyped-def]
    result = assemble(claims, K, **kw)
    assert len(result.assets) == 1
    return result.assets[0]


def test_every_family_named_in_family_functions_yaml_exists_in_the_registry() -> None:
    named = {f for fams in FUNCTIONS_DOC["default_function"].values() for f in fams}
    named |= set(FUNCTIONS_DOC["fixed_parameter_set"]) | set(FUNCTIONS_DOC["curve_families"])
    assert named - set(REGISTRY.families) == set()


def test_conservation_every_claim_becomes_an_occurrence_of_exactly_one_asset() -> None:
    claims = (
        [claim("AES", line=i, parameter_set="256") for i in range(5)]
        + [claim("MD5", line=9)]
        + [claim("Frobnicate", line=7)]
    )
    result = assemble(claims, K)
    assert sum(len(a.occurrences) for a in result.assets) == len(claims) == 7


def test_the_same_algorithm_in_ten_files_is_one_asset_with_ten_occurrences() -> None:
    a = one([claim("AES", path=f"f{i}.py", parameter_set="256") for i in range(10)])
    assert len(a.occurrences) == 10 and a.algorithm_family == "AES"


def test_T024_regression_the_same_md5_from_three_tools_is_one_asset() -> None:
    """Real output: cdxgen (with an OID), cbomkit (parameter 128), Opengrep (bare)."""
    a = one(
        [
            claim("MD5", collector="cdxgen", oid="1.2.840.113549.2.5", primitive="hash"),
            claim("MD5", collector="cbomkit", primitive="hash", parameter_set="128"),
            claim("MD5", collector="opengrep", primitive="hash"),
        ]
    )
    assert len(a.occurrences) == 3 and a.parameter_set == "128"
    assert a.finding_class is FindingClass.CLASSICAL_WEAK
    assert {o.collector for o in a.occurrences} == {"cdxgen", "cbomkit", "opengrep"}


def test_T024_regression_a_wrong_tool_oid_does_not_split_or_pollute_the_asset() -> None:
    """cdxgen labelled SHA-1 with a Novell OID. It must neither split the asset
    nor be recorded as the asset's OID."""
    a = one(
        [
            claim("SHA-1", collector="cdxgen", oid="2.16.840.1.113719.1.2.8.82", primitive="hash"),
            claim("SHA-1", collector="opengrep", primitive="hash"),
        ]
    )
    assert len(a.occurrences) == 2 and a.oid is None and a.parameter_set == "160"


def test_an_oid_our_own_table_resolved_is_kept_as_the_assets_oid() -> None:
    a = one([claim(None, oid="2.16.840.1.101.3.4.4.2")])  # id-alg-ml-kem-768
    assert (
        a.algorithm_family == "ML-KEM"
        and a.parameter_set == "768"
        and a.oid == "2.16.840.1.101.3.4.4.2"
    )
    assert a.finding_class is FindingClass.QUANTUM_SAFE


def test_the_same_algorithm_with_different_sizes_stays_two_assets() -> None:
    result = assemble([claim("AES", parameter_set="128"), claim("AES", parameter_set="256")], K)
    assert len(result.assets) == 2


def test_I8_an_unresolvable_algorithm_becomes_an_unknown_asset_never_dropped() -> None:
    result = assemble(
        [claim("Vendor-Cipher-9000", path="x.bin"), claim("Vendor-Cipher-9000", path="y.bin")], K
    )
    (a,) = result.assets
    assert a.finding_class is FindingClass.UNKNOWN and len(a.occurrences) == 2
    assert a.algorithm_family == "Vendor-Cipher-9000"
    assert result.unresolved == ("Vendor-Cipher-9000",)


def test_a_claim_with_no_name_and_no_oid_is_still_kept() -> None:
    a = one([claim(None)])
    assert a.finding_class is FindingClass.UNKNOWN and a.algorithm_family == "<unnamed>"


def test_function_comes_from_the_claims_primitive_first_then_the_family_default() -> None:
    assert (
        one([claim("RSASSA-PKCS1", parameter_set="2048", primitive="signature")]).function
        is CryptoFunction.SIGNATURE
    )
    assert (
        one([claim("AES", parameter_set="256")]).function is CryptoFunction.ENCRYPTION
    )  # family default
    assert one([claim("ECDH", parameter_set="x25519")]).function is CryptoFunction.KEY_AGREEMENT


def test_an_ambiguous_family_gets_no_function_rather_than_a_guess() -> None:
    a = one([claim("SM2")])
    assert a.function is None  # SM2 does signatures, encryption and key exchange


def test_a_curve_name_becomes_the_curve_not_a_parameter_set() -> None:
    a = one([claim("ECDSA", parameter_set="secp256r1")])
    assert a.curve is not None and a.parameter_set is None
    b = one([claim("ECDSA", parameter_set="P-256"), claim("ECDSA", parameter_set="secp256r1")])
    assert len(b.occurrences) == 2  # two spellings, one curve, one asset


def test_classification_follows_the_rules_including_the_also_quantum_flag() -> None:
    assert (
        one([claim("RSASSA-PKCS1", parameter_set="2048")]).finding_class
        is FindingClass.QUANTUM_VULNERABLE
    )
    assert (
        one([claim("RSASSA-PKCS1", parameter_set="1024")]).finding_class
        is FindingClass.CLASSICAL_WEAK
    )
    assert one([claim("AES", parameter_set="128")]).finding_class is FindingClass.GROVER_AFFECTED
    assert one([claim("AES", parameter_set="256")]).finding_class is FindingClass.QUANTUM_SAFE


def test_mode_is_concluded_by_usage_observing_tiers_and_a_dispute_is_recorded_not_resolved() -> (
    None
):
    a = one(
        [
            claim(
                "AES",
                parameter_set="256",
                collector="ast-tool",
                mode="gcm",
                tier=ConfidenceTier.AST,
            ),
            claim(
                "AES",
                parameter_set="256",
                collector="pattern-tool",
                mode="cbc",
                tier=ConfidenceTier.PATTERN,
            ),
        ]
    )
    assert a.disputed and a.mode == "gcm"  # AST outranks PATTERN for usage, both claims retained
    assert {c.value for d in a.disputes for c in d.claims} == {"gcm", "cbc"}


def test_authority_defaults_to_self_and_can_be_overridden_per_asset() -> None:
    a = one([claim("RSASSA-PKCS1", parameter_set="2048")])
    assert a.migration_authority is MigrationAuthority.SELF and a.authority_basis
    b = one(
        [claim("RSASSA-PKCS1", parameter_set="2048")],
        authority_for=lambda _i, _l: AuthorityContext(
            chains_to_public_root=True, all_loci_third_party=True
        ),
    )
    assert b.migration_authority is MigrationAuthority.EXTERNAL_TRUST_ANCHOR


def test_assembly_is_deterministic_and_input_order_independent() -> None:
    claims = [
        claim("AES", parameter_set="256", line=i, collector=f"c{i % 3}") for i in range(12)
    ] + [claim("MD5")]
    a = assemble(claims, K)
    b = assemble(list(reversed(claims)), K)
    assert a.assets == b.assets


def test_locus_types_other_than_files_are_preserved() -> None:
    net = NetworkLocus(host="h", port=443, sni=None, protocol="tls")
    a = one(
        [
            ClaimInput(
                name="ECDSA",
                locus=net,
                collector="tls",
                tool_version="1",
                confidence=ConfidenceTier.RUNTIME,
                detection_method="runtime",
                raw_ref="r",
                observed_at=NOW,
                parameter_set="secp256r1",
            )
        ]
    )
    assert a.occurrences[0].locus == net and a.concluded_from is ConfidenceTier.RUNTIME


@pytest.mark.parametrize("n", [1, 100])
def test_scale_smoke(n: int) -> None:
    assert (
        len(assemble([claim("AES", parameter_set="256", line=i) for i in range(n)], K).assets) == 1
    )


def test_a_stored_adjudication_is_applied_reported_and_the_dispute_resolved() -> None:
    """The assembler must hand back what happened to each ruling (it once
    computed the outcome and dropped it on the floor)."""
    from qavach_core.reconcile import OccurrenceClaim, adjudicate, merge_all

    claims = [
        claim(
            "AES", parameter_set="256", collector="ast-tool", mode="gcm", tier=ConfidenceTier.AST
        ),
        claim(
            "AES",
            parameter_set="256",
            collector="pattern-tool",
            mode="cbc",
            tier=ConfidenceTier.PATTERN,
        ),
    ]
    first = assemble(claims, K)
    assert first.adjudications is None and first.assets[0].disputed
    identity = first.assets[0].identity
    locus = FileLocus(path="a.py", offset=1)
    dispute_claims = [
        OccurrenceClaim(
            identity=identity,
            locus=locus,
            collector=c,
            tool_version="1",
            confidence=t,
            detection_method="x",
            raw_ref="r",
            observed_at=NOW,
            mode=m,
        )
        for c, t, m in (("a", ConfidenceTier.AST, "gcm"), ("b", ConfidenceTier.PATTERN, "cbc"))
    ]
    ruling = adjudicate(
        merge_all(dispute_claims)[0], "mode", "gcm", by="ops", at=NOW, reason="read it"
    )
    second = assemble(claims, K, adjudications=[ruling])
    assert second.adjudications is not None and second.adjudications.applied == (ruling,)
    resolved = second.assets[0]
    assert not resolved.disputed and resolved.mode == "gcm"
    assert all(d.resolved for d in resolved.disputes) and {
        c.value for d in resolved.disputes for c in d.claims
    } == {"gcm", "cbc"}


def test_capability_only_means_only_a_dependency_was_seen_never_a_call_site() -> None:
    """DEPENDENCY (60) outranks AST (50) and PATTERN (30) numerically, so judging by the
    maximum tier called observed call sites "capability only". It is judged over every
    occurrence instead."""
    from qavach_core.model.asset import is_capability_only
    from qavach_core.model.enums import ConfidenceTier as T

    assert is_capability_only([T.DEPENDENCY, T.DEPENDENCY])
    assert not is_capability_only([T.PATTERN])
    assert not is_capability_only([T.AST])
    assert not is_capability_only([T.DEPENDENCY, T.PATTERN])  # a dependency AND a call site
    assert not is_capability_only([T.DEPENDENCY, T.RUNTIME])
    assert not is_capability_only([])
