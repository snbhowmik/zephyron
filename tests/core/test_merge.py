"""T-022, T-023 — the merge engine and dispute detection. Includes Phase
2's actual exit-criteria scenario: four fixture-shaped claims from four
different tools describing the same RSA-2048 key produce one MergeResult
with four occurrences and the correct concluded tier; two contradictory
claims at the same tier produce a disputed result.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from qavach_core.model.enums import AssetType, ConfidenceTier
from qavach_core.model.locus import ContainerLocus, FileLocus, NetworkLocus, SourceLocus
from qavach_core.reconcile.identity import IdentityClaim, asset_identity
from qavach_core.reconcile.merge import OccurrenceClaim, group_by_identity, merge, merge_all

RSA_2048_IDENTITY = asset_identity(
    IdentityClaim(
        asset_type=AssetType.ALGORITHM,
        algorithm_family="RSASSA-PKCS1",
        parameter_set="2048",
        oid="1.2.840.113549.1.1.1",
    )
)


def _occurrence(**overrides: object) -> OccurrenceClaim:
    defaults: dict[str, object] = {
        "identity": RSA_2048_IDENTITY,
        "locus": FileLocus(path="/default", offset=0),
        "collector": "test",
        "tool_version": "1.0",
        "confidence": ConfidenceTier.AST,
        "detection_method": "source-code-analysis",
        "raw_ref": "raw://1",
        "observed_at": datetime(2026, 9, 18, tzinfo=UTC),
    }
    defaults.update(overrides)
    return OccurrenceClaim(**defaults)  # type: ignore[arg-type]


# --- Phase 2's exit criterion, exactly ---


def test_four_tools_same_rsa_2048_key_produce_one_asset_four_occurrences() -> None:
    """The reconciliation layer's whole point, made visible in one test:
    the same RSA-2048 key found by cdxgen (AST), the SBOM mapper
    (DEPENDENCY), the TLS collector (RUNTIME), and a cert-store parse
    (ARTEFACT) is one asset, not four."""
    claims = [
        _occurrence(
            collector="source_scan.cdxgen",
            confidence=ConfidenceTier.AST,
            locus=SourceLocus(repo="r", commit="c", path="Auth.java", start_line=1, end_line=1),
        ),
        _occurrence(
            collector="sbom.syft",
            confidence=ConfidenceTier.DEPENDENCY,
            locus=ContainerLocus(image_digest="sha256:a", layer_digest="sha256:b", path="/lib"),
        ),
        _occurrence(
            collector="tls.endpoint",
            confidence=ConfidenceTier.RUNTIME,
            locus=NetworkLocus(host="example.com", port=443, sni=None, protocol="tls1.2"),
        ),
        _occurrence(
            collector="tls.store",
            confidence=ConfidenceTier.ARTEFACT,
            locus=FileLocus(path="/etc/pki/keystore.jks", offset=0),
        ),
    ]
    results = merge_all(claims)
    assert len(results) == 1
    result = results[0]
    assert result.identity == RSA_2048_IDENTITY
    assert len(result.occurrences) == 4
    assert result.concluded_from == ConfidenceTier.RUNTIME  # highest of the four
    assert not result.disputed


def test_two_contradictory_claims_at_the_same_tier_produce_a_disputed_asset() -> None:
    """Phase 2's second exit criterion, exactly."""
    same_locus = SourceLocus(repo="r", commit="c", path="Crypto.java", start_line=10, end_line=10)
    claims = [
        _occurrence(
            collector="cdxgen", confidence=ConfidenceTier.AST, locus=same_locus, padding="oaep"
        ),
        _occurrence(
            collector="opengrep",
            confidence=ConfidenceTier.AST,
            locus=same_locus,
            padding="pkcs1v15",
        ),
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert result.disputed
    assert len(result.disputes) == 1
    assert result.disputes[0].attribute == "padding"
    assert {c.value for c in result.disputes[0].claims} == {"oaep", "pkcs1v15"}


# --- Occurrences retained, never averaged (invariant I4) ---


def test_all_occurrences_are_retained_never_averaged_or_dropped() -> None:
    claims = [
        _occurrence(collector=f"tool-{i}", locus=FileLocus(path=f"/{i}", offset=0))
        for i in range(5)
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert len(result.occurrences) == 5


def test_merge_rejects_a_mixed_identity_batch() -> None:
    other_identity = asset_identity(
        IdentityClaim(asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="256")
    )
    claims = [_occurrence(), _occurrence(identity=other_identity)]
    with pytest.raises(ValueError, match="share the given identity"):
        merge(RSA_2048_IDENTITY, claims)


def test_merge_requires_at_least_one_occurrence() -> None:
    with pytest.raises(ValueError, match="at least one occurrence"):
        merge(RSA_2048_IDENTITY, [])


# --- Multi-usage is not dispute (A-5) ---


def test_different_loci_with_different_padding_is_multi_usage_not_dispute() -> None:
    """ARCH.md §6.3: 'The same RSA key used with OAEP at one call site and
    PKCS#1 v1.5 at another is two true facts, not a conflict.'"""
    claims = [
        _occurrence(locus=FileLocus(path="/a.java", offset=0), padding="oaep"),
        _occurrence(locus=FileLocus(path="/b.java", offset=0), padding="pkcs1v15"),
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert not result.disputed
    assert result.disputes == ()


def test_silence_is_not_a_claim_does_not_trigger_a_dispute() -> None:
    """A-5: an occurrence that never reported `padding` at all must not be
    treated as disagreeing with one that did."""
    same_locus = FileLocus(path="/x.java", offset=0)
    claims = [
        _occurrence(locus=same_locus, padding="oaep"),
        _occurrence(locus=same_locus, padding=None),  # silent on padding
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert not result.disputed


# --- Attribute-scoped precedence (A-5, ARCH.md §6.4) — the specific
# silent-failure mode the doc calls out by name ---


def test_usage_observing_tier_outranks_attested_for_mode_padding() -> None:
    """The exact scenario ARCH.md §6.4 warns about: an ATTESTED cloud KMS
    API (tier 80) does NOT outrank an AST claim (tier 50) for padding — it
    never observed that attribute at all. Getting this backwards is 'the
    single most likely silent-failure mode in this layer.'"""
    claims = [
        _occurrence(
            collector="cloud.aws", confidence=ConfidenceTier.ATTESTED, padding="declared-oaep"
        ),
        _occurrence(collector="cdxgen", confidence=ConfidenceTier.AST, padding="observed-pkcs1v15"),
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert result.concluded_padding is not None
    assert result.concluded_padding.value == "observed-pkcs1v15"
    assert result.concluded_padding.source_collector == "cdxgen"


def test_runtime_outranks_ast_within_usage_observing_tiers() -> None:
    claims = [
        _occurrence(collector="cdxgen", confidence=ConfidenceTier.AST, mode="cbc"),
        _occurrence(collector="tracebom", confidence=ConfidenceTier.RUNTIME, mode="gcm"),
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert result.concluded_mode is not None
    assert result.concluded_mode.value == "gcm"


def test_concluded_from_uses_the_plain_confidence_tier_ordering() -> None:
    """concluded_from (the asset's OVERALL provenance tier) is distinct
    from the attribute-scoped precedence above — it uses ConfidenceTier's
    plain "higher wins" ordering, where ATTESTED (80) genuinely does
    outrank AST (50)."""
    claims = [
        _occurrence(confidence=ConfidenceTier.AST),
        _occurrence(confidence=ConfidenceTier.ATTESTED),
    ]
    result = merge(RSA_2048_IDENTITY, claims)
    assert result.concluded_from == ConfidenceTier.ATTESTED


def test_concluded_attribute_is_none_when_no_occurrence_reports_it() -> None:
    claims = [_occurrence(mode=None, padding=None)]
    result = merge(RSA_2048_IDENTITY, claims)
    assert result.concluded_mode is None
    assert result.concluded_padding is None


# --- group_by_identity ---


def test_group_by_identity_separates_distinct_assets() -> None:
    aes_identity = asset_identity(
        IdentityClaim(asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="256")
    )
    claims = [_occurrence(), _occurrence(identity=aes_identity)]
    groups = group_by_identity(claims)
    assert len(groups) == 2
    assert len(groups[RSA_2048_IDENTITY]) == 1
    assert len(groups[aes_identity]) == 1
