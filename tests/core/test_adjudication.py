"""T-025 — an operator's ruling on a dispute survives re-scan, and stops
applying (visibly, never silently) when it no longer answers the question."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from qavach_core.model.enums import AssetType, ConfidenceTier
from qavach_core.model.locus import FileLocus
from qavach_core.reconcile import (
    Adjudication,
    IdentityClaim,
    OccurrenceClaim,
    adjudicate,
    adjudication_from_dict,
    adjudication_to_dict,
    apply_adjudications,
    asset_identity,
    merge_all,
)

AES = asset_identity(
    IdentityClaim(asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="256")
)
OTHER = asset_identity(
    IdentityClaim(asset_type=AssetType.ALGORITHM, algorithm_family="AES", parameter_set="128")
)
T0 = datetime(2026, 9, 19, 9, 0, tzinfo=UTC)
LOCUS = FileLocus(path="src/pay.c", offset=42)


def claim(
    collector: str,
    tier: ConfidenceTier,
    mode: str | None,
    *,
    identity=AES,  # type: ignore[no-untyped-def]
    locus=LOCUS,  # type: ignore[no-untyped-def]
) -> OccurrenceClaim:
    return OccurrenceClaim(
        identity=identity,
        locus=locus,
        collector=collector,
        tool_version="1",
        confidence=tier,
        detection_method="x",
        raw_ref="r",
        observed_at=T0,
        mode=mode,
    )


def disputed_scan() -> list:  # type: ignore[type-arg]
    return merge_all(
        [
            claim("source_scan.cbomkit", ConfidenceTier.AST, "gcm"),
            claim("source_scan.opengrep", ConfidenceTier.PATTERN, "cbc"),
        ]
    )


def ruling(value: str = "gcm") -> Adjudication:
    return adjudicate(
        disputed_scan()[0], "mode", value, by="ops@example", at=T0, reason="reviewed pay.c:42"
    )


def test_a_dispute_is_open_until_ruled_on() -> None:
    result = disputed_scan()[0]
    assert result.disputed and len(result.unresolved_disputes) == 1


def test_ruling_resolves_the_dispute_and_keeps_both_claim_records() -> None:
    outcome = apply_adjudications(disputed_scan(), [ruling("gcm")])
    result = outcome.results[0]
    assert outcome.applied and not outcome.reopened and not outcome.orphaned
    assert not result.disputed and result.unresolved_disputes == ()
    dispute = result.disputes[0]
    assert dispute.resolved and dispute.adjudicated_value == "gcm"
    assert dispute.adjudicated_by == "ops@example" and dispute.adjudication_reason
    assert {c.value for c in dispute.claims} == {"gcm", "cbc"}  # I4: nothing discarded
    assert result.concluded_mode is not None
    assert result.concluded_mode.value == "gcm"
    assert result.concluded_mode.source_collector == "adjudication"


def test_the_operator_can_overrule_the_higher_tier_tool() -> None:
    """The point of adjudicating: the AST tool said gcm, the operator read
    the code and it is cbc. The ruling wins, and the concluded confidence is
    the evidence's actual strength (PATTERN), not an invented operator tier."""
    outcome = apply_adjudications(disputed_scan(), [ruling("cbc")])
    concluded = outcome.results[0].concluded_mode
    assert concluded is not None
    assert (concluded.value, concluded.confidence) == ("cbc", ConfidenceTier.PATTERN)


def test_survives_a_rescan_that_reproduces_the_same_disagreement() -> None:
    saved = adjudication_from_dict(json.loads(json.dumps(adjudication_to_dict(ruling()))))
    rescanned = disputed_scan()  # brand-new merge results, same claims
    outcome = apply_adjudications(rescanned, [saved])
    assert outcome.applied == (saved,) and not outcome.results[0].disputed


def test_a_new_conflicting_value_reopens_the_dispute() -> None:
    rescan = merge_all(
        [
            claim("source_scan.cbomkit", ConfidenceTier.AST, "gcm"),
            claim("source_scan.opengrep", ConfidenceTier.PATTERN, "cbc"),
            claim("runtime.tracebom", ConfidenceTier.RUNTIME, "ecb"),
        ]
    )
    outcome = apply_adjudications(rescan, [ruling()])
    assert outcome.applied == () and len(outcome.reopened) == 1
    assert "ecb" in outcome.reopened[0].reason
    assert outcome.results[0].disputed  # fails safe: still open


def test_a_ruling_for_a_value_no_tool_reports_any_more_reopens() -> None:
    three_way = merge_all(
        [
            claim("a", ConfidenceTier.AST, "gcm"),
            claim("b", ConfidenceTier.PATTERN, "cbc"),
            claim("c", ConfidenceTier.PATTERN, "ecb"),
        ]
    )
    adj = adjudicate(three_way[0], "mode", "gcm", by="o", at=T0, reason="r")
    # The code changed: nothing reports gcm any more, cbc and ecb still clash.
    rescan = merge_all(
        [claim("b", ConfidenceTier.PATTERN, "cbc"), claim("c", ConfidenceTier.PATTERN, "ecb")]
    )
    outcome = apply_adjudications(rescan, [adj])
    assert outcome.applied == () and len(outcome.reopened) == 1
    assert "no longer reported" in outcome.reopened[0].reason
    assert outcome.results[0].disputed


def test_when_the_tools_stop_disagreeing_the_ruling_is_orphaned_not_dropped() -> None:
    agreed = merge_all(
        [
            claim("source_scan.cbomkit", ConfidenceTier.AST, "gcm"),
            claim("source_scan.opengrep", ConfidenceTier.PATTERN, "gcm"),
        ]
    )
    outcome = apply_adjudications(agreed, [ruling()])
    assert outcome.applied == () and len(outcome.orphaned) == 1
    assert "no longer disagree" in outcome.orphaned[0].reason


def test_when_the_asset_disappears_the_ruling_is_orphaned() -> None:
    other = merge_all([claim("a", ConfidenceTier.AST, "gcm", identity=OTHER)])
    outcome = apply_adjudications(other, [ruling()])
    assert len(outcome.orphaned) == 1 and "no longer present" in outcome.orphaned[0].reason
    assert outcome.results == tuple(other)


def test_a_narrower_conflict_still_honours_the_ruling() -> None:
    three_way = merge_all(
        [
            claim("a", ConfidenceTier.AST, "gcm"),
            claim("b", ConfidenceTier.PATTERN, "cbc"),
            claim("c", ConfidenceTier.PATTERN, "ecb"),
        ]
    )
    adj = adjudicate(three_way[0], "mode", "gcm", by="o", at=T0, reason="r")
    assert adj.reviewed_values == {"gcm", "cbc", "ecb"}
    outcome = apply_adjudications(disputed_scan(), [adj])  # ecb went away
    assert outcome.applied == (adj,)


def test_the_latest_ruling_on_a_dispute_wins_and_the_older_is_superseded() -> None:
    first, second = (
        ruling("gcm"),
        adjudicate(
            disputed_scan()[0],
            "mode",
            "cbc",
            by="lead@example",
            at=T0 + timedelta(hours=1),
            reason="r2",
        ),
    )
    outcome = apply_adjudications(disputed_scan(), [second, first])
    assert outcome.superseded == (first,)
    assert outcome.results[0].concluded_mode.value == "cbc"  # type: ignore[union-attr]


def test_two_conflicting_rulings_with_the_same_timestamp_are_refused() -> None:
    a = ruling("gcm")
    b = adjudicate(disputed_scan()[0], "mode", "cbc", by="o2", at=T0, reason="r")
    with pytest.raises(ValueError, match="same timestamp"):
        apply_adjudications(disputed_scan(), [a, b])


def test_ruling_on_one_attribute_leaves_the_other_open() -> None:
    def padded(mode: str, padding: str, collector: str, tier: ConfidenceTier) -> OccurrenceClaim:
        return OccurrenceClaim(
            identity=AES,
            locus=LOCUS,
            collector=collector,
            tool_version="1",
            confidence=tier,
            detection_method="x",
            raw_ref="r",
            observed_at=T0,
            mode=mode,
            padding=padding,
        )

    results = merge_all(
        [
            padded("gcm", "pkcs7", "a", ConfidenceTier.AST),
            padded("cbc", "oaep", "b", ConfidenceTier.PATTERN),
        ]
    )
    assert len(results[0].disputes) == 2
    adj = adjudicate(results[0], "mode", "gcm", by="o", at=T0, reason="r")
    result = apply_adjudications(results, [adj]).results[0]
    assert result.disputed  # padding still open
    assert [d.attribute for d in result.unresolved_disputes] == ["padding"]


def test_guards_on_building_a_ruling() -> None:
    result = disputed_scan()[0]
    with pytest.raises(ValueError, match="not reported by any tool"):
        adjudicate(result, "mode", "ctr", by="o", at=T0, reason="r")
    with pytest.raises(ValueError, match="no unresolved dispute"):
        adjudicate(result, "padding", "oaep", by="o", at=T0, reason="r")
    resolved = apply_adjudications([result], [ruling()]).results[0]
    with pytest.raises(ValueError, match="no unresolved dispute"):
        adjudicate(resolved, "mode", "gcm", by="o", at=T0, reason="r")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"adjudicated_by": " "},
        {"reason": ""},
        {"value": " "},
        {"attribute": "digest"},
        {"adjudicated_at": datetime(2026, 9, 19)},
        {"reviewed_values": frozenset({"cbc"})},
    ],
)
def test_an_adjudication_must_be_attributable_reasoned_and_consistent(
    kwargs: dict[str, object],
) -> None:
    base: dict[str, object] = {
        "identity": AES,
        "attribute": "mode",
        "value": "gcm",
        "reviewed_values": frozenset({"gcm", "cbc"}),
        "adjudicated_by": "o",
        "adjudicated_at": T0,
        "reason": "r",
    }
    with pytest.raises(ValueError):
        Adjudication(**{**base, **kwargs})  # type: ignore[arg-type]


def test_serialisation_round_trips_and_is_json_safe() -> None:
    adj = ruling()
    encoded = json.dumps(adjudication_to_dict(adj), sort_keys=True)
    assert adjudication_from_dict(json.loads(encoded)) == adj


def test_no_adjudications_is_a_no_op_that_preserves_order() -> None:
    results = merge_all(
        [
            claim("a", ConfidenceTier.AST, "gcm"),
            claim("a", ConfidenceTier.AST, "cbc", identity=OTHER),
        ]
    )
    outcome = apply_adjudications(results, [])
    assert outcome.results == tuple(results) and outcome.applied == ()
