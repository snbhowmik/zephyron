"""T-060, T-068 - every policy value is cited, and a snapshot is a frozen,
hashable value scores are computed against."""

from __future__ import annotations

import copy
import json
from datetime import date

import pytest
from _policy import load_documents, real_policy
from qavach_core.policy import PolicyError, PolicySnapshot


def test_every_value_in_the_shipped_policy_files_is_cited() -> None:
    snapshot = real_policy()  # the loader rejects anything uncited
    nodes = list(snapshot.iter_nodes())
    assert len(nodes) > 40
    assert all(n.basis.strip() for n in nodes)


def test_every_deadline_declares_kind_binding_and_scope() -> None:
    for name, node in real_policy().nodes("regulatory_deadlines.deadlines").items():
        assert node.fields["kind"] in {"migration", "inventory"}, name
        assert isinstance(node.fields["binding"], bool), name
        assert node.fields["scope"], name
        date.fromisoformat(str(node.fields["date"]))


def test_all_three_z_scenarios_are_cited_and_a_default_is_named() -> None:
    snap = real_policy()
    assert set(snap.nodes("z_scenarios.scenarios")) == {"aggressive", "nominal", "conservative"}
    assert snap.value("z_scenarios.default") in {"aggressive", "nominal", "conservative"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["scoring"]["mosca"].__setitem__("bare", 3),
        lambda d: d["scoring"]["mosca"]["imminent_within_years"].__setitem__("basis", ""),
        lambda d: d["scoring"]["mosca"]["imminent_within_years"].pop("basis"),
        lambda d: d["scoring"].__setitem__("empty", {}),
        lambda d: d["scoring"]["mosca"].__setitem__("listy", [1, 2]),
    ],
)
def test_an_uncited_or_malformed_value_is_rejected_at_load(mutate) -> None:  # type: ignore[no-untyped-def]
    docs = copy.deepcopy(load_documents())
    mutate(docs)
    with pytest.raises(PolicyError):
        PolicySnapshot.from_documents(docs)


def test_the_snapshot_id_is_stable_and_changes_with_any_value() -> None:
    a, b = real_policy(), real_policy()
    assert a.snapshot_id == b.snapshot_id and len(a.snapshot_id) == 64
    docs = copy.deepcopy(load_documents())
    docs["scoring"]["caraf"]["exposure_internet_facing"]["value"] = 1.6
    assert PolicySnapshot.from_documents(docs).snapshot_id != a.snapshot_id


def test_the_snapshot_round_trips_through_json_byte_for_byte() -> None:
    snap = real_policy()
    again = PolicySnapshot.from_json(snap.canonical_json())
    assert again.canonical_json() == snap.canonical_json()
    assert again.snapshot_id == snap.snapshot_id
    json.loads(snap.canonical_json())  # dates were canonicalised to strings


def test_key_order_in_the_source_never_changes_the_id() -> None:
    docs = load_documents()
    reordered = {k: docs[k] for k in reversed(list(docs))}
    assert PolicySnapshot.from_documents(reordered).snapshot_id == real_policy().snapshot_id


def test_paths_resolve_and_bad_paths_fail_loudly() -> None:
    snap = real_policy()
    assert snap.node("scoring.caraf.exposure_internet_facing").value == 1.5
    with pytest.raises(PolicyError):
        snap.node("scoring.nope")
    with pytest.raises(PolicyError, match="container"):
        snap.node("scoring.caraf")
