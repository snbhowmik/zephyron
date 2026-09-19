"""T-075's budget at scale: `policy/simulate` over 50,000 stored assets."""

from __future__ import annotations

import importlib.util
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from qavach_core.context import parse_systems_csv
from qavach_storage import Repository, create_all, make_engine, models, session_factory
from qavach_worker import simulate
from sqlalchemy import insert

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/demo.py")
assert _spec and _spec.loader
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)
KNOWLEDGE, POLICY, _ = demo.load_knowledge()
NOW = datetime(2026, 9, 20, tzinfo=UTC)


def _seed(n: int):  # type: ignore[no-untyped-def]
    engine = make_engine("sqlite://")
    create_all(engine)
    session = session_factory(engine)()
    repo = Repository(session)
    repo.replace_systems(
        parse_systems_csv((ROOT / "tests/fixtures/demo/systems.csv").read_text(), POLICY)
    )
    repo.create_scan(
        scan_id="big",
        target_ref="t",
        policy=POLICY,
        z_scenario="nominal",
        as_of="2026-09-20",
        now=NOW,
    )
    classes = ["quantum-vulnerable", "classical-weak", "grover-affected", "quantum-safe", "unknown"]
    functions = ["signature", "key-agreement", "encryption", "hash", "key-encapsulation"]
    session.execute(
        insert(models.CryptoAssetRow),
        [
            {
                "id": f"a{i}",
                "scan_run_id": "big",
                "identity_kind": "algo",
                "identity_key": f"{i:064x}",
                "asset_type": "algorithm",
                "function": functions[i % 5],
                "family": "RSASSA-PKCS1",
                "parameter_set": "2048",
                "curve": None,
                "mode": None,
                "padding": None,
                "oid": None,
                "finding_class": classes[i % 5],
                "migration_authority": "self",
                "authority_basis": "b",
                "concluded_tier": 50,
                "disputed": False,
                "disputes_json": [],
            }
            for i in range(n)
        ],
    )
    locus = {"locus_type": "file", "path": "a.py", "offset": 1}
    session.execute(
        insert(models.OccurrenceRow),
        [
            {
                "asset_id": f"a{i}",
                "collector": "c",
                "tool_version": "1",
                "locus_type": "file",
                "locus_json": locus,
                "confidence": 50,
                "detection_method": "ast",
                "raw_ref": "r",
                "observed_at": NOW,
            }
            for i in range(n)
        ],
    )
    session.execute(
        insert(models.AssetSystem),
        [{"asset_id": f"a{i}", "system_id": "payments-core", "basis_json": []} for i in range(n)],
    )
    session.execute(
        insert(models.RiskScoreRow),
        [
            {
                "asset_id": f"a{i}",
                "system_id": "payments-core",
                "scan_run_id": "big",
                "policy_snapshot_id": "p",
                "band": "planned",
                "outcome": None,
                "reason": "r",
                "mosca_gap": 0.0,
                "ev": 1.0,
                "z_effective": "2028-12-31",
                "z_source": "x",
                "entry_json": {},
            }
            for i in range(n)
        ],
    )
    session.commit()
    return session


def test_simulating_fifty_thousand_stored_assets_end_to_end() -> None:
    session = _seed(50_000)
    start = time.perf_counter()
    result = simulate(session, "big", overrides={}, z_scenario="aggressive", knowledge=KNOWLEDGE)
    total = time.perf_counter() - start
    assert result["scored"] == 50_000
    print(
        f"\nsimulate over 50,000 stored assets: {total:.2f}s end to end "  # noqa: T201
        f"({result['scoring_ms']:.0f} ms of it scoring)"
    )
    assert total < 15, (
        f"{total:.1f}s"
    )  # loose CI ceiling; the measured figure is recorded in NOTE.md
    assert result["scoring_ms"] < 2500
