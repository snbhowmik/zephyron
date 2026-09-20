"""Demo mode: replay the recorded real scanner output through the real pipeline.

Nothing here fabricates a finding. The collectors are the real ones - their real
*parsers* run over output recorded from the real tools (`tests/fixtures/
scanner-output/`, T-024) - so the demo exercises the same normalisation,
reconciliation, scoring, recommendation, roadmap and export code as a live scan.
Only the *acquisition* is replayed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest import mock

from qavach_collectors import CollectorResult, RunContext, Target, TargetType
from qavach_core.context import parse_systems_csv
from qavach_core.model.enums import ConfidenceTier
from qavach_storage import Repository
from qavach_worker import Deps, ScanRequest, run_scan
from sqlalchemy.orm import Session


class ReplayCollector:
    requires_sandbox = False
    requires_network = False
    default_confidence = ConfidenceTier.AST

    def __init__(self, result: CollectorResult) -> None:
        self._result = result
        self.name = result.tool.name
        self.version = result.tool.version

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        return self._result


def register_replay_collectors(root: Path, deps: Deps) -> None:
    sys.path.insert(0, str(root / "scripts"))
    import demo as demo_script  # type: ignore[import-not-found]

    with mock.patch.object(demo_script, "ROOT", root):
        for result in demo_script.replay_results(deps.knowledge):
            deps.registry.register(ReplayCollector(result))


def seed_demo(session: Session, state: Any, root: Path) -> None:
    repo = Repository(session)
    repo.replace_systems(
        parse_systems_csv((root / "tests/fixtures/demo/systems.csv").read_text(), state.deps.policy)
    )
    session.commit()
    run_scan(
        session,
        ScanRequest(
            target=Target(type=TargetType.REPOSITORY, ref="github.com/acme/polyglot-payments"),
            scan_id="demo-scan",
            capacity_per_quarter=4,
            actor="demo",
        ),
        state.deps,
    )
