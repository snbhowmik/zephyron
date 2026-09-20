"""The scan job as RQ runs it: a plain, JSON-serialisable payload in, `run_scan`
out. The worker process builds its own deps (knowledge, policy, real collector
registry) and database session from the environment, exactly as the API does, so
a queued scan is indistinguishable from an in-process one except for where it ran.
"""

from __future__ import annotations

import os
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

from qavach_collectors import Target, TargetType
from qavach_storage import make_engine, session_factory

from qavach_worker.config import config_dir, production_deps
from qavach_worker.pipeline import Deps, ScanRequest, run_scan
from qavach_worker.simulate import warm_simulation_cache

_ROOT = Path(__file__).resolve().parents[4]


def to_payload(request: ScanRequest) -> dict[str, Any]:
    return {
        "scan_id": request.scan_id,
        "target_type": request.target.type.value,
        "target_ref": request.target.ref,
        "options": dict(request.target.options),
        "z_scenario": request.z_scenario,
        "as_of": request.as_of.isoformat() if request.as_of else None,
        "capacity_per_quarter": request.capacity_per_quarter,
        "actor": request.actor,
    }


def from_payload(payload: dict[str, Any]) -> ScanRequest:
    return ScanRequest(
        target=Target(
            type=TargetType(payload["target_type"]),
            ref=payload["target_ref"],
            options=dict(payload.get("options") or {}),
        ),
        scan_id=payload["scan_id"],
        z_scenario=payload.get("z_scenario"),
        as_of=date.fromisoformat(payload["as_of"]) if payload.get("as_of") else None,
        capacity_per_quarter=payload.get("capacity_per_quarter"),
        actor=payload.get("actor", "worker"),
    )


@lru_cache(maxsize=1)
def _process_deps() -> Deps:
    return production_deps(config_dir(_ROOT))[0]


def execute_scan_job(payload: dict[str, Any]) -> None:
    """Entry point RQ calls. Failures are recorded on the scan by `run_scan`."""
    engine = make_engine(os.environ["QAVACH_DATABASE_URL"])
    deps = _process_deps()
    request = from_payload(payload)
    with session_factory(engine)() as session:
        run_scan(session, request, deps)
        warm_simulation_cache(session, request.scan_id, deps.knowledge)
