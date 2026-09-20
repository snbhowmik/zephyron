"""RQ wiring against a real Redis (`make dev`): the API enqueues, a separate worker
executes `run_scan`, and progress is derived from the persisted stages.

Uses the external-CBOM collector (no container needed) so the job is quick, and a
file-backed SQLite database because the API and the worker are separate sessions."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from redis import Redis
from rq import Queue, SimpleWorker

REDIS_URL = os.environ.get("QAVACH_TEST_REDIS_URL", "redis://localhost:6379/15")
ROOT = Path(__file__).parent.parent.parent
CBOM = ROOT / "tests/fixtures/scanner-output/cbomkit/polyglot.cdx.json"


def _redis_up() -> bool:
    try:
        return bool(Redis.from_url(REDIS_URL).ping())
    except Exception:  # noqa: BLE001
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _redis_up(), reason="no Redis (run `make dev`)"),
]


def test_a_queued_scan_runs_in_the_worker_and_reports_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qavach_api.main import build_app
    from qavach_worker import jobs
    from qavach_worker.queue import QUEUE_NAME

    monkeypatch.setenv("QAVACH_DATABASE_URL", f"sqlite:///{tmp_path / 'q.db'}")
    monkeypatch.setenv("QAVACH_REDIS_URL", REDIS_URL)
    monkeypatch.setenv("QAVACH_AGENT_CA_DIR", str(tmp_path / "ca"))
    monkeypatch.delenv("QAVACH_DEMO", raising=False)
    jobs._process_deps.cache_clear()
    connection = Redis.from_url(REDIS_URL)
    connection.flushdb()

    client = TestClient(build_app())
    assert client.get("/api/v1/meta").json()["queue"] == "rq"
    r = client.post("/api/v1/scans", json={"target_type": "cbom-upload", "target_ref": str(CBOM)})
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]

    # not run yet: the API only enqueued it
    queue = Queue(QUEUE_NAME, connection=connection)
    assert queue.count == 1
    assert client.get(f"/api/v1/scans/{scan_id}").json()["summary"] in ({}, None)

    SimpleWorker([queue], connection=connection).work(burst=True)

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] in {"complete", "partial"}, scan
    assert scan["summary"]["assets"] > 0
    with client.websocket_connect(f"/api/v1/scans/{scan_id}/progress") as ws:
        events = []
        while True:
            e = ws.receive_json()
            events.append(e)
            if e["stage"] == "scan":
                break
    stages = [e["stage"] for e in events if e["status"] == "finished"]
    assert stages[:3] == ["collect", "assemble", "context"] and "persist" in stages
    assert uuid.UUID(scan_id)
