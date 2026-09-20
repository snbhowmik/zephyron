"""RQ plumbing: enqueue from the API, run a worker with `python -m qavach_worker`."""

from __future__ import annotations

import os
from typing import Any

from redis import Redis
from rq import Queue, Worker

QUEUE_NAME = "qavach-scans"
JOB_TIMEOUT_SECONDS = 3600


def enqueue_scan(redis_url: str, payload: dict[str, Any]) -> str:
    queue = Queue(QUEUE_NAME, connection=Redis.from_url(redis_url))
    job = queue.enqueue(
        "qavach_worker.jobs.execute_scan_job",
        payload,
        job_timeout=JOB_TIMEOUT_SECONDS,
        result_ttl=3600,
        failure_ttl=86400,
    )
    return str(job.id)


def run_worker(redis_url: str | None = None, *, burst: bool = False) -> None:
    connection = Redis.from_url(redis_url or os.environ["QAVACH_REDIS_URL"])
    Worker([Queue(QUEUE_NAME, connection=connection)], connection=connection).work(burst=burst)
