"""`python -m qavach_worker` - run an RQ worker for scan jobs.

Needs `QAVACH_REDIS_URL` and `QAVACH_DATABASE_URL`."""

from qavach_worker.queue import run_worker

if __name__ == "__main__":
    run_worker()
