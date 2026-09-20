"""Runnable entry point: `uvicorn qavach_api.main:app`.

Configuration is environment-only (nothing secret is ever read from a file):

* `QAVACH_DATABASE_URL`  SQLAlchemy URL. Default: a local SQLite file, so the
  API and UI run with no Docker or Postgres (`make dev` uses Postgres).
* `QAVACH_CONFIG_DIR`    the repo `config/` directory (knowledge and policy).
* `QAVACH_DEMO=1`        seed the example systems and run one scan over the
  **recorded real scanner output** (`tests/fixtures/scanner-output/`), so the UI
  has real data to show. Demo data is labelled as such by the API
  (`/api/v1/meta`); it is never presented as a live scan.

* `QAVACH_REDIS_URL`     if set, scans are queued to RQ and run by a separate worker
  (`python -m qavach_worker`); unset, they run on an in-process thread pool.
* `QAVACH_AGENT_CA_DIR`  where the agent-credential CA key lives (created on first
  enrolment, mode 0600). Default `dist/agent-ca`.
* `QAVACH_API_TOKEN`     if set (>= 16 chars), every route but `/api/v1/meta`
  requires `Authorization: Bearer <token>` (`qavach_api.auth`). If unset there is
  **no authentication**: bind to localhost only and do not expose it.
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Any

from fastapi.middleware.cors import CORSMiddleware
from qavach_collectors import CollectorRegistry, Target, TargetType
from qavach_storage import Repository, create_all, make_engine, schema_drift, session_factory
from qavach_worker.config import load_deps, production_deps

from qavach_api.agent_ca import AgentCA
from qavach_api.app import AppState, create_app
from qavach_api.auth import BearerAuth


def repository_ref_policy(workspace: Any) -> Any:
    """A deployed QAVACH scans git URLs it clones itself. A bare filesystem path is
    accepted only if it is inside the workspace or `QAVACH_ALLOW_LOCAL_PATHS=1`
    (development), so the API cannot be asked to read arbitrary host directories."""
    allow_local = os.environ.get("QAVACH_ALLOW_LOCAL_PATHS") == "1"

    def check(ref: str) -> str | None:
        if workspace is not None and workspace.wants(Target(TargetType.REPOSITORY, ref)):
            return None
        if allow_local:
            return None
        if workspace is not None:
            path = Path(ref).resolve()
            if workspace.root.resolve() in path.parents:
                return None
        return (
            "a repository target must be a git URL (https://, ssh://, git@host:path); "
            "local paths are refused unless QAVACH_ALLOW_LOCAL_PATHS=1"
        )

    return check


def build_app() -> Any:
    root = Path(__file__).resolve().parents[4]
    config = Path(os.environ.get("QAVACH_CONFIG_DIR", root / "config"))
    url = os.environ.get("QAVACH_DATABASE_URL", f"sqlite:///{root / 'dist' / 'qavach-dev.db'}")
    demo = os.environ.get("QAVACH_DEMO") == "1"
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

    engine = make_engine(url)
    create_all(engine)
    drift = schema_drift(engine)
    if drift:
        default_dev_db = "QAVACH_DATABASE_URL" not in os.environ
        if demo and default_dev_db:
            # A disposable demo database from an older build: rebuild it.
            engine.dispose()
            Path(url.removeprefix("sqlite:///")).unlink(missing_ok=True)
            engine = make_engine(url)
            create_all(engine)
        else:
            raise RuntimeError(
                "the database schema is out of date "
                f"({'; '.join(drift[:5])}). Run `alembic upgrade head` "
                "(packages/storage) or point QAVACH_DATABASE_URL at a fresh database."
            )
    registry = CollectorRegistry()
    meta: dict[str, Any] = {"demo": demo, "collectors": [], "auth": "none"}

    if demo:
        from qavach_api.demo import register_replay_collectors, seed_demo

        deps = load_deps(config, registry)
        register_replay_collectors(root, deps)
        meta["collectors"] = sorted(c.name for c in registry)
        meta["demo_note"] = (
            "Demo mode: scans replay recorded real scanner output "
            "(tests/fixtures/scanner-output/); no live scanning happens."
        )
    else:
        deps, skipped = production_deps(config)
        meta["collectors"] = sorted(c.name for c in deps.registry)
        meta["collectors_skipped"] = skipped

    ca_dir = Path(os.environ.get("QAVACH_AGENT_CA_DIR", root / "dist" / "agent-ca"))
    redis_url = os.environ.get("QAVACH_REDIS_URL")
    enqueue = None
    if redis_url:
        from qavach_worker.queue import enqueue_scan

        def enqueue(payload: dict[str, Any]) -> None:  # noqa: F811
            enqueue_scan(redis_url, payload)

        meta["queue"] = "rq"
    state = AppState(
        session_factory=session_factory(engine),
        deps=deps,
        enqueue=enqueue,
        workspace_policy=None if demo else repository_ref_policy(deps.workspace),
        agent_ca=lambda: AgentCA.load_or_create(ca_dir),
    )
    app = create_app(state)
    token = os.environ.get("QAVACH_API_TOKEN")
    if token:
        app.add_middleware(BearerAuth, token=token)
        meta["auth"] = "bearer"
    # Added after the auth middleware so CORS is outermost and answers
    # preflight (which carries no credentials) before auth sees it.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/meta")
    def get_meta() -> dict[str, Any]:
        return meta

    if demo:
        with state.session_factory() as session:
            if not Repository(session).load_systems()[0]:
                seed_demo(session, state, root)
    return app


app = build_app()
_ = date  # noqa: F841
