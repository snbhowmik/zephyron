"""Runnable entry point: `uvicorn qavach_api.main:app`.

Configuration is environment-only (nothing secret is ever read from a file):

* `QAVACH_DATABASE_URL`  SQLAlchemy URL. Default: a local SQLite file, so the
  API and UI run with no Docker or Postgres (`make dev` uses Postgres).
* `QAVACH_CONFIG_DIR`    the repo `config/` directory (knowledge and policy).
* `QAVACH_DEMO=1`        seed the example systems and run one scan over the
  **recorded real scanner output** (`tests/fixtures/scanner-output/`), so the UI
  has real data to show. Demo data is labelled as such by the API
  (`/api/v1/meta`); it is never presented as a live scan.

* `QAVACH_AGENT_CA_DIR`  where the agent-credential CA key lives (created on first
  enrolment, mode 0600). Default `dist/agent-ca`.
* `QAVACH_API_TOKEN`     if set (>= 16 chars), every route but `/api/v1/meta`
  requires `Authorization: Bearer <token>` (`qavach_api.auth`). If unset there is
  **no authentication**: bind to localhost only and do not expose it.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi.middleware.cors import CORSMiddleware
from qavach_collectors import CollectorRegistry
from qavach_core.normalize import AliasTable, CryptographyRegistry
from qavach_core.pipeline import AssembleKnowledge, FamilyFunctions
from qavach_core.policy import PolicySnapshot
from qavach_core.recommend import PqcKnowledge
from qavach_core.risk import ClassificationRules
from qavach_storage import Repository, create_all, make_engine, session_factory
from qavach_worker import Deps

from qavach_api.agent_ca import AgentCA
from qavach_api.app import AppState, create_app
from qavach_api.auth import BearerAuth

POLICY_DOCS = (
    "z_scenarios",
    "regulatory_deadlines",
    "scoring",
    "risk_tolerance",
    "migration_effort",
    "retention_defaults",
)


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def load_deps(config: Path, registry: CollectorRegistry) -> Deps:
    knowledge = config / "knowledge"
    return Deps(
        registry=registry,
        knowledge=AssembleKnowledge(
            registry=CryptographyRegistry.from_dict(
                json.loads(
                    (knowledge / "cdx-crypto-registry" / "cryptography-defs.json").read_text()
                )
            ),
            aliases=AliasTable.from_dict(_yaml(knowledge / "aliases.yaml")),
            rules=ClassificationRules.from_dict(_yaml(knowledge / "classification_rules.yaml")),
            family_functions=FamilyFunctions.from_dict(_yaml(knowledge / "family_functions.yaml")),
        ),
        policy=PolicySnapshot.from_documents(
            {n: _yaml(config / "policy" / f"{n}.yaml") for n in POLICY_DOCS}
        ),
        pqc=PqcKnowledge.from_documents(
            _yaml(knowledge / "pqc_alternatives.yaml"), _yaml(knowledge / "performance.yaml")
        ),
        clock=lambda: datetime.now(UTC),
    )


def build_app() -> Any:
    root = Path(__file__).resolve().parents[4]
    config = Path(os.environ.get("QAVACH_CONFIG_DIR", root / "config"))
    url = os.environ.get("QAVACH_DATABASE_URL", f"sqlite:///{root / 'dist' / 'qavach-dev.db'}")
    demo = os.environ.get("QAVACH_DEMO") == "1"
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

    engine = make_engine(url)
    create_all(engine)
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
        deps = load_deps(config, registry)

    ca_dir = Path(os.environ.get("QAVACH_AGENT_CA_DIR", root / "dist" / "agent-ca"))
    state = AppState(
        session_factory=session_factory(engine),
        deps=deps,
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
