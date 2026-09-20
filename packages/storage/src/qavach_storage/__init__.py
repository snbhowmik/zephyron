"""SQLAlchemy models, repositories and Alembic migrations. See ARCH.md §11."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from qavach_storage import models
from qavach_storage.agents import AgentRepository, as_utc
from qavach_storage.models import Base
from qavach_storage.repository import (
    UNASSIGNED,
    AssetFilter,
    AssetPage,
    Repository,
    asset_id_for,
    row_to_asset,
)


def make_engine(url: str) -> Engine:
    return create_engine(url, future=True)


def create_all(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def schema_drift(engine: Engine) -> list[str]:
    """Tables and columns the models declare that the database lacks.

    `create_all` only creates missing *tables*; it never adds a column to an
    existing one, so a database made by an older build looks fine until a write
    touches the new column and fails mid-scan. Checking at startup turns that into
    one clear message. (Production runs Alembic; this guards the dev/demo path.)
    """
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    problems: list[str] = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            problems.append(f"missing table {table.name}")
            continue
        have = {c["name"] for c in inspector.get_columns(table.name)}
        problems += [f"{table.name}.{c.name} missing" for c in table.columns if c.name not in have]
    return problems


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


__all__ = [
    "schema_drift",
    "AgentRepository",
    "as_utc",
    "UNASSIGNED",
    "AssetFilter",
    "AssetPage",
    "Base",
    "Repository",
    "asset_id_for",
    "create_all",
    "make_engine",
    "models",
    "row_to_asset",
    "session_factory",
]
