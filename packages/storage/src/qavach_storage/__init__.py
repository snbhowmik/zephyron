"""SQLAlchemy models, repositories and Alembic migrations. See ARCH.md §11."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
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


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


__all__ = [
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
