"""Alembic environment. The database URL is read from `QAVACH_DATABASE_URL`
(never from a committed file), and `target_metadata` is the models' metadata so
`alembic revision --autogenerate` sees every table."""

from __future__ import annotations

import os

from alembic import context
from qavach_storage.models import Base
from sqlalchemy import create_engine, pool

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    url = os.environ.get("QAVACH_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("set QAVACH_DATABASE_URL to run migrations")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
