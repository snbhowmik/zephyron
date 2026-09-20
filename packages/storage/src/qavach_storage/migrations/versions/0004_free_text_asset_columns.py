"""free-text asset columns: VARCHAR(n) -> TEXT

Revision ID: 0004
Revises: 0003

Postgres enforces VARCHAR(n) and SQLite does not, so a long algorithm spelling in real
scanner output would have failed only on Postgres, mid-scan. These columns hold whatever a
tool reported, so they carry no arbitrary length limit.
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_COLUMNS = {
    "family": (sa.String(128), False),
    "parameter_set": (sa.String(64), True),
    "curve": (sa.String(128), True),
    "mode": (sa.String(32), True),
    "padding": (sa.String(32), True),
    "oid": (sa.String(128), True),
}


def upgrade() -> None:
    with op.batch_alter_table("crypto_assets") as batch:
        for name, (old, nullable) in _COLUMNS.items():
            batch.alter_column(name, existing_type=old, type_=sa.Text(), existing_nullable=nullable)


def downgrade() -> None:
    with op.batch_alter_table("crypto_assets") as batch:
        for name, (old, nullable) in _COLUMNS.items():
            batch.alter_column(name, existing_type=sa.Text(), type_=old, existing_nullable=nullable)
