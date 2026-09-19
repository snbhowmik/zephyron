"""SQLAlchemy 2.0 models per `ARCH.md §11`. T-070.

Portable types only, so the same models run on Postgres 16 (production) and on
SQLite (unit tests, no service needed - `make test-unit` must pass with no
Docker): `JSON` with a `JSONB` variant on Postgres, string ids, no
Postgres-only column types.

`scan_runs.policy_snapshot_json` stores the **entire** policy used for a run
(ARCH.md §11, NFR-09): a score is only reproducible six months later if it can
be recomputed against exactly that policy, so scores are never computed against
"current" policy.

Indexes follow the queries the inventory view actually makes (facet on finding
class, band, authority, system, disputed; filter on family) because the
inventory must return in under 500 ms at 50k assets.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

Json = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_ref: Mapped[str] = mapped_column(Text)
    started: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), index=True)
    policy_snapshot_id: Mapped[str] = mapped_column(String(64))
    policy_snapshot_json: Mapped[dict[str, Any]] = mapped_column(Json)
    z_scenario: Mapped[str] = mapped_column(String(64))
    as_of: Mapped[str] = mapped_column(String(10))
    summary_json: Mapped[dict[str, Any] | None] = mapped_column(Json)
    stages_json: Mapped[dict[str, Any] | None] = mapped_column(Json)


class CollectorRun(Base):
    __tablename__ = "collector_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    collector: Mapped[str] = mapped_column(String(64))
    tool_version: Mapped[str] = mapped_column(String(64))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    raw_uri: Mapped[str | None] = mapped_column(Text)
    partial: Mapped[bool] = mapped_column(Boolean, default=False)
    errors_json: Mapped[list[Any] | None] = mapped_column(Json)
    duration_seconds: Mapped[float | None] = mapped_column(Float)


class CryptoAssetRow(Base):
    __tablename__ = "crypto_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"))
    identity_kind: Mapped[str] = mapped_column(String(16))
    identity_key: Mapped[str] = mapped_column(String(128))
    asset_type: Mapped[str] = mapped_column(String(32))
    function: Mapped[str | None] = mapped_column(String(32))
    family: Mapped[str] = mapped_column(String(128))
    parameter_set: Mapped[str | None] = mapped_column(String(64))
    curve: Mapped[str | None] = mapped_column(String(128))
    mode: Mapped[str | None] = mapped_column(String(32))
    padding: Mapped[str | None] = mapped_column(String(32))
    oid: Mapped[str | None] = mapped_column(String(128))
    finding_class: Mapped[str] = mapped_column(String(24))
    migration_authority: Mapped[str] = mapped_column(String(32))
    authority_basis: Mapped[str] = mapped_column(Text)
    concluded_tier: Mapped[int] = mapped_column(Integer)
    disputed: Mapped[bool] = mapped_column(Boolean)
    disputes_json: Mapped[list[Any]] = mapped_column(Json)

    occurrences: Mapped[list[OccurrenceRow]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", order_by="OccurrenceRow.id"
    )

    __table_args__ = (
        Index("ix_assets_scan_class", "scan_run_id", "finding_class"),
        Index("ix_assets_scan_authority", "scan_run_id", "migration_authority"),
        Index("ix_assets_scan_family", "scan_run_id", "family"),
        Index("ix_assets_scan_identity", "scan_run_id", "identity_key"),
        Index("ix_assets_scan_disputed", "scan_run_id", "disputed"),
    )


class OccurrenceRow(Base):
    __tablename__ = "occurrences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("crypto_assets.id"), index=True)
    collector_run_id: Mapped[str | None] = mapped_column(ForeignKey("collector_runs.id"))
    collector: Mapped[str] = mapped_column(String(64))
    tool_version: Mapped[str] = mapped_column(String(64))
    locus_type: Mapped[str] = mapped_column(String(24))
    locus_json: Mapped[dict[str, Any]] = mapped_column(Json)
    confidence: Mapped[int] = mapped_column(Integer)
    detection_method: Mapped[str] = mapped_column(String(64))
    raw_ref: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    asset: Mapped[CryptoAssetRow] = relationship(back_populates="occurrences")


class SystemRow(Base):
    __tablename__ = "systems"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(Text)
    criticality: Mapped[int] = mapped_column(Integer)
    data_class: Mapped[str] = mapped_column(String(24))
    retention_years: Mapped[float] = mapped_column(Float)
    retention_inferred: Mapped[bool] = mapped_column(Boolean)
    internet_facing: Mapped[bool] = mapped_column(Boolean)
    regimes_json: Mapped[list[str]] = mapped_column(Json)
    bindings_json: Mapped[dict[str, Any]] = mapped_column(Json)


class AssetSystem(Base):
    __tablename__ = "asset_systems"

    asset_id: Mapped[str] = mapped_column(ForeignKey("crypto_assets.id"), primary_key=True)
    system_id: Mapped[str] = mapped_column(ForeignKey("systems.id"), primary_key=True, index=True)
    basis_json: Mapped[list[str]] = mapped_column(Json)


class SystemDep(Base):
    __tablename__ = "system_deps"

    from_system_id: Mapped[str] = mapped_column(ForeignKey("systems.id"), primary_key=True)
    to_system_id: Mapped[str] = mapped_column(ForeignKey("systems.id"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), default="depends-on")


class RiskScoreRow(Base):
    __tablename__ = "risk_scores"

    asset_id: Mapped[str] = mapped_column(ForeignKey("crypto_assets.id"), primary_key=True)
    system_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    """`""` for an unassigned asset - kept visible, never dropped."""
    scan_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"))
    policy_snapshot_id: Mapped[str] = mapped_column(String(64))
    band: Mapped[str] = mapped_column(String(24))
    outcome: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    mosca_gap: Mapped[float | None] = mapped_column(Float)
    ev: Mapped[float | None] = mapped_column(Float)
    z_effective: Mapped[str | None] = mapped_column(String(10))
    z_source: Mapped[str | None] = mapped_column(String(128))
    entry_json: Mapped[dict[str, Any]] = mapped_column(Json)
    """The complete register entry (Mosca inputs, EV, explanations)."""

    __table_args__ = (
        Index("ix_scores_scan_band", "scan_run_id", "band"),
        Index("ix_scores_scan_outcome", "scan_run_id", "outcome"),
        Index("ix_scores_scan_system", "scan_run_id", "system_id"),
    )


class RecommendationRow(Base):
    __tablename__ = "recommendations"

    asset_id: Mapped[str] = mapped_column(ForeignKey("crypto_assets.id"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(24))
    target_algorithm: Mapped[str | None] = mapped_column(String(128))
    rationale_json: Mapped[dict[str, Any]] = mapped_column(Json)


class MigrationUnitRow(Base):
    __tablename__ = "migration_units"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), primary_key=True)
    system_id: Mapped[str] = mapped_column(String(128))
    function: Mapped[str] = mapped_column(String(32))
    wave: Mapped[int | None] = mapped_column(Integer)
    target_quarter: Mapped[str | None] = mapped_column(String(10))
    feasible: Mapped[bool] = mapped_column(Boolean)
    schedule_risk: Mapped[str | None] = mapped_column(String(16))


class MigrationEdgeRow(Base):
    __tablename__ = "migration_edges"

    scan_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), primary_key=True)
    from_unit_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    to_unit_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    rationale: Mapped[str | None] = mapped_column(Text)


class SuppressionRow(Base):
    __tablename__ = "suppressions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_identity_key: Mapped[str] = mapped_column(String(128), index=True)
    reason: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AdjudicationRow(Base):
    """T-025's persistence: an operator's ruling on a dispute, keyed by
    `(asset identity, attribute)` so it survives a re-scan."""

    __tablename__ = "adjudications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identity_kind: Mapped[str] = mapped_column(String(16))
    identity_key: Mapped[str] = mapped_column(String(128), index=True)
    attribute: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(64))
    reviewed_values_json: Mapped[list[str]] = mapped_column(Json)
    adjudicated_by: Mapped[str] = mapped_column(String(128))
    adjudicated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(256))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    detail_json: Mapped[dict[str, Any] | None] = mapped_column(Json)


class AgentToken(Base):
    """A single-use enrollment token, scoped to exactly one host (ARCH.md §3a).
    Only the SHA-256 of the token is stored: the plaintext is shown to the
    operator once, at issue, and is unrecoverable after."""

    __tablename__ = "agent_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_by_agent: Mapped[str | None] = mapped_column(String(36))


class Agent(Base):
    """An enrolled host agent. `id` is issued by the backend; evidence is
    attributed to it, never to an operator-typed hostname (ARCH.md §3a)."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host: Mapped[str] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(String(64))
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    credential_fingerprint: Mapped[str] = mapped_column(String(64))
    credential_pem: Mapped[str] = mapped_column(Text)
    credential_expires: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), index=True)
    """`active` or `revoked`."""


class AgentRun(Base):
    """One unit of work for an agent: the host-mode analogue of a collector run.
    `queued` -> `dispatched` (the agent polled it) -> `complete`/`failed`."""

    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    scan_run_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id"))
    scan_spec_json: Mapped[dict[str, Any]] = mapped_column(Json)
    status: Mapped[str] = mapped_column(String(16), index=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    partial: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str | None] = mapped_column(Text)
