"""Repositories. T-071. `packages/core` stays pure: everything that touches a
database lives here, and the mapping between rows and domain objects is
explicit and round-trips (`load_assets` rebuilds `CryptoAsset`s exactly, which
is what lets `POST /policy/simulate` re-score stored assets with no re-scan).

Ids are deterministic (UUIDv5 over the scan id and the asset's identity key), so
re-saving the same result is idempotent and an id in a URL always means the same
asset.

Nothing is hidden by a filter without saying so: a suppressed asset is *flagged*
in listings (`suppressed`), never removed, and an unassigned asset is a score row
with `system_id == ""`, visible in every facet (`UNASSIGNED`).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from qavach_core.context import SystemImport
from qavach_core.model.asset import CryptoAsset, Occurrence
from qavach_core.model.certificate import CertificateFacts
from qavach_core.model.dispute import AttributeClaim, Dispute
from qavach_core.model.enums import (
    AssetType,
    ConfidenceTier,
    CryptoFunction,
    FindingClass,
    MigrationAuthority,
)
from qavach_core.model.identity import AssetIdentity, IdentityKind
from qavach_core.model.locus import locus_from_dict, locus_to_dict
from qavach_core.model.system import DataClass, System
from qavach_core.policy import PolicySnapshot
from qavach_core.reconcile import Adjudication
from sqlalchemy import Select, and_, delete, exists, func, select
from sqlalchemy.orm import Session, selectinload

from qavach_storage import models as m

UNASSIGNED = ""
NAMESPACE = uuid.UUID("6d0f5f3e-6a55-4d4c-9c5e-5c8b8f0a7e11")


def asset_id_for(scan_id: str, identity_key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{scan_id}:{identity_key}"))


def _aware(value: datetime) -> datetime:
    """SQLite drops tzinfo; every stored time is UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ---- domain <-> row mapping -------------------------------------------------


def dispute_to_dict(dispute: Dispute) -> dict[str, Any]:
    return {
        "attribute": dispute.attribute,
        "claims": [
            {
                "value": c.value,
                "source_collector": c.source_collector,
                "confidence": int(c.confidence),
                "locus": locus_to_dict(c.locus),
            }
            for c in dispute.claims
        ],
        "adjudicated_value": dispute.adjudicated_value,
        "adjudicated_by": dispute.adjudicated_by,
        "adjudicated_at": dispute.adjudicated_at.isoformat() if dispute.adjudicated_at else None,
        "adjudication_reason": dispute.adjudication_reason,
    }


def dispute_from_dict(data: Mapping[str, Any]) -> Dispute:
    at = data.get("adjudicated_at")
    return Dispute(
        attribute=data["attribute"],
        claims=tuple(
            AttributeClaim(
                value=c["value"],
                source_collector=c["source_collector"],
                confidence=ConfidenceTier(c["confidence"]),
                locus=locus_from_dict(c["locus"]),
            )
            for c in data["claims"]
        ),
        adjudicated_value=data.get("adjudicated_value"),
        adjudicated_by=data.get("adjudicated_by"),
        adjudicated_at=datetime.fromisoformat(at) if at else None,
        adjudication_reason=data.get("adjudication_reason"),
    )


def asset_to_row(scan_id: str, asset: CryptoAsset) -> m.CryptoAssetRow:
    row = m.CryptoAssetRow(
        id=asset_id_for(scan_id, asset.identity.key),
        scan_run_id=scan_id,
        identity_kind=asset.identity.kind.value,
        identity_key=asset.identity.key,
        asset_type=asset.asset_type.value,
        function=asset.function.value if asset.function else None,
        family=asset.algorithm_family,
        parameter_set=asset.parameter_set,
        curve=asset.curve,
        mode=asset.mode,
        padding=asset.padding,
        oid=asset.oid,
        finding_class=asset.finding_class.value,
        migration_authority=asset.migration_authority.value,
        authority_basis=asset.authority_basis,
        concluded_tier=int(asset.concluded_from),
        disputed=asset.disputed,
        disputes_json=[dispute_to_dict(d) for d in asset.disputes],
        certificate_json=asset.certificate.to_dict() if asset.certificate else None,
    )
    row.occurrences = [
        m.OccurrenceRow(
            collector=o.collector,
            tool_version=o.tool_version,
            locus_type=locus_to_dict(o.locus)["locus_type"],
            locus_json=locus_to_dict(o.locus),
            confidence=int(o.confidence),
            detection_method=o.detection_method,
            raw_ref=o.raw_ref,
            observed_at=o.observed_at,
        )
        for o in asset.occurrences
    ]
    return row


def row_to_asset(row: m.CryptoAssetRow) -> CryptoAsset:
    return CryptoAsset(
        identity=AssetIdentity(kind=IdentityKind(row.identity_kind), key=row.identity_key),
        asset_type=AssetType(row.asset_type),
        function=CryptoFunction(row.function) if row.function else None,
        algorithm_family=row.family,
        parameter_set=row.parameter_set,
        curve=row.curve,
        mode=row.mode,
        padding=row.padding,
        oid=row.oid,
        finding_class=FindingClass(row.finding_class),
        migration_authority=MigrationAuthority(row.migration_authority),
        authority_basis=row.authority_basis,
        occurrences=tuple(
            Occurrence(
                locus=locus_from_dict(o.locus_json),
                collector=o.collector,
                tool_version=o.tool_version,
                confidence=ConfidenceTier(o.confidence),
                detection_method=o.detection_method,
                raw_ref=o.raw_ref,
                observed_at=_aware(o.observed_at),
            )
            for o in row.occurrences
        ),
        concluded_from=ConfidenceTier(row.concluded_tier),
        disputed=row.disputed,
        disputes=tuple(dispute_from_dict(d) for d in row.disputes_json),
        certificate=(
            CertificateFacts.from_dict(row.certificate_json) if row.certificate_json else None
        ),
    )


# ---- listing ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssetFilter:
    finding_class: str | None = None
    migration_authority: str | None = None
    band: str | None = None
    outcome: str | None = None
    system_id: str | None = None
    """`UNASSIGNED` ("") selects assets no system is bound to."""
    disputed: bool | None = None
    family: str | None = None
    text: str | None = None


@dataclass(slots=True)
class AssetPage:
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int
    facets: dict[str, dict[str, int]] = field(default_factory=dict)


class Repository:
    def __init__(self, session: Session) -> None:
        self.s = session

    # -- scans --

    def create_scan(
        self,
        *,
        scan_id: str,
        target_ref: str,
        policy: PolicySnapshot,
        z_scenario: str,
        as_of: str,
        now: datetime,
    ) -> str:
        self.s.add(
            m.ScanRun(
                id=scan_id,
                target_ref=target_ref,
                started=now,
                status="queued",
                policy_snapshot_id=policy.snapshot_id,
                policy_snapshot_json=dict(policy.documents),
                z_scenario=z_scenario,
                as_of=as_of,
            )
        )
        self.s.flush()
        return scan_id

    def get_scan(self, scan_id: str) -> m.ScanRun | None:
        return self.s.get(m.ScanRun, scan_id)

    def set_status(
        self,
        scan_id: str,
        status: str,
        *,
        now: datetime | None = None,
        stages: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        scan = self.s.get(m.ScanRun, scan_id)
        if scan is None:
            raise KeyError(scan_id)
        scan.status = status
        if now is not None and status in {"complete", "failed", "partial"}:
            scan.finished = now
        if stages is not None:
            scan.stages_json = stages
        if summary is not None:
            scan.summary_json = summary
        self.s.flush()

    def policy_snapshot(self, scan_id: str) -> PolicySnapshot:
        """The policy this scan ran under - never the live files (T-068)."""
        scan = self.s.get(m.ScanRun, scan_id)
        if scan is None:
            raise KeyError(scan_id)
        return PolicySnapshot.from_documents(scan.policy_snapshot_json)

    def add_collector_run(
        self,
        scan_id: str,
        *,
        collector: str,
        tool_version: str,
        exit_code: int | None,
        partial: bool,
        errors: list[Any],
        duration_seconds: float | None,
        raw_uri: str | None = None,
    ) -> str:
        run_id = str(uuid.uuid4())
        self.s.add(
            m.CollectorRun(
                id=run_id,
                scan_run_id=scan_id,
                collector=collector,
                tool_version=tool_version,
                exit_code=exit_code,
                raw_uri=raw_uri,
                partial=partial,
                errors_json=errors,
                duration_seconds=duration_seconds,
            )
        )
        self.s.flush()
        return run_id

    def collector_runs(self, scan_id: str) -> list[m.CollectorRun]:
        return list(
            self.s.scalars(
                select(m.CollectorRun)
                .where(m.CollectorRun.scan_run_id == scan_id)
                .order_by(m.CollectorRun.collector)
            )
        )

    # -- assets --

    def save_assets(self, scan_id: str, assets: Iterable[CryptoAsset]) -> dict[str, str]:
        """Idempotent: re-saving replaces the scan's assets. Returns
        `identity_key -> asset_id`."""
        self.s.execute(delete(m.RiskScoreRow).where(m.RiskScoreRow.scan_run_id == scan_id))
        old = self.s.scalars(
            select(m.CryptoAssetRow).where(m.CryptoAssetRow.scan_run_id == scan_id)
        ).all()
        for row in old:
            self.s.execute(delete(m.AssetSystem).where(m.AssetSystem.asset_id == row.id))
            self.s.execute(
                delete(m.RecommendationRow).where(m.RecommendationRow.asset_id == row.id)
            )
            self.s.delete(row)
        self.s.flush()
        ids: dict[str, str] = {}
        for asset in assets:
            row = asset_to_row(scan_id, asset)
            self.s.add(row)
            ids[asset.identity.key] = row.id
        self.s.flush()
        return ids

    def load_assets(self, scan_id: str) -> list[CryptoAsset]:
        rows = self.s.scalars(
            select(m.CryptoAssetRow)
            .where(m.CryptoAssetRow.scan_run_id == scan_id)
            .options(selectinload(m.CryptoAssetRow.occurrences))
            .order_by(m.CryptoAssetRow.identity_key)
        ).all()
        return [row_to_asset(r) for r in rows]

    def link_occurrences_to_runs(self, scan_id: str) -> None:
        """Point each occurrence at the collector run that produced it (the
        provenance link ARCH.md 11 draws between occurrences and collector runs)."""
        runs = {c.collector: c.id for c in self.collector_runs(scan_id)}
        occurrences = self.s.scalars(
            select(m.OccurrenceRow)
            .join(m.CryptoAssetRow, m.OccurrenceRow.asset_id == m.CryptoAssetRow.id)
            .where(m.CryptoAssetRow.scan_run_id == scan_id)
        )
        for occ in occurrences:
            occ.collector_run_id = runs.get(occ.collector)
        self.s.flush()

    def score_entries(self, scan_id: str) -> list[dict[str, Any]]:
        """Stored register entries, in the register's deterministic order."""
        rows = self.s.execute(
            select(
                m.RiskScoreRow.entry_json,
                m.CryptoAssetRow.identity_kind,
                m.CryptoAssetRow.identity_key,
                m.RiskScoreRow.system_id,
            )
            .join(m.CryptoAssetRow, m.RiskScoreRow.asset_id == m.CryptoAssetRow.id)
            .where(m.RiskScoreRow.scan_run_id == scan_id)
        ).all()
        rows = sorted(rows, key=lambda r: (f"crypto/{r[1]}/{r[2]}", r[3]))
        return [dict(r[0]) for r in rows]

    def save_scores(
        self,
        scan_id: str,
        snapshot_id: str,
        entries: Iterable[tuple[str, str | None, Mapping[str, Any]]],
    ) -> None:
        for asset_id, system_id, entry in entries:
            mosca = entry.get("mosca") or {}
            ev = entry.get("expected_value") or {}
            z = entry.get("z_effective") or {}
            self.s.add(
                m.RiskScoreRow(
                    asset_id=asset_id,
                    system_id=system_id or UNASSIGNED,
                    scan_run_id=scan_id,
                    policy_snapshot_id=snapshot_id,
                    band=entry["band"],
                    outcome=entry["outcome"],
                    reason=entry["reason"],
                    mosca_gap=mosca.get("gap_years"),
                    ev=ev.get("ev"),
                    z_effective=z.get("date"),
                    z_source=z.get("bound_by"),
                    entry_json=dict(entry),
                )
            )
        self.s.flush()

    def save_bindings(self, rows: Iterable[tuple[str, str, Sequence[str]]]) -> None:
        for asset_id, system_id, basis in rows:
            self.s.merge(
                m.AssetSystem(asset_id=asset_id, system_id=system_id, basis_json=list(basis))
            )
        self.s.flush()

    def save_recommendation(
        self, asset_id: str, *, kind: str, target: str | None, rationale: Mapping[str, Any]
    ) -> None:
        self.s.merge(
            m.RecommendationRow(
                asset_id=asset_id,
                kind=kind,
                target_algorithm=target,
                rationale_json=dict(rationale),
            )
        )
        self.s.flush()

    def save_roadmap(
        self, scan_id: str, units: Iterable[Mapping[str, Any]], edges: Iterable[Mapping[str, Any]]
    ) -> None:
        self.s.execute(delete(m.MigrationUnitRow).where(m.MigrationUnitRow.scan_run_id == scan_id))
        self.s.execute(delete(m.MigrationEdgeRow).where(m.MigrationEdgeRow.scan_run_id == scan_id))
        for u in units:
            self.s.add(m.MigrationUnitRow(scan_run_id=scan_id, **u))
        for e in edges:
            self.s.add(m.MigrationEdgeRow(scan_run_id=scan_id, **e))
        self.s.flush()

    # -- inventory query --

    def _filtered(self, scan_id: str, f: AssetFilter) -> Select[Any]:
        a = m.CryptoAssetRow
        q = select(a).where(a.scan_run_id == scan_id)
        if f.finding_class:
            q = q.where(a.finding_class == f.finding_class)
        if f.migration_authority:
            q = q.where(a.migration_authority == f.migration_authority)
        if f.disputed is not None:
            q = q.where(a.disputed == f.disputed)
        if f.family:
            q = q.where(a.family == f.family)
        if f.text:
            like = f"%{f.text}%"
            q = q.where(
                a.family.ilike(like) | a.parameter_set.ilike(like) | a.identity_key.ilike(like)
            )
        score = m.RiskScoreRow
        conditions = []
        if f.band:
            conditions.append(score.band == f.band)
        if f.outcome:
            conditions.append(score.outcome == f.outcome)
        if f.system_id is not None:
            conditions.append(score.system_id == f.system_id)
        if conditions:
            q = q.where(exists().where(and_(score.asset_id == a.id, *conditions)))
        return q

    def list_assets(
        self, scan_id: str, f: AssetFilter | None = None, *, page: int = 1, page_size: int = 50
    ) -> AssetPage:
        f = f or AssetFilter()
        page_size = max(1, min(page_size, 500))
        base = self._filtered(scan_id, f)
        total = self.s.scalar(select(func.count()).select_from(base.subquery())) or 0
        rows = self.s.scalars(
            base.order_by(m.CryptoAssetRow.family, m.CryptoAssetRow.identity_key)
            .offset((max(page, 1) - 1) * page_size)
            .limit(page_size)
        ).all()
        ids = [r.id for r in rows]
        occurrence_counts: dict[str, int] = {}
        if ids:
            for asset_id, count in self.s.execute(
                select(m.OccurrenceRow.asset_id, func.count())
                .where(m.OccurrenceRow.asset_id.in_(ids))
                .group_by(m.OccurrenceRow.asset_id)
            ):
                occurrence_counts[asset_id] = int(count)
        scores: dict[str, list[m.RiskScoreRow]] = {}
        if ids:
            for sc in self.s.scalars(
                select(m.RiskScoreRow).where(m.RiskScoreRow.asset_id.in_(ids))
            ):
                scores.setdefault(sc.asset_id, []).append(sc)
        suppressed = self.suppressed_keys(datetime.now(UTC))
        items = [
            {
                "id": r.id,
                "identity_key": r.identity_key,
                "family": r.family,
                "parameter_set": r.parameter_set,
                "curve": r.curve,
                "function": r.function,
                "finding_class": r.finding_class,
                "migration_authority": r.migration_authority,
                "disputed": r.disputed,
                "occurrences": occurrence_counts.get(r.id, 0),
                "suppressed": r.identity_key in suppressed,
                "capability_only": r.concluded_tier <= int(ConfidenceTier.DEPENDENCY),
                "certificate": r.certificate_json,
                "scores": [
                    {
                        "system_id": s_.system_id or None,
                        "band": s_.band,
                        "outcome": s_.outcome,
                        "mosca_gap": s_.mosca_gap,
                        "ev": s_.ev,
                    }
                    for s_ in sorted(scores.get(r.id, []), key=lambda x: x.system_id)
                ],
            }
            for r in rows
        ]
        return AssetPage(
            items=items, total=total, page=page, page_size=page_size, facets=self.facets(scan_id, f)
        )

    def facets(self, scan_id: str, f: AssetFilter | None = None) -> dict[str, dict[str, int]]:
        """Counts over the *filtered* set, one bucket per value - `unknown` is
        always its own bucket (I8). Band/outcome/system count (asset, system)
        pairs, since one asset can be scored under several systems."""
        f = f or AssetFilter()
        sub = self._filtered(scan_id, f).subquery()
        a = m.CryptoAssetRow

        def group(column: Any) -> dict[str, int]:
            rows = self.s.execute(
                select(column, func.count())
                .select_from(a)
                .where(a.id.in_(select(sub.c.id)))
                .group_by(column)
            ).all()
            return {str(k): int(v) for k, v in rows}

        score = m.RiskScoreRow

        def group_scores(column: Any) -> dict[str, int]:
            rows = self.s.execute(
                select(column, func.count())
                .where(score.asset_id.in_(select(sub.c.id)))
                .group_by(column)
            ).all()
            return {
                ("unassigned" if k in (None, "") and column is score.system_id else str(k)): int(v)
                for k, v in rows
            }

        return {
            "finding_class": group(a.finding_class),
            "migration_authority": group(a.migration_authority),
            "disputed": group(a.disputed),
            "band": group_scores(score.band),
            "outcome": group_scores(score.outcome),
            "system": group_scores(score.system_id),
        }

    def get_asset_detail(self, asset_id: str) -> dict[str, Any] | None:
        row = self.s.scalars(
            select(m.CryptoAssetRow)
            .where(m.CryptoAssetRow.id == asset_id)
            .options(selectinload(m.CryptoAssetRow.occurrences))
        ).first()
        if row is None:
            return None
        rec = self.s.get(m.RecommendationRow, asset_id)
        scores = self.s.scalars(
            select(m.RiskScoreRow).where(m.RiskScoreRow.asset_id == asset_id)
        ).all()
        systems = self.s.scalars(
            select(m.AssetSystem).where(m.AssetSystem.asset_id == asset_id)
        ).all()
        return {
            "id": row.id,
            "scan_run_id": row.scan_run_id,
            "identity_key": row.identity_key,
            "asset_type": row.asset_type,
            "function": row.function,
            "family": row.family,
            "parameter_set": row.parameter_set,
            "curve": row.curve,
            "mode": row.mode,
            "padding": row.padding,
            "oid": row.oid,
            "finding_class": row.finding_class,
            "migration_authority": row.migration_authority,
            "authority_basis": row.authority_basis,
            "certificate": row.certificate_json,
            "concluded_tier": ConfidenceTier(row.concluded_tier).name.lower(),
            "disputed": row.disputed,
            "disputes": row.disputes_json,
            "occurrences": [
                {
                    "collector": o.collector,
                    "tool_version": o.tool_version,
                    "locus": o.locus_json,
                    "confidence": ConfidenceTier(o.confidence).name.lower(),
                    "detection_method": o.detection_method,
                    "raw_ref": o.raw_ref,
                }
                for o in row.occurrences
            ],
            "risk": [sc.entry_json for sc in sorted(scores, key=lambda x: x.system_id)],
            "systems": [{"system_id": s_.system_id, "basis": s_.basis_json} for s_ in systems],
            "recommendation": None
            if rec is None
            else {"kind": rec.kind, "target": rec.target_algorithm, **rec.rationale_json},
        }

    def simulation_rows(self, scan_id: str) -> list[dict[str, Any]]:
        """The minimum a re-score needs, straight from Core selects (no ORM
        objects): one dict per asset with its system ids and locus JSONs. Built
        for `policy/simulate` at 50k assets, where hydrating full aggregates
        would cost more than the scoring itself."""
        a, o, link = m.CryptoAssetRow, m.OccurrenceRow, m.AssetSystem
        assets = {
            row.id: {
                "id": row.id,
                "identity_kind": row.identity_kind,
                "identity_key": row.identity_key,
                "family": row.family,
                "parameter_set": row.parameter_set,
                "function": row.function,
                "finding_class": row.finding_class,
                "migration_authority": row.migration_authority,
                "certificate": row.certificate_json,
                "loci": [],
                "systems": [],
            }
            for row in self.s.execute(
                select(
                    a.id,
                    a.identity_kind,
                    a.identity_key,
                    a.family,
                    a.parameter_set,
                    a.function,
                    a.finding_class,
                    a.migration_authority,
                    a.certificate_json,
                ).where(a.scan_run_id == scan_id)
            )
        }
        for asset_id, locus_json in self.s.execute(
            select(o.asset_id, o.locus_json)
            .join(a, o.asset_id == a.id)
            .where(a.scan_run_id == scan_id)
        ):
            assets[asset_id]["loci"].append(locus_json)
        for asset_id, system_id in self.s.execute(
            select(link.asset_id, link.system_id)
            .join(a, link.asset_id == a.id)
            .where(a.scan_run_id == scan_id)
        ):
            assets[asset_id]["systems"].append(system_id)
        return list(assets.values())

    def stored_bands(
        self, scan_id: str
    ) -> dict[tuple[str, str], tuple[str, str | None, float | None]]:
        """`(asset_id, system_id) -> (band, outcome, mosca_gap)` under the scan's own policy."""
        return {
            (asset_id, system_id): (band, outcome, gap)
            for asset_id, system_id, band, outcome, gap in self.s.execute(
                select(
                    m.RiskScoreRow.asset_id,
                    m.RiskScoreRow.system_id,
                    m.RiskScoreRow.band,
                    m.RiskScoreRow.outcome,
                    m.RiskScoreRow.mosca_gap,
                ).where(m.RiskScoreRow.scan_run_id == scan_id)
            )
        }

    # -- systems --

    def replace_systems(self, imported: SystemImport) -> None:
        self.s.execute(delete(m.SystemDep))
        self.s.execute(delete(m.AssetSystem))
        self.s.execute(delete(m.SystemRow))
        self.s.flush()
        for system in imported.systems:
            b = imported.bindings[system.id]
            self.s.add(
                m.SystemRow(
                    id=system.id,
                    name=system.name,
                    owner=system.owner,
                    criticality=system.criticality,
                    data_class=system.data_classification.value,
                    retention_years=system.retention_years,
                    retention_inferred=system.retention_inferred,
                    internet_facing=system.internet_facing,
                    regimes_json=sorted(system.regulatory_regimes),
                    bindings_json={
                        "repos": sorted(b.repos),
                        "images": sorted(b.images),
                        "endpoints": sorted(b.endpoints),
                        "cloud_accounts": sorted(b.cloud_accounts),
                        "hosts": sorted(b.hosts),
                    },
                )
            )
        self.s.flush()
        for system in imported.systems:
            for dep in sorted(system.depends_on):
                self.s.add(m.SystemDep(from_system_id=system.id, to_system_id=dep))
        self.s.flush()

    def load_systems(self) -> tuple[list[System], dict[str, dict[str, Any]]]:
        rows = self.s.scalars(select(m.SystemRow).order_by(m.SystemRow.id)).all()
        deps: dict[str, set[str]] = {}
        for d in self.s.scalars(select(m.SystemDep)):
            deps.setdefault(d.from_system_id, set()).add(d.to_system_id)
        systems = [
            System(
                id=r.id,
                name=r.name,
                owner=r.owner,
                criticality=r.criticality,
                data_classification=DataClass(r.data_class),
                retention_years=r.retention_years,
                retention_inferred=r.retention_inferred,
                internet_facing=r.internet_facing,
                regulatory_regimes=frozenset(r.regimes_json),
                depends_on=frozenset(deps.get(r.id, ())),
            )
            for r in rows
        ]
        return systems, {r.id: r.bindings_json for r in rows}

    # -- suppressions, adjudications, audit --

    def audit(
        self,
        actor: str,
        action: str,
        subject: str,
        *,
        now: datetime,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        self.s.add(
            m.AuditLog(
                actor=actor,
                action=action,
                subject=subject,
                at=now,
                detail_json=dict(detail) if detail else None,
            )
        )
        self.s.flush()

    def suppress(
        self, identity_key: str, *, reason: str, author: str, now: datetime, expires_at: datetime
    ) -> str:
        if not reason.strip():
            raise ValueError("a suppression must record a reason")
        if expires_at <= now:
            raise ValueError("a suppression must expire in the future")
        sid = str(uuid.uuid4())
        self.s.add(
            m.SuppressionRow(
                id=sid,
                asset_identity_key=identity_key,
                reason=reason,
                author=author,
                created_at=now,
                expires_at=expires_at,
            )
        )
        self.audit(
            author,
            "suppress",
            identity_key,
            now=now,
            detail={"reason": reason, "expires_at": expires_at.isoformat()},
        )
        return sid

    def suppressed_keys(self, now: datetime) -> set[str]:
        rows = self.s.scalars(select(m.SuppressionRow)).all()
        return {r.asset_identity_key for r in rows if _aware(r.expires_at) > _aware(now)}

    def save_adjudication(self, adj: Adjudication, *, now: datetime) -> str:
        aid = str(uuid.uuid4())
        self.s.add(
            m.AdjudicationRow(
                id=aid,
                identity_kind=adj.identity.kind.value,
                identity_key=adj.identity.key,
                attribute=adj.attribute,
                value=adj.value,
                reviewed_values_json=sorted(adj.reviewed_values),
                adjudicated_by=adj.adjudicated_by,
                adjudicated_at=adj.adjudicated_at,
                reason=adj.reason,
            )
        )
        self.audit(
            adj.adjudicated_by,
            "adjudicate",
            adj.identity.key,
            now=now,
            detail={"attribute": adj.attribute, "value": adj.value, "reason": adj.reason},
        )
        return aid

    def load_adjudications(self) -> list[Adjudication]:
        return [
            Adjudication(
                identity=AssetIdentity(kind=IdentityKind(r.identity_kind), key=r.identity_key),
                attribute=r.attribute,
                value=r.value,
                reviewed_values=frozenset(r.reviewed_values_json),
                adjudicated_by=r.adjudicated_by,
                adjudicated_at=_aware(r.adjudicated_at),
                reason=r.reason,
            )
            for r in self.s.scalars(
                select(m.AdjudicationRow).order_by(m.AdjudicationRow.adjudicated_at)
            )
        ]
