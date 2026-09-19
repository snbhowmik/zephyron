"""Agent registry persistence (T-073a, ARCH.md §3a and §11).

Kept apart from `Repository` because it is a self-contained aggregate: enrolment
tokens, enrolled agents and their queued/dispatched runs. All times are UTC.

Token handling: only the SHA-256 of a token is stored. `consume_token` is a
single conditional `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`, so
two concurrent enrolments cannot both win: the second sees rowcount 0. That is
what makes the token single-use rather than "checked, then used".
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from qavach_storage import models as m

QUEUED, DISPATCHED, COMPLETE, FAILED = "queued", "dispatched", "complete", "failed"


def as_utc(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; everything here is stored as UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class AgentRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    # -- enrolment tokens ---------------------------------------------------

    def issue_token(
        self,
        *,
        token_sha256: str,
        host: str,
        created_by: str,
        now: datetime,
        expires_at: datetime,
    ) -> str:
        token_id = str(uuid.uuid4())
        self.s.add(
            m.AgentToken(
                id=token_id,
                token_sha256=token_sha256,
                host=host,
                created_by=created_by,
                created_at=now,
                expires_at=expires_at,
            )
        )
        self.s.flush()
        return token_id

    def consume_token(self, *, token_sha256: str, host: str, now: datetime, agent_id: str) -> bool:
        """True iff this call consumed a live, unexpired, unconsumed token scoped
        to `host`. Anything else - unknown, expired, already used, wrong host - is
        the same `False`, so a caller cannot tell them apart."""
        result = self.s.execute(
            update(m.AgentToken)
            .where(
                m.AgentToken.token_sha256 == token_sha256,
                m.AgentToken.consumed_at.is_(None),
                m.AgentToken.expires_at > now,
                func.lower(m.AgentToken.host) == host.lower(),
            )
            .values(consumed_at=now, consumed_by_agent=agent_id)
        )
        return bool(result.rowcount == 1)  # type: ignore[attr-defined]

    def tokens(self, now: datetime) -> list[dict[str, Any]]:
        """Issued tokens and their state - never the token itself."""
        rows = self.s.scalars(select(m.AgentToken).order_by(m.AgentToken.created_at.desc()))
        out = []
        for t in rows:
            state = (
                "consumed"
                if t.consumed_at is not None
                else "expired"
                if as_utc(t.expires_at) <= now
                else "pending"
            )
            out.append(
                {
                    "id": t.id,
                    "host": t.host,
                    "state": state,
                    "created_at": as_utc(t.created_at).isoformat(),
                    "expires_at": as_utc(t.expires_at).isoformat(),
                    "consumed_by_agent": t.consumed_by_agent,
                }
            )
        return out

    # -- agents ---------------------------------------------------------------

    def add_agent(
        self,
        *,
        agent_id: str,
        host: str,
        os_name: str,
        now: datetime,
        credential_fingerprint: str,
        credential_pem: str,
        credential_expires: datetime,
    ) -> None:
        self.s.add(
            m.Agent(
                id=agent_id,
                host=host,
                os=os_name,
                enrolled_at=now,
                credential_fingerprint=credential_fingerprint,
                credential_pem=credential_pem,
                credential_expires=credential_expires,
                last_seen=None,
                status="active",
            )
        )
        self.s.flush()

    def get_agent(self, agent_id: str) -> m.Agent | None:
        return self.s.get(m.Agent, agent_id)

    def list_agents(self) -> list[m.Agent]:
        return list(self.s.scalars(select(m.Agent).order_by(m.Agent.enrolled_at)))

    def touch(self, agent_id: str, now: datetime) -> None:
        self.s.execute(update(m.Agent).where(m.Agent.id == agent_id).values(last_seen=now))

    def revoke(self, agent_id: str) -> bool:
        result = self.s.execute(
            update(m.Agent)
            .where(m.Agent.id == agent_id, m.Agent.status == "active")
            .values(status="revoked")
        )
        return bool(result.rowcount == 1)  # type: ignore[attr-defined]

    # -- runs -----------------------------------------------------------------

    def queue_run(self, agent_id: str, spec: Mapping[str, Sequence[str]], now: datetime) -> str:
        run_id = str(uuid.uuid4())
        self.s.add(
            m.AgentRun(
                id=run_id,
                agent_id=agent_id,
                scan_spec_json={k: list(v) for k, v in spec.items()},
                status=QUEUED,
                queued_at=now,
                partial=False,
            )
        )
        self.s.flush()
        return run_id

    def dispatch_next(self, agent_id: str, now: datetime) -> m.AgentRun | None:
        """Hand the agent its oldest queued run, atomically marking it dispatched
        so a second poll cannot receive the same work."""
        while True:
            run = self.s.scalars(
                select(m.AgentRun)
                .where(m.AgentRun.agent_id == agent_id, m.AgentRun.status == QUEUED)
                .order_by(m.AgentRun.queued_at, m.AgentRun.id)
                .limit(1)
            ).first()
            if run is None:
                return None
            claimed = self.s.execute(
                update(m.AgentRun)
                .where(m.AgentRun.id == run.id, m.AgentRun.status == QUEUED)
                .values(status=DISPATCHED, started=now)
            )
            if claimed.rowcount == 1:  # type: ignore[attr-defined]
                self.s.refresh(run)
                return run

    def dispatched_run(self, agent_id: str) -> m.AgentRun | None:
        """The run this agent is currently working on (its oldest dispatched one)."""
        return self.s.scalars(
            select(m.AgentRun)
            .where(m.AgentRun.agent_id == agent_id, m.AgentRun.status == DISPATCHED)
            .order_by(m.AgentRun.started, m.AgentRun.id)
            .limit(1)
        ).first()

    def finish_run(
        self,
        run_id: str,
        *,
        now: datetime,
        status: str,
        scan_run_id: str | None,
        partial: bool,
        detail: str | None = None,
    ) -> None:
        self.s.execute(
            update(m.AgentRun)
            .where(m.AgentRun.id == run_id)
            .values(
                status=status,
                finished=now,
                scan_run_id=scan_run_id,
                partial=partial,
                detail=detail,
                exit_code=0 if status == COMPLETE else 1,
            )
        )

    def runs(self, agent_id: str) -> list[m.AgentRun]:
        return list(
            self.s.scalars(
                select(m.AgentRun)
                .where(m.AgentRun.agent_id == agent_id)
                .order_by(m.AgentRun.queued_at.desc(), m.AgentRun.id)
            )
        )

    def run_counts(self) -> dict[str, int]:
        rows = self.s.execute(
            select(m.AgentRun.agent_id, func.count()).group_by(m.AgentRun.agent_id)
        ).all()
        return {agent_id: int(n) for agent_id, n in rows}
