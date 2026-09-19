"""T-073a persistence: single-use enrolment tokens and the agent run queue."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from qavach_storage import AgentRepository, create_all, make_engine, session_factory
from sqlalchemy.orm import Session

NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@pytest.fixture
def repo() -> Iterator[AgentRepository]:
    engine = make_engine("sqlite://")
    create_all(engine)
    session: Session
    with session_factory(engine)() as session:
        yield AgentRepository(session)


def issue(repo: AgentRepository, token: str = "tok", host: str = "web-01", ttl: int = 60) -> None:
    repo.issue_token(
        token_sha256=sha(token),
        host=host,
        created_by="op",
        now=NOW,
        expires_at=NOW + timedelta(minutes=ttl),
    )


def test_a_token_enrols_exactly_once(repo: AgentRepository) -> None:
    issue(repo)
    assert repo.consume_token(token_sha256=sha("tok"), host="web-01", now=NOW, agent_id="a1")
    assert not repo.consume_token(token_sha256=sha("tok"), host="web-01", now=NOW, agent_id="a2")
    [row] = repo.tokens(NOW)
    assert row["state"] == "consumed" and row["consumed_by_agent"] == "a1"


def test_a_token_is_scoped_to_its_host_case_insensitively(repo: AgentRepository) -> None:
    issue(repo, host="Web-01")
    assert not repo.consume_token(token_sha256=sha("tok"), host="web-02", now=NOW, agent_id="a")
    # the wrong-host attempt must not burn the token
    assert repo.consume_token(token_sha256=sha("tok"), host="WEB-01", now=NOW, agent_id="a")


def test_an_expired_or_unknown_token_is_refused(repo: AgentRepository) -> None:
    issue(repo, ttl=5)
    later = NOW + timedelta(minutes=6)
    assert not repo.consume_token(token_sha256=sha("tok"), host="web-01", now=later, agent_id="a")
    assert not repo.consume_token(token_sha256=sha("nope"), host="web-01", now=NOW, agent_id="a")
    assert repo.tokens(later)[0]["state"] == "expired"


def test_only_the_hash_of_a_token_is_ever_stored(repo: AgentRepository) -> None:
    issue(repo, token="qat_plaintext")
    from qavach_storage import models

    row = repo.s.query(models.AgentToken).one()
    assert "qat_plaintext" not in {row.token_sha256, row.host, row.created_by}
    assert row.token_sha256 == sha("qat_plaintext")
    assert "qat_plaintext" not in str(repo.tokens(NOW))


def add_agent(repo: AgentRepository, agent_id: str = "a1") -> None:
    repo.add_agent(
        agent_id=agent_id,
        host="web-01",
        os_name="Linux",
        now=NOW,
        credential_fingerprint="f" * 64,
        credential_pem="PEM",
        credential_expires=NOW + timedelta(days=90),
    )


def test_a_queued_run_is_dispatched_once_oldest_first(repo: AgentRepository) -> None:
    add_agent(repo)
    first = repo.queue_run("a1", {"paths": ["/etc/ssl"], "collectors": ["tls.store"]}, NOW)
    second = repo.queue_run(
        "a1", {"paths": ["/opt"], "collectors": ["hsm.evidence"]}, NOW + timedelta(seconds=1)
    )
    got = repo.dispatch_next("a1", NOW)
    assert got is not None and got.id == first and got.status == "dispatched"
    assert repo.dispatched_run("a1").id == first  # type: ignore[union-attr]
    nxt = repo.dispatch_next("a1", NOW)
    assert nxt is not None and nxt.id == second
    assert repo.dispatch_next("a1", NOW) is None


def test_runs_are_per_agent_and_finishing_records_the_outcome(repo: AgentRepository) -> None:
    add_agent(repo, "a1")
    add_agent(repo, "a2")
    run = repo.queue_run("a1", {"paths": ["/x"], "collectors": ["tls.store"]}, NOW)
    assert repo.dispatch_next("a2", NOW) is None  # not a2's work
    repo.dispatch_next("a1", NOW)
    repo.finish_run(run, now=NOW, status="complete", scan_run_id=None, partial=True)
    [done] = repo.runs("a1")
    assert done.status == "complete" and done.partial and done.exit_code == 0
    assert repo.dispatched_run("a1") is None
    assert repo.run_counts() == {"a1": 1}


def test_revoking_is_idempotent_in_effect(repo: AgentRepository) -> None:
    add_agent(repo)
    assert repo.revoke("a1") and not repo.revoke("a1")
    assert repo.get_agent("a1").status == "revoked"  # type: ignore[union-attr]
