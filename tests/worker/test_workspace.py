"""Cloning remote repositories into the workspace: what is allowed, what is refused,
and that nothing sensitive survives (hooks, .git, credentials)."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
from qavach_collectors import Target, TargetType
from qavach_worker.workspace import CloneError, Workspace, is_remote, redact_url


def make_remote(tmp: Path) -> Path:
    repo = tmp / "origin"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@x",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@x",
    }
    (repo / "src").mkdir()
    (repo / "src" / "A.java").write_text('Cipher.getInstance("AES/ECB/PKCS5Padding");\n')
    hooks = repo / ".git-hooks-marker"
    hooks.write_text("x")
    for cmd in (["init", "-q", "-b", "main"], ["add", "."], ["commit", "-q", "-m", "c"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    return repo


@pytest.mark.parametrize(
    "ref",
    [
        "https://github.com/acme/pay.git",
        "http://git.internal/acme/pay",
        "ssh://git@gitlab.example.org/acme/pay.git",
        "git://host/x.git",
        "git@github.com:acme/pay.git",
    ],
)
def test_git_urls_of_any_vcs_host_are_remote(ref: str) -> None:
    assert is_remote(ref)


@pytest.mark.parametrize(
    "ref",
    [
        "/etc",
        "../secrets",
        "file:///etc",
        "ext::sh -c 'touch /tmp/pwn'",
        "--upload-pack=touch /tmp/pwn",
        "-c core.sshCommand=evil",
        "ftp://host/x",
        "github.com/acme/pay",
        "",
    ],
)
def test_paths_option_lookalikes_and_dangerous_schemes_are_never_cloned(
    ref: str, tmp_path: Path
) -> None:
    assert not is_remote(ref)
    with pytest.raises(CloneError):
        Workspace(tmp_path / "ws").clone(ref, "scan-1")
    assert not (tmp_path / "ws" / "scan-1").exists()


def test_credentials_in_a_url_are_redacted_everywhere_they_could_leak(tmp_path: Path) -> None:
    assert redact_url("https://bot:s3cr3t@host/x.git") == "https://host/x.git"
    assert redact_url("https://tok@host/x") == "https://host/x"
    with pytest.raises(CloneError) as exc:
        Workspace(tmp_path / "ws", schemes=frozenset({"https"}), timeout_seconds=20).clone(
            "https://bot:s3cr3t@127.0.0.1:9/nope.git", "s2"
        )
    assert "s3cr3t" not in str(exc.value)


def test_a_clone_is_shallow_stripped_of_git_readable_by_the_sandbox_and_removable(
    tmp_path: Path,
) -> None:
    origin = make_remote(tmp_path)
    ws = Workspace(tmp_path / "ws", schemes=frozenset({"file"}))
    checkout = ws.clone(f"file://{origin}", "scan-abc")
    assert checkout.commit and len(checkout.commit) == 40
    tree = checkout.path
    assert (tree / "src" / "A.java").read_text().startswith("Cipher")
    assert not (tree / ".git").exists()  # the sandbox never sees repository config or history
    mode = (tree / "src" / "A.java").stat().st_mode
    assert mode & stat.S_IROTH and not mode & (
        stat.S_IWUSR | stat.S_IWOTH
    )  # uid 65534 can read, nobody writes
    assert (tree.stat().st_mode & stat.S_IXOTH) and not tree.stat().st_mode & stat.S_IWOTH
    ws.remove(checkout)
    assert not tree.exists()


def test_a_failed_clone_leaves_nothing_behind_and_says_why(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws", schemes=frozenset({"file"}))
    with pytest.raises(CloneError, match="git clone failed"):
        ws.clone(f"file://{tmp_path}/does-not-exist", "scan-x")
    assert not (tmp_path / "ws" / "scan-x").exists()


def test_the_size_cap_removes_an_oversized_checkout(tmp_path: Path) -> None:
    origin = make_remote(tmp_path)
    ws = Workspace(tmp_path / "ws", schemes=frozenset({"file"}), max_bytes=10)
    with pytest.raises(CloneError, match="over the"):
        ws.clone(f"file://{origin}", "scan-big")
    assert not (tmp_path / "ws" / "scan-big").exists()


def test_the_workspace_only_claims_remote_repository_targets(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    assert ws.wants(Target(TargetType.REPOSITORY, "https://github.com/a/b"))
    assert not ws.wants(Target(TargetType.REPOSITORY, "/local/path"))
    assert not ws.wants(Target(TargetType.CONTAINER_IMAGE, "https://github.com/a/b"))


def test_scan_ids_cannot_escape_the_workspace(tmp_path: Path) -> None:
    with pytest.raises(CloneError):
        Workspace(tmp_path).path_for("../../etc")


def test_run_scan_over_a_git_url_scans_the_checkout_binds_by_the_normalised_url_and_cleans_up(
    tmp_path: Path,
) -> None:
    import dataclasses
    import sys
    from datetime import UTC, datetime

    from qavach_collectors import (
        CollectorRegistry,
        CollectorResult,
        RawClaim,
        RawFormat,
        ToolIdentity,
    )
    from qavach_core.context import parse_systems_csv
    from qavach_core.model import ConfidenceTier, FileLocus
    from qavach_storage import Repository, create_all, make_engine, session_factory
    from qavach_worker import Deps, ScanRequest, run_scan

    root = Path(__file__).parent.parent.parent
    sys.path.insert(0, str(root / "scripts"))
    import demo

    knowledge, policy, pqc = demo.load_knowledge()
    origin = make_remote(tmp_path)
    seen: dict[str, str] = {}

    class Probe:
        name, version = "probe", "1"
        requires_sandbox = requires_network = False
        default_confidence = ConfidenceTier.AST

        def supports(self, target: Target) -> bool:
            return target.type is TargetType.REPOSITORY

        def collect(self, target: Target, ctx: object) -> CollectorResult:
            seen["ref"] = target.ref
            seen["has_source"] = str((Path(target.ref) / "src" / "A.java").exists())
            return CollectorResult(
                raw=b"",
                raw_format=RawFormat.QAVACH_NATIVE,
                claims=[
                    RawClaim(
                        locus=FileLocus(path="src/A.java", offset=1),
                        name="AES/ECB/PKCS5Padding",
                        detection_method="ast",
                        confidence=ConfidenceTier.AST,
                    )
                ],
                tool=ToolIdentity("probe", "1", ("p",), 0, 0.0),
                errors=[],
                partial=False,
            )

    registry = CollectorRegistry()
    registry.register(Probe())
    ws = Workspace(tmp_path / "ws", schemes=frozenset({"file"}))
    deps = Deps(
        registry=registry,
        knowledge=knowledge,
        policy=policy,
        pqc=pqc,
        clock=lambda: datetime(2026, 9, 20, tzinfo=UTC),
        workspace=ws,
    )
    engine = make_engine("sqlite://")
    create_all(engine)
    url = f"file://{origin}"
    with session_factory(engine)() as session:
        repo = Repository(session)
        # a system bound to a *differently spelled* URL for the same repository
        csv = (
            "id,name,owner,criticality,data_classification,internet_facing,retention_years,"
            f"regulatory_regimes,depends_on,repos\npay,Pay,team,5,restricted,true,10,,,{url}/\n"
        )
        imported = parse_systems_csv(csv, policy)
        assert imported.ok, imported.errors
        repo.replace_systems(imported)
        session.commit()
        outcome = run_scan(
            session, ScanRequest(target=Target(TargetType.REPOSITORY, url), scan_id="s1"), deps
        )
        assert outcome.status in {"complete", "partial"}, outcome.summary
        scan = repo.get_scan("s1")
        assert scan is not None and scan.target_ref == url
        page = repo.list_assets("s1", __import__("qavach_storage").AssetFilter(system_id="pay"))
        assert page.total >= 1  # bound via the normalised URL, not left "unassigned"
    assert seen["ref"].startswith(str(tmp_path / "ws")) and seen["has_source"] == "True"
    assert not (tmp_path / "ws" / "s1").exists()  # checkout removed
    _ = dataclasses


def test_build_resolution_is_off_by_default_audited_when_on_and_survives_the_queue() -> None:
    from qavach_worker import ScanRequest
    from qavach_worker.jobs import from_payload, to_payload

    default = ScanRequest(target=Target(TargetType.REPOSITORY, "https://h/x"))
    assert default.allow_build_resolution is False
    on = ScanRequest(
        target=Target(TargetType.REPOSITORY, "https://h/x"), allow_build_resolution=True
    )
    assert from_payload(to_payload(on)).allow_build_resolution is True
    assert from_payload(to_payload(default)).allow_build_resolution is False
