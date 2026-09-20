"""Where remote repositories are checked out for scanning.

A deployed QAVACH does not scan whatever path the operator types. It clones the
repository named by a git URL (any VCS host the organisation runs: GitHub,
GitLab, Bitbucket, Gitea, an internal server) into a shared workspace directory,
scans that checkout in the sandbox, and removes it afterwards.

**The workspace directory.** `QAVACH_WORKSPACE_DIR` (default `dist/workspace`).
For a deployment pick a directory every account that runs QAVACH can use and that
Docker can bind-mount - e.g. `/srv/qavach/workspace` (or `/home/repo-scan`) owned
by group `docker`, mode 2775, so new checkouts inherit the group:
    sudo install -d -m 2775 -g docker /srv/qavach/workspace
On Docker Desktop the directory must also be a path Docker Desktop shares with its
VM (home directories are by default; a bare `/tmp` is not). `QAVACH_WORKSPACE_GROUP`
optionally names a group to `chgrp` the root to.

**Hostile input.** Cloning is the one place the host (not the sandbox) touches
repository content, so it is narrow: a scheme allowlist (`https`, `http`, `ssh`,
`git`, scp-style `user@host:path`) - no `file:`, `ext::` or local paths - the URL
follows `--` so it can never be parsed as an option, hooks are disabled, submodules
and LFS are not fetched, the clone is shallow and single-branch and time-limited,
and `.git` is deleted afterwards (the scanners need the tree, not the history, and
the sandbox should never see repository config). Credentials come from the service
account's own git configuration (credential helper, ssh-agent, deploy key) - never
from QAVACH's database, argv or logs - and any credential in a URL is redacted
from every message and stored value.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from qavach_collectors import Target, TargetType

DEFAULT_SCHEMES = frozenset({"https", "http", "ssh", "git"})
_SCHEME_URL = re.compile(r"^([a-z][a-z0-9+.-]*)://[^\s]+$", re.IGNORECASE)
_SCP_LIKE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-][^\s]*$")
_CREDENTIALS = re.compile(r"(?<=://)[^/@\s]+(:[^/@\s]*)?@")


class CloneError(RuntimeError):
    """Safe to show an operator: credentials are already redacted."""


def redact_url(ref: str) -> str:
    """`https://user:token@host/x` -> `https://host/x`."""
    return _CREDENTIALS.sub("", ref)


def is_remote(ref: str, schemes: frozenset[str] = DEFAULT_SCHEMES) -> bool:
    ref = ref.strip()
    if ref.startswith("-"):
        return False
    m = _SCHEME_URL.match(ref)
    if m:
        return m.group(1).lower() in schemes
    return "ssh" in schemes and bool(_SCP_LIKE.match(ref))


@dataclass(frozen=True, slots=True)
class Checkout:
    path: Path
    commit: str | None


class Workspace:
    def __init__(
        self,
        root: Path,
        *,
        schemes: frozenset[str] = DEFAULT_SCHEMES,
        timeout_seconds: int = 900,
        max_bytes: int = 2 * 1024**3,
        group: str | None = None,
    ) -> None:
        self.root = root
        self.schemes = schemes
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self._group = group

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o2775)
        if self._group:
            shutil.chown(self.root, group=self._group)

    def wants(self, target: Target) -> bool:
        return target.type is TargetType.REPOSITORY and is_remote(target.ref, self.schemes)

    def path_for(self, scan_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", scan_id):
            raise CloneError("invalid scan id")
        return self.root / scan_id

    def clone(self, ref: str, scan_id: str) -> Checkout:
        if not is_remote(ref, self.schemes):
            raise CloneError(
                f"refusing {redact_url(ref)!r}: only {sorted(self.schemes)} URLs and "
                "user@host:path are cloned"
            )
        self.ensure()
        dest = self.path_for(scan_id)
        if dest.exists():
            shutil.rmtree(dest)
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",  # never hang on a credential prompt
            "GIT_ALLOW_PROTOCOL": ":".join(sorted(self.schemes)),
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
        command = [
            "git",
            "-c", "core.hooksPath=/dev/null",
            "-c", "protocol.ext.allow=never",
            "-c", "submodule.recurse=false",
            "clone", "--depth", "1", "--single-branch", "--no-tags",
            "--", ref.strip(), str(dest),
        ]  # fmt: skip
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise CloneError(f"clone timed out after {self.timeout_seconds}s") from exc
        except OSError as exc:
            raise CloneError(f"could not run git: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            detail = redact_url(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "")
            raise CloneError(f"git clone failed ({proc.returncode}): {detail[:300]}")

        commit = self._head(dest)
        shutil.rmtree(dest / ".git", ignore_errors=True)
        size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file() and not f.is_symlink())
        if size > self.max_bytes:
            shutil.rmtree(dest, ignore_errors=True)
            raise CloneError(f"checkout is {size} bytes, over the {self.max_bytes} byte limit")
        # the sandbox reads it as uid 65534: world-readable, never writable
        for path in [dest, *dest.rglob("*")]:
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            path.chmod(0o555 if path.is_dir() else (mode | 0o444) & ~0o222)
        return Checkout(dest, commit)

    @staticmethod
    def _head(dest: Path) -> str | None:
        proc = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        out = proc.stdout.strip()
        return out if proc.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", out) else None

    def remove(self, checkout: Checkout) -> None:
        # make it deletable again (read-only dirs), then delete; refuse anything outside root
        root = self.root.resolve()
        target = checkout.path.resolve()
        if root not in target.parents:
            return
        for path in [target, *target.rglob("*")]:
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o700)
        shutil.rmtree(target, ignore_errors=True)
