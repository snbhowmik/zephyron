"""ARCH.md §3a / PRD.md FR-134 — the known-paths manifest. T-034a.

'In addition to whatever explicit paths the operator supplies from the
dashboard, the agent auto-scans a curated, per-OS/per-platform manifest of
common certificate, keystore, HSM-config and appserver locations.'

`config/knowledge/host_known_paths.yaml` is the curated data (a separate
curation task, same category as `crypto_libraries.yaml`, T-034); this
module loads it and resolves it against a *real* host at scan time:
OS-specific entries (`platform: linux`/`windows`) are filtered by the
running OS, and appserver entries (`relative_to: CATALINA_BASE`, etc.) are
only included when that environment variable is actually set on this host
— not every host runs every appserver, and guessing a fake default install
root would report locations that were never scanned. Glob patterns are
expanded against the real filesystem, so the result is always paths that
exist on this host right now, never a template.
"""

from __future__ import annotations

import glob
import os
import platform
from dataclasses import dataclass

import yaml


@dataclass(frozen=True, slots=True)
class KnownPathEntry:
    platform_name: str
    path: str
    kind: str
    relative_to: str | None = None


_OS_PLATFORMS = {"linux": "linux", "windows": "windows"}
"""Entries whose `platform` names an OS directly (rather than an
appserver/web-server product) are matched against `platform.system()`."""


def load_known_paths(yaml_text: str) -> list[KnownPathEntry]:
    data = yaml.safe_load(yaml_text)
    return [
        KnownPathEntry(
            platform_name=str(raw["platform"]),
            path=str(raw["path"]),
            kind=str(raw["kind"]),
            relative_to=str(raw["relative_to"]) if raw.get("relative_to") else None,
        )
        for raw in data["paths"]
    ]


def resolve_for_host(
    entries: list[KnownPathEntry], *, os_name: str | None = None, env: dict[str, str] | None = None
) -> list[str]:
    """Returns real, currently-existing paths on this host — OS entries
    filtered to the running OS, appserver entries only when their
    `relative_to` environment variable is actually set, globs expanded
    against the real filesystem. Never returns a path that doesn't
    currently exist; an unset appserver env var or a glob with no matches
    means that platform simply isn't present on this host, not an error."""
    current_os = (os_name or platform.system()).lower()
    environ = env if env is not None else dict(os.environ)

    resolved: list[str] = []
    for entry in entries:
        if entry.platform_name in _OS_PLATFORMS:
            if _OS_PLATFORMS[entry.platform_name] != current_os:
                continue
            candidates = [entry.path]
        else:
            if entry.relative_to is None:
                candidates = [entry.path]
            else:
                base = environ.get(entry.relative_to)
                if base is None:
                    continue
                candidates = [os.path.join(base, entry.path)]

        for candidate in candidates:
            if any(ch in candidate for ch in "*?["):
                resolved.extend(glob.glob(candidate))
            elif os.path.exists(candidate):
                resolved.append(candidate)

    # De-duplicate while preserving first-seen order — stable output for
    # anything that logs or diffs a scan spec.
    seen: set[str] = set()
    deduped: list[str] = []
    for path in resolved:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped
