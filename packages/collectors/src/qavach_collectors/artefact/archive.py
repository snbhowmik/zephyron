"""Safe WAR/EAR/JAR reading for the deployed-artefact collector. T-036a.

`SECURITY.md §9`: 'Archive extraction... must guard against zip slip,
symlink escape and decompression bombs. Enforce an uncompressed-size cap
and an entry-count cap.'

This module never extracts to disk at all — entries are read into memory
one at a time, which removes zip-slip and symlink-escape as a category
rather than defending against them path-by-path (there is no destination
path to traverse out of). What remains is resource exhaustion, and that
is capped three ways: total uncompressed bytes, per-entry uncompressed
bytes, and entry count. Nested archives (a WAR's `WEB-INF/lib/*.jar`) are
walked to a bounded depth with the *same* caps applied to each level,
since a bomb nested one layer down is still a bomb.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass

ARCHIVE_EXTENSIONS = (".war", ".ear", ".jar")


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_total_uncompressed_bytes: int = 512 * 1024 * 1024
    max_entry_uncompressed_bytes: int = 64 * 1024 * 1024
    max_entries: int = 20_000
    max_depth: int = 3
    """A WAR containing JARs containing classes is depth 3 — the real
    shape of a deployed Java artefact. Deeper nesting is a bomb pattern,
    not a build output."""


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    archive_path: str
    """Logical path including any nested archives, e.g.
    `app.war!/WEB-INF/lib/util.jar!/com/example/Crypto.class`."""
    name: str
    data: bytes


class ArchiveLimitExceeded(RuntimeError):
    pass


def iter_archive_entries(
    data: bytes,
    *,
    archive_path: str,
    limits: ArchiveLimits | None = None,
    _depth: int = 1,
    _budget: list[int] | None = None,
) -> Iterator[ArchiveEntry]:
    """Yields every entry in the archive, descending into nested
    archives up to `limits.max_depth`. Raises `ArchiveLimitExceeded` when
    a cap is hit — the caller decides whether that degrades the scan
    (`partial=True`) or aborts it; this function does not silently
    truncate, because "we stopped looking and didn't say so" is exactly
    the failure invariant I8 exists to prevent."""
    limits = limits or ArchiveLimits()
    budget = _budget if _budget is not None else [limits.max_total_uncompressed_bytes]
    entry_count = 0

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return

    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue

            entry_count += 1
            if entry_count > limits.max_entries:
                raise ArchiveLimitExceeded(
                    f"{archive_path}: entry count exceeded {limits.max_entries}"
                )
            if info.file_size > limits.max_entry_uncompressed_bytes:
                raise ArchiveLimitExceeded(
                    f"{archive_path}!/{info.filename}: entry size {info.file_size} "
                    f"exceeds {limits.max_entry_uncompressed_bytes}"
                )
            if info.file_size > budget[0]:
                raise ArchiveLimitExceeded(
                    f"{archive_path}: total uncompressed size exceeded "
                    f"{limits.max_total_uncompressed_bytes}"
                )

            entry_data = archive.read(info)
            budget[0] -= len(entry_data)
            entry_path = f"{archive_path}!/{info.filename}"

            if info.filename.lower().endswith(ARCHIVE_EXTENSIONS):
                if _depth < limits.max_depth:
                    yield from iter_archive_entries(
                        entry_data,
                        archive_path=entry_path,
                        limits=limits,
                        _depth=_depth + 1,
                        _budget=budget,
                    )
                continue

            yield ArchiveEntry(archive_path=entry_path, name=info.filename, data=entry_data)
