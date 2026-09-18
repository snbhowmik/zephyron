"""T-036a — `artefact/archive.py`'s `SECURITY.md §9` guards. Real ZIP
archives throughout (built with `zipfile`, which is what a JAR is), so
the caps are exercised against genuine archive structures rather than
mocked metadata."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from _java_fixture import build_jar
from qavach_collectors.artefact import (
    ArchiveLimitExceeded,
    ArchiveLimits,
    iter_archive_entries,
)


def test_reads_entries_from_a_real_jar(tmp_path: Path) -> None:
    jar = build_jar(
        {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\n", "a/b/Thing.class": b"\xca\xfe"},
        path=tmp_path / "app.jar",
    )
    entries = list(iter_archive_entries(jar.read_bytes(), archive_path=str(jar)))
    names = {entry.name for entry in entries}
    assert names == {"META-INF/MANIFEST.MF", "a/b/Thing.class"}
    assert all(entry.archive_path.startswith(str(jar)) for entry in entries)


def test_descends_into_nested_jars(tmp_path: Path) -> None:
    """A WAR's `WEB-INF/lib/*.jar` is the normal shape of a deployed Java
    app — the nested jar's entries must be reachable, with a logical
    path showing the nesting."""
    inner = build_jar({"com/example/Inner.class": b"\xca\xfe\xba\xbe"}, path=tmp_path / "util.jar")
    war = build_jar(
        {"WEB-INF/lib/util.jar": inner.read_bytes(), "WEB-INF/web.xml": b"<web-app/>"},
        path=tmp_path / "app.war",
    )

    entries = list(iter_archive_entries(war.read_bytes(), archive_path=str(war)))
    nested = [e for e in entries if e.name == "com/example/Inner.class"]
    assert len(nested) == 1
    assert "util.jar!/com/example/Inner.class" in nested[0].archive_path


def test_stops_descending_past_max_depth(tmp_path: Path) -> None:
    innermost = build_jar({"deep/Deep.class": b"\xca\xfe"}, path=tmp_path / "deep.jar")
    middle = build_jar({"lib/deep.jar": innermost.read_bytes()}, path=tmp_path / "middle.jar")
    outer = build_jar({"lib/middle.jar": middle.read_bytes()}, path=tmp_path / "outer.war")

    shallow = list(
        iter_archive_entries(
            outer.read_bytes(), archive_path=str(outer), limits=ArchiveLimits(max_depth=2)
        )
    )
    assert not any(e.name == "deep/Deep.class" for e in shallow)

    deep = list(
        iter_archive_entries(
            outer.read_bytes(), archive_path=str(outer), limits=ArchiveLimits(max_depth=3)
        )
    )
    assert any(e.name == "deep/Deep.class" for e in deep)


def test_entry_count_cap_raises(tmp_path: Path) -> None:
    jar = build_jar({f"file{i}.txt": b"x" for i in range(50)}, path=tmp_path / "many.jar")
    with pytest.raises(ArchiveLimitExceeded, match="entry count"):
        list(
            iter_archive_entries(
                jar.read_bytes(), archive_path=str(jar), limits=ArchiveLimits(max_entries=10)
            )
        )


def test_per_entry_size_cap_raises_on_a_real_decompression_bomb(tmp_path: Path) -> None:
    """A highly compressible 8 MiB entry — small on disk, large when
    inflated. The cap must fire on the *declared uncompressed* size,
    before the data is ever read into memory."""
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.bin", b"\x00" * (8 * 1024 * 1024))

    with pytest.raises(ArchiveLimitExceeded, match="exceeds"):
        list(
            iter_archive_entries(
                bomb.getvalue(),
                archive_path="bomb.jar",
                limits=ArchiveLimits(max_entry_uncompressed_bytes=1024 * 1024),
            )
        )


def test_total_size_budget_raises_across_many_entries(tmp_path: Path) -> None:
    """No single entry exceeds the per-entry cap, but together they
    exceed the total budget — the case a per-entry-only guard misses."""
    jar = build_jar(
        {f"chunk{i}.bin": b"\x00" * (256 * 1024) for i in range(8)}, path=tmp_path / "sum.jar"
    )
    with pytest.raises(ArchiveLimitExceeded, match="total uncompressed size"):
        list(
            iter_archive_entries(
                jar.read_bytes(),
                archive_path=str(jar),
                limits=ArchiveLimits(
                    max_entry_uncompressed_bytes=1024 * 1024,
                    max_total_uncompressed_bytes=512 * 1024,
                ),
            )
        )


def test_a_non_archive_yields_nothing_rather_than_raising() -> None:
    assert list(iter_archive_entries(b"not a zip at all", archive_path="junk.jar")) == []


def test_directories_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "dirs.jar"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/", b"")
        archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
    entries = list(iter_archive_entries(path.read_bytes(), archive_path=str(path)))
    assert [e.name for e in entries] == ["META-INF/MANIFEST.MF"]
