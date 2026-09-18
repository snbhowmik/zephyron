"""T-034a — `config/knowledge/host_known_paths.yaml` and its loader.
Loads the *real* file (its own exit criteria — real platform coverage,
schema shape) and proves `resolve_for_host` only ever returns paths that
actually exist on a real filesystem, built fresh per test with `tmp_path`
rather than asserted against the real host (whose OS and installed
appservers this test suite cannot assume anything about)."""

from __future__ import annotations

from pathlib import Path

from qavach_agent import load_known_paths, resolve_for_host
from qavach_agent.known_paths import KnownPathEntry

ROOT = Path(__file__).parent.parent.parent
REAL_YAML = ROOT / "config" / "knowledge" / "host_known_paths.yaml"


def test_real_file_covers_every_platform_fr_134_names() -> None:
    entries = load_known_paths(REAL_YAML.read_text())
    platforms = {e.platform_name for e in entries}
    assert platforms == {
        "linux",
        "windows",
        "tomcat",
        "jboss_wildfly",
        "weblogic",
        "websphere",
        "nginx",
        "apache_httpd",
        "iis",
    }


def test_real_file_has_a_reasonable_number_of_entries() -> None:
    entries = load_known_paths(REAL_YAML.read_text())
    assert len(entries) >= 30


def test_real_file_flags_known_demo_credentials() -> None:
    """WebLogic's DemoIdentity.jks and WebSphere's DummyServerKeyFile.jks
    are the two most-cited vendor-demo-cert-left-in-production examples in
    appserver hardening guides — the manifest must actually flag them as
    `demo_credential`, not just list them as ordinary keystores."""
    entries = load_known_paths(REAL_YAML.read_text())
    demo_paths = {e.path for e in entries if e.kind == "demo_credential"}
    assert any("DemoIdentity" in p for p in demo_paths)
    assert any("DummyServerKeyFile" in p for p in demo_paths)


def test_resolve_filters_os_entries_by_platform(tmp_path: Path) -> None:
    linux_dir = tmp_path / "etc-ssl-certs"
    linux_dir.mkdir()
    windows_dir = tmp_path / "windows-only"
    windows_dir.mkdir()
    entries = [
        KnownPathEntry(platform_name="linux", path=str(linux_dir), kind="trust_store"),
        KnownPathEntry(platform_name="windows", path=str(windows_dir), kind="trust_store"),
    ]

    resolved_linux = resolve_for_host(entries, os_name="Linux", env={})
    assert resolved_linux == [str(linux_dir)]

    resolved_windows = resolve_for_host(entries, os_name="Windows", env={})
    assert resolved_windows == [str(windows_dir)]


def test_resolve_skips_appserver_entries_when_env_var_unset(tmp_path: Path) -> None:
    """Not every host runs Tomcat — an unset `CATALINA_BASE` must mean
    'this platform isn't here,' never a guessed default install root."""
    entries = [
        KnownPathEntry(
            platform_name="tomcat",
            path="conf/server.xml",
            kind="config_with_keystore_refs",
            relative_to="CATALINA_BASE",
        )
    ]
    resolved = resolve_for_host(entries, os_name="Linux", env={})
    assert resolved == []


def test_resolve_includes_appserver_entries_when_env_var_set_and_file_exists(
    tmp_path: Path,
) -> None:
    catalina_base = tmp_path / "tomcat"
    (catalina_base / "conf").mkdir(parents=True)
    (catalina_base / "conf" / "server.xml").write_text("<Server/>")

    entries = [
        KnownPathEntry(
            platform_name="tomcat",
            path="conf/server.xml",
            kind="config_with_keystore_refs",
            relative_to="CATALINA_BASE",
        )
    ]
    resolved = resolve_for_host(entries, os_name="Linux", env={"CATALINA_BASE": str(catalina_base)})
    assert resolved == [str(catalina_base / "conf" / "server.xml")]


def test_resolve_expands_globs_against_the_real_filesystem(tmp_path: Path) -> None:
    catalina_base = tmp_path / "tomcat"
    conf_dir = catalina_base / "conf"
    conf_dir.mkdir(parents=True)
    (conf_dir / "keystore1.jks").write_bytes(b"fake-jks-1")
    (conf_dir / "keystore2.jks").write_bytes(b"fake-jks-2")
    (conf_dir / "not-a-keystore.txt").write_text("irrelevant")

    entries = [
        KnownPathEntry(
            platform_name="tomcat", path="conf/*.jks", kind="keystore", relative_to="CATALINA_BASE"
        )
    ]
    resolved = resolve_for_host(entries, os_name="Linux", env={"CATALINA_BASE": str(catalina_base)})
    assert set(resolved) == {str(conf_dir / "keystore1.jks"), str(conf_dir / "keystore2.jks")}


def test_resolve_returns_no_duplicates(tmp_path: Path) -> None:
    real_dir = tmp_path / "certs"
    real_dir.mkdir()
    entries = [
        KnownPathEntry(platform_name="linux", path=str(real_dir), kind="trust_store"),
        KnownPathEntry(platform_name="linux", path=str(real_dir), kind="trust_store"),
    ]
    resolved = resolve_for_host(entries, os_name="Linux", env={})
    assert resolved == [str(real_dir)]


def test_resolve_omits_nonexistent_fixed_paths(tmp_path: Path) -> None:
    entries = [
        KnownPathEntry(
            platform_name="linux", path=str(tmp_path / "does-not-exist"), kind="trust_store"
        )
    ]
    resolved = resolve_for_host(entries, os_name="Linux", env={})
    assert resolved == []
