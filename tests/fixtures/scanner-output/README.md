# Recorded scanner output (T-024)

Real output from the real tools over **one target**,
`tests/fixtures/targets/polyglot/` (C, C#, PHP, Ruby, Rust, Python and Java
sources plus `requirements.txt` and `Cargo.toml`, each with a known, planted
crypto call site). Nothing here is hand-written or edited.

| Directory | Tool | Ran as |
|---|---|---|
| `cdxgen/` | cdxgen 13.0.1 (`--include-crypto`, explicit `-t` list) | pinned upstream image, in the QAVACH sandbox |
| `cbomkit/` | cbomkit-lib + sonar-cryptography 1.7.0 | `qavach/cbomkit-lib:dev` (`docker/cbomkit-lib`) |
| `opengrep/` | Opengrep 1.30.0, QAVACH's 14-rule pack | `qavach/opengrep:dev` (`docker/opengrep`) |
| `syft/` | Syft (pinned image) | pinned upstream image |
| `tracebom/` | tracebom 13.0.1 (`python3 -c 'import hashlib, ssl ...'`) | `qavach/tracebom:dev` (`docker/tracebom`) |

Regenerate with `make build-images && uv run python scripts/record_fixtures.py`
(needs Docker; not run in CI). Commit the diff: a change in what a tool reports
is exactly what this corpus exists to surface.

`tests/collectors/test_scanner_corpus.py` replays each file through its
collector's parser and reconciles all four. Findings from recording it are in
`NOTE.md` (T-024 entry, OQ-18).
