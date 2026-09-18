# Third-party scanners and tools

Every scanner QAVACH invokes, its licence, and how it's run. Required by
`SECURITY.md §7` and `NFR-10`. Licence and repo state verified live against
each project on 2026-09-18 (`NOTE.md §7`) — re-check before relying on this
table after that date.

| Tool | Licence | Invocation | Notes |
|---|---|---|---|
| [cdxgen](https://github.com/cdxgen/cdxgen) | Apache-2.0 | Sandboxed container, pinned by digest (`config/scanners.yaml`) | `source_scan.cdxgen`. npm package renamed `@cyclonedx/cdxgen` → `@cdxgen/cdxgen` in v13 — the old scope is fix-only. `tracebom` ships in the same repo/image (`runtime.tracebom`). |
| [cbomkit-lib](https://github.com/cbomkit/cbomkit-lib) + [sonar-cryptography](https://github.com/cbomkit/sonar-cryptography) | Apache-2.0 (both — `LICENSE.txt` in each repo, checked 2026-09-19) | QAVACH-built container (`docker/cbomkit-lib/Dockerfile`, T-038), not the full CBOMkit app | `source_scan.cbomkit`. The plugin `com.ibm:sonar-cryptography-plugin` is published only to GitHub Packages (PAT required even to read; **not** on Maven Central — checked), so QAVACH builds it from its pinned `1.7.0` tag inside the image build: **no credential exists at build or scan time.** Redistributing the built image is permitted by Apache-2.0 (keep both LICENSE/NOTICE files). Java is scanned source-only (no network in the sandbox, so the target is never built) — a stated coverage limit. |
| [Opengrep](https://github.com/opengrep/opengrep) | **LGPL-2.1** | QAVACH-built container (T-037, `docker/opengrep`, release v1.30.0, checksum-verified), separate process only | `source_scan.opengrep`. Fork of Semgrep v1.100.0. **Never linked or vendored into the QAVACH codebase** (NFR-10). No upstream container image exists — verified against the live repo, no Dockerfile or image-publish workflow. |
| [Syft](https://github.com/anchore/syft) | Apache-2.0 | Sandboxed container, pinned by digest | `sbom.syft`. No native crypto-detection capability — QAVACH's `crypto_libraries.yaml` purl-mapping layer is what makes it useful for PQC purposes (`NOTE.md §3.5`). |
| [CBOMkit-theia](https://github.com/cbomkit/cbomkit-theia) | Apache-2.0 | Sandboxed container (images/directories, `container.theia`) **and** agent-side (`dir` command, `tls.store`, `ARCH.md §3a`) | Standalone Go binary — **no GitHub-Packages dependency**, unlike `cbomkit-lib`. Five plugins: `certificates` (PEM/DER only), `secrets`, `javasecurity`, `opensslconf`, `problematicca`. |
| [certfinder](https://github.com/krisiasty/certfinder) | Apache-2.0 | Agent-side binary, pinned by release version + SHA-256 checksum (`config/scanners.yaml`) | `tls.store`. Covers JKS/JCEKS/PKCS#12 + SPKI fingerprinting that CBOMkit-theia's `certificates` plugin doesn't. Small project (22 commits at time of adoption) — re-check maintenance status before pinning a new version. |
| [Certipy](https://github.com/ly4k/Certipy) | MIT | QAVACH-built container (`docker/certipy/Dockerfile`, T-045), pinned to an upstream commit | `ad.adcs`. Network-mode sandboxed subprocess, no host install. Credential travels by environment variable and Certipy's stdin, never argv (`SECURITY.md §6`). Ship `docker/certipy/LICENSE` with the image (MIT requires the notice). |
| [Grype](https://github.com/anchore/grype) | Apache-2.0 | **Not integrated** | Evaluated and descoped (`NOTE.md §3.4`, `CLAUDE.md §7`) — pure CVE/vulnerability scanning, no cryptographic-asset capability. Listed here only for the record; there is no adapter for it. |

## Considered and rejected

- **PingCastle** — Non-Profit OSL 3.0 forbids commercial/revenue use without
  a paid Service Providers licence. Fails NFR-10's licence-hygiene bar the
  same way a hypothetical RSAL tool would. Never a shipped dependency; may
  be named as an optional operator-supplied external-report ingestion path
  (same shape as external CBOM ingestion, FR-180), nothing more.
- **ADRecon** — AGPLv3. Same separate-process-only treatment as Opengrep's
  LGPL-2.1 would apply if ever adopted, but its PKI coverage is generic
  next to Certipy's — deprioritised, not integrated.
- **BloodHound CE** — Apache-2.0, but an attack-path graph tool with no
  crypto-inventory purpose. Not integrated.
- **sslyze** — AGPL-3.0. Ruled out for the TLS endpoint collector.
- **nmap** (`ssl-enum-ciphers`/`ssl-cert` NSE scripts) — non-standard NPSL
  licence needing legal review before any dependency; scripts are also
  flagged "intrusive" by nmap's own docs. Ruled out.
- **secure-77/Certipy-Docker** — unlicensed and stale (last push
  2024-03-28). Do not depend on it; QAVACH builds its own Certipy wrapper
  instead (T-045).

## Base infrastructure images (dev/deployment, not scanners)

| Image | Licence | Note |
|---|---|---|
| `postgres:16-alpine` | PostgreSQL Licence | `docker-compose.yml`, T-002 |
| `redis:7-alpine` | BSD-3-Clause | `docker-compose.yml`, T-002. Redis re-licensed to a tri-choice of RSALv2/SSPLv1/AGPLv3 **starting at Redis 8** — verified against the live `LICENSE.txt` 2026-09-18. We pin 7.x specifically, which stays BSD-3-Clause; re-verify the licence before ever bumping to 8.x. |
| `quay.io/minio/minio` | AGPL-3.0 (MinIO Community Edition) | `docker-compose.yml`, T-002. MinIO no longer publishes to Docker Hub — `quay.io` is the only current source, verified 2026-09-18 (`NOTE.md §7`). |
