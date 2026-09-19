# TASK.md — QAVACH Backlog

Rules:
- Pick the **lowest-numbered task with no open blockers**.
- Reference the task ID in the branch name and commit subject: `T-014: ...`
- Tick the box and update the status column **in the same commit** as the work.
- Do not start a phase before its predecessor's **exit criteria** are met.
- `★` marks the demo-critical path (`PRD.md §7`). If time runs short,
  everything unstarred waits.

Status: ` ` open · `~` in progress · `x` done · `!` blocked · `-` descoped

---

## Phase 0 — Foundation

**Exit criteria:** `make test-unit` passes with no Docker, no network, no
database. CI is green. A contributor can clone and be productive in 10 minutes.

| | ID | Task | Blocked by |
|---|---|---|---|
| x | T-001 ★ | Repo skeleton per `CLAUDE.md §3`. `uv` + `pnpm` workspaces, Makefile, `.editorconfig`. | — |
| x | T-002 ★ | `docker-compose.yml`: postgres 16, redis, minio. `make dev` brings them up healthy. | T-001 |
| x | T-003 ★ | CI: ruff, mypy strict on `packages/core`, biome, pytest, vitest. Fails on any error. | T-001 |
| x | T-004 ★ | `tests/test_architecture.py` — import-inspection test enforcing that `packages/core` imports no framework, no I/O library, and nothing from `collectors/`. | T-001 |
| x | T-005 | `docs/THIRD_PARTY.md` with every scanner's licence. Note Opengrep LGPL-2.1 → separate process only. | T-001 |
| x | T-006 ★ | `config/scanners.yaml` pinning every scanner image by digest. `make scanners-pull`. **cdxgen: pin `@cdxgen/cdxgen` (renamed from `@cyclonedx/cdxgen` in v13 — the old scope is fix-only); build with `--ignore-scripts --min-release-age=2`.** | T-002 |

---

## Phase 1 — Domain model and normalisation

**Exit criteria:** a hand-written CycloneDX 1.7 CBOM and a cdxgen 1.7 CBOM both
normalise into identical canonical `CryptoAsset` objects for the same
underlying algorithm. (Legacy 1.4–1.6 input ingestion is still built per
`ARCH.md §5.1`/T-014 — it's just not gated into this phase's exit bar; it
gets its own fixture coverage when T-014 lands.)

| | ID | Task | Blocked by |
|---|---|---|---|
| x | T-010 ★ | Domain model per `ARCH.md §4`. Frozen dataclasses, full type coverage, zero I/O. | T-004 |
| x | T-011 ★ | Vendor the CycloneDX 1.7 JSON schema and the Cryptography Registry into `config/knowledge/cdx-crypto-registry/` at a pinned version. Document how to refresh. | T-001 |
| x | T-012 ★ | `normalize/registry.py` — resolve any algorithm spelling to canonical `(family, parameter_set, curve, primitive)`. Resolution order: OID → registry exact → alias table → UNKNOWN. Never drop silently. | T-010, T-011 |
| x | T-013 ★ | `config/knowledge/aliases.yaml` — first 60 aliases covering what the tools actually emit. Include pre-standardisation PQC names (`Kyber768` → `ML-KEM-768`). | T-012 |
| x | T-014 ★ | CycloneDX version normalisation: ingest 1.4–1.7 → canonical 1.7. Preserve `evidence.occurrences[]` and `evidence.identity[].methods[]`. | T-012 |
| x | T-015 ★ | `classify.py` — the four finding classes (invariant I1). **Table-driven, from config, not hardcoded branches.** Property test: no symmetric algorithm ever lands in `QUANTUM_VULNERABLE`. | T-012 |
| x | T-015a ★ | **Invariant I8 enforcement.** `UNKNOWN` is a first-class class with its own aggregate. Property test: no `UNKNOWN` asset ever contributes to a safe/none count, in any aggregate, at any layer. A second test asserts the UI colour token for `UNKNOWN` is never the safe token. | T-015 |
| x | T-015b ★ | **Golden test: PQC OID resolution (A-19).** Every OID in the NIST ML-KEM / ML-DSA / SLH-DSA arcs resolves to a named parameter set and classifies `QUANTUM_SAFE`, never `UNKNOWN`. Verify each mapping against the vendored registry — do not hand-write from memory. | T-012 |
| x | T-015c ★ | **Curve canonicalisation stage (A-18)** before identity hashing, with an alias-corpus test: `secp256r1` / `prime256v1` / `P-256` / `NIST P-256` / `1.2.840.10045.3.1.7` must collapse to one identity. | T-012 |
| x | T-016a ★ | `MigrationAuthority` derivation per `ARCH.md §4.1` (invariant I9), with `authority_basis` recorded. Property test: a cert chaining to a public root whose every locus is third-party software never enters the roadmap. | T-010 |
| x | T-016b | **Data-quality queue (A-13).** Implausible modulus lengths, `0-bit` keys and filename-shaped algorithm names are routed to triage, never to a chart. Regression fixtures drawn from the failure modes in `IDEATION.md §2.2b`. | T-012 |
| x | T-016 ★ | Function classification: map every algorithm to a `CryptoFunction`. Drives Mosca — invariant I2. | T-012 |

---

## Phase 2 — Reconciliation

**Exit criteria:** four fixture files from four different tools describing the
same RSA-2048 key produce **one** `CryptoAsset` with four occurrences and the
correct concluded tier. Two contradictory claims at the same tier produce a
`disputed` asset.

| | ID | Task | Blocked by |
|---|---|---|---|
| x | T-020 ★ | `asset_identity()` per `ARCH.md §6.1`. Instance identity for certs and keys, class identity for algorithms. | T-010 |
| x | T-021 ★ | `Locus` types per `ARCH.md §6.2`, with parsers and round-trip serialisation. | T-010 |
| x | T-022 ★ | Merge engine: group by identity, retain all occurrences, conclude by precedence. | T-020, T-021 |
| x | T-023 ★ | Dispute detection on material attributes at equal-or-higher tier. Disputed assets score at their worst plausible claim. | T-022 |
| ☒ | T-024 ★ | Fixture corpus in `tests/fixtures/scanner-output/` — real recorded output from cdxgen, CBOMkit, Opengrep, Syft over the same target. **These fixtures are the backbone of the whole test suite; record them properly and check them in.** | T-030 |
| ☒ | T-025 | Adjudication: persist an operator's resolution of a dispute; it survives re-scan. | T-023, T-041 |

---

## Phase 3 — Collectors

**Exit criteria:** each collector produces valid `CollectorResult` from a real
target — via the sandbox for a repository/image/network/cloud target, or via
the deployed agent for a Host target (`ARCH.md §2.3`) — with `partial=True` on
failure rather than an exception escaping.

| | ID | Task | Blocked by |
|---|---|---|---|
| x | T-030 ★ | `Collector` protocol + registry + `CollectorResult`. | T-010 |
| ☒ | T-031 ★ | **Sandbox runner** per `SECURITY.md §3`: per-job container, `--network=none`, non-root, read-only rootfs, tmpfs, cgroup limits, timeout. Every sandboxed collector goes through this — no exceptions, no bypass flag. | T-030, T-002 |
| ☒ | T-031a ★ | **Agent runtime** (`ARCH.md §3a`): outbound-poll loop, mTLS client, enrollment-token exchange, typed scan-spec protocol (paths + collector modules, no command execution). Packaged as a single-file Python bundle (PyInstaller); **needs a per-OS CI build matrix, not a cross-compile step** — PyInstaller does not cross-compile, confirmed against GRR Rapid Response's own build pipeline. **Per-OS CI matrix itself not done** — this machine only proves the Linux build; a GitHub Actions matrix (`windows-latest`/`macos-latest`/`ubuntu-latest`) is a follow-up, tracked below. | T-030 |
| ☒ | T-031c | **Per-OS PyInstaller CI build matrix** for the agent binary (`windows-latest`, `macos-latest`, `ubuntu-latest` GitHub Actions runners) — the packaging mechanism itself was proven end-to-end on Linux in T-031a; this task is purely the CI wiring to produce all three release artefacts. | T-031a |
| ☒ | T-031d | **Wire the agent-side collectors into the agent's registry.** `run` polled with an empty `CollectorRegistry`, so the shipped binary would have reported every collector as unregistered. `tls.store` registers only if certfinder is found; the closed vocabulary is enforced. | T-031a, T-036, T-036a, T-041, T-042a |
| ☒ | T-031b ★ | **Resource-limited parsing worker** used by every agent-mode collector (`ARCH.md §3a`, "Containment for hostile input"): fork/subprocess per fetched file, `resource.setrlimit` (CPU, address space, output size) plus a wall-clock timeout, dropped to the most restricted account reachable, kill-and-mark-`partial` on breach. **Privilege-drop mechanism implemented but not exercised end-to-end** — this dev environment has no root/`CAP_SETUID`; see `NOTE.md`. | T-031a |
| ☒ | T-032 ★ | cdxgen `cbom` adapter. Build resolution **off** by default; `--allow-build-resolution` with egress allowlist and a printed warning. **Found and fixed a real bug in T-031's sandbox runner along the way** — see `NOTE.md`: `build_sandbox_args` never overrode a scanner image's own `ENTRYPOINT`, silently breaking every image whose entrypoint isn't a shell. | T-031 |
| ☒ | T-033 ★ | Syft adapter → package inventory. | T-031 |
| ☒ | T-034 ★ | `config/knowledge/crypto_libraries.yaml` — purl → cryptographic capability. **Start with 40 libraries covering Java, Python, Go, JS. This is real curation work, not a config stub. Schema must force `capability` not `usage` semantics.** | T-033 |
| ☒ | T-034a ★ | `config/knowledge/host_known_paths.yaml` — curated per-OS/per-platform manifest the agent auto-scans (`ARCH.md §3a`, FR-134): Linux/Windows cert stores, Tomcat/JBoss-WildFly/WebLogic/WebSphere/nginx/Apache httpd/IIS layouts. Same curation-effort category as T-034 — do not stub it. | T-031a |
| ☒ | T-035 ★ | **TLS endpoint collector** (QAVACH-built). asyncio; per endpoint capture protocol version, cipher suite, negotiated group, full chain, per-cert key algorithm/size/curve, signature algorithm, validity, SANs, SHA-256 fingerprint, SPKI hash. Probe for hybrid group support. Respect the SSRF denylist in `SECURITY.md §4`. **Decide `OQ-10` first** (wrap testssl.sh for the classical half, or stay fully custom) — do not default to full custom-build silently. **OQ-10 resolved: fully custom, via `openssl s_client` CLI, not asyncio directly** — see `NOTE.md`. | T-030 |
| ☒ | T-036 ★ | Certificate store collector: wraps **certfinder** (Apache-2.0) for the PEM/DER/JKS/JCEKS/PKCS#12 filesystem walk and SPKI/SHA-256 fingerprinting, **and CBOMkit-theia's `dir` command** (Apache-2.0) for secrets/private-key detection, OpenSSL config extraction, and known-bad-CA flagging — additive, not overlapping (theia's own cert plugin is PEM/DER only). QAVACH owns PKCS#7 parsing and chain reconstruction on top. **Runs exclusively via the deployed agent** (`ARCH.md §2.3`, §3a) — no sandboxed-subprocess variant. **certfinder half + PKCS#7 + chain reconstruction done; theia half split out to T-036c** — theia ships as a container image only (verified: zero binary assets on every release), which the agent cannot run. `NOTE.md` OQ-11. | T-031a, T-031b |
| ☒ | T-036c | **CBOMkit-theia's agent-side half of `tls.store`** (secrets/private-key detection, `opensslconf` TLS extraction, `problematicca` known-bad-CA flagging). Blocked on a build/bundling decision — theia has no binary releases, so QAVACH must cross-compile it from Go source (Apache-2.0) into a companion binary shipped with the agent, per `NOTE.md` OQ-11's options. Needs a Go toolchain build step and a per-OS/arch release matrix, same category of work as T-031c. | T-036 |
| ☒ | T-036a ★ | **Deployed-artefact collector (A-20).** WAR/EAR/JAR inspection: `MANIFEST.MF`, embedded `pom.properties`, JCA call sites in classes, plus the keystores sitting beside them. **Priority over the source collector for the demo corpus** — in an SI-built Indian BFSI estate the customer usually does not hold the repository. `IDEATION.md §5.1`. Lives in `packages/collectors/artefact/`, not a `host/` package (`CLAUDE.md §3`). Runs via the deployed agent. | T-031a, T-031b |
| ☒ | T-036b | Binary collector, shallow: ELF/PE/Mach-O import tables, known algorithm constants, Authenticode/code-signing chain reconstruction. **No symbolic execution** — scope stated honestly in the coverage report. | T-031 |
| ☒ | T-037 | Opengrep adapter, SARIF → claims at `PATTERN` confidence. Ship **10–15 rules only** (`NOTE.md §3.3`). | T-031 |
| ☒ | T-038 | **`cbomkit-lib` adapter** (`source_scan.cbomkit`, `NOTE.md §3.2`): pinned QAVACH-owned container wrapping `cbomkit-lib` directly — no CBOMkit sidecar app. Build the target first when `--allow-build-resolution` is set, then scan with jar/class paths configured, matching `cbomkit-action`'s sequencing. The `com.ibm:sonar-cryptography-plugin` GitHub Packages credential is resolved once at image-build time, never at scan time. | T-031 **Done without a PAT**: QAVACH builds the plugin from its pinned tag inside the image (`docker/cbomkit-lib`); verified running sandboxed against real code. `NOTE.md`. |
| ☒ | T-039 | CBOMkit-theia adapter for container images. | T-031 |
| ☒ | T-040 | AWS cloud collector, read-only: KMS `DescribeKey` → `KeySpec`, ACM certificates, ELBv2 TLS policies. | T-030 **Done without AWS credentials**, tested against `moto`. Refuses write-capable credentials; minimum IAM policy in `docs/iam/`. |
| ☒ | T-041 | HSM evidence collector: PKCS#11 config, vendor client libraries, `SunPKCS11` JVM config, slot references. Emits an **unresolved crypto boundary**, not a resolved asset. **Runs exclusively via the deployed agent.** | T-031a, T-031b |
| ☒ | T-042 | SSH host key collector — network probe (banner/KEX negotiation) only, shares `tls.endpoint`'s sandboxed transport. `sshd_config` KEX/cipher/MAC inspection is a separate agent-mode task (folded into T-036's scope note; local file access requires the agent, `ARCH.md §2.3`). | T-030 |
| ☒ | T-042a | **`sshd_config` inspection — the agent-side half of `ssh.hostkey`.** T-042 delegated it to "a separate agent-mode task" that no task owned. `KexAlgorithms`/`Ciphers`/`MACs`/`HostKey` with sshd's real semantics (first value wins, `Include` order, `Match` skipped, `+ - ^` modifiers); private keys never opened. | T-042 |
| ☒ | T-043 | External CBOM ingestion — upload a CycloneDX 1.4–1.7 CBOM as a first-class source. | T-014 |
| ☒ | T-044 | `tracebom` runtime adapter. | T-031 |
| ☒ | T-045 | **AD Certificate Services collector**, wrapping Certipy (MIT) — `find -json` over LDAP with an operator-supplied domain credential. Network-mode sandboxed subprocess, not agent-mode — no host install. Maps ESC1–ESC8 findings and template algorithms onto QAVACH's finding classes (`PRD.md FR-135`). | T-031 **Built and image-verified; NOT verified against a real AD** — fixtures are derived from Certipy's source, not recorded. `NOTE.md` OQ-13/14. |

---

## Phase 4 — Business context

**Exit criteria:** a systems CSV imports, assets bind to systems, and every
system carries criticality, retention and exposure.

| | ID | Task | Blocked by |
|---|---|---|---|
| ☒ | T-050 ★ | `System` model + CSV/YAML import with validation and a clear error report. | T-010 |
| ☒ | T-051 ★ | Asset → system binding: by repo, by image, by endpoint, by cloud account. Unbound assets go to a visible "unassigned" bucket, never dropped. | T-050, T-022 |
| ☒ | T-052 | Retention inference from data classification when unsupplied; mark `retention_inferred=True` and surface the inference in the UI. | T-050 |
| ☒ | T-053 | System dependency import (`system_deps`) — feeds the roadmap DAG. | T-050 |

---

## Phase 5 — Risk engine

**Exit criteria:** given the same assets and the same policy snapshot, scoring
is byte-identical across runs and machines. Every score decomposes into inputs
via the explain API. **Total runtime under 60s for 50k assets (NFR-02).**

| | ID | Task | Blocked by |
|---|---|---|---|
| ☒ | T-060 ★ | `config/policy/z_scenarios.yaml` + `regulatory_deadlines.yaml`, every entry with a `basis` citation and a `binding: true|false` flag. | — |
| ☒ | T-061 ★ | `shelf_life_years()` per `ARCH.md §7.2`. **Property test: for identical algorithm and key size, a long-lived signing asset always outranks an ephemeral one.** This is the invariant-I2 guard. | T-016, T-050 |
| ☒ | T-062 ★ | `Z_effective = min(Z_scenario, applicable_regulatory_deadlines)`, returning which one bound and why. | T-060 |
| ☒ | T-063 ★ | `Y` estimator from `config/policy/migration_effort.yaml`. Labelled a planning heuristic in every surface it appears. | T-051 |
| ☒ | T-064 ★ | Mosca evaluation: `X + Y > Z_effective`, gap in years, urgency band. | T-061, T-062, T-063 |
| ☒ | T-065 ★ | CARAF D3 expected value: criticality × sensitivity × exposure × mosca gap factor. | T-064 |
| ☒ | T-066 ★ | CARAF D4 outcome selection: Migrate / Compensating control / Accept / Phase out, against `risk_tolerance.yaml`. **Every outcome carries a human-readable reason string.** | T-065 |
| ☒ | T-067 ★ | Explanation objects: every score serialises its inputs, its formula, the policy values used, and each value's citation. Powers FR-360 and the UI drill-down. | T-064, T-066 |
| ☐ | T-068 ★ | **Core half done** (`PolicySnapshot`: frozen, canonical JSON, SHA-256 `snapshot_id`, scoring reads only it); **the `scan_runs.policy_snapshot_json` column waits on T-070.** Policy snapshotting into `scan_runs.policy_snapshot_json`. Scores are **always** computed against the snapshot, never against current policy. | T-060, T-070 |

---

## Phase 6 — Persistence and API

**Exit criteria:** a scan runs end to end via HTTP with live WebSocket
progress, and the inventory endpoint returns faceted results in under 500ms for
50k assets.

| | ID | Task | Blocked by |
|---|---|---|---|
| ☐ | T-070 ★ | SQLAlchemy models + Alembic baseline per `ARCH.md §11`. | T-002 |
| ☐ | T-071 ★ | Repositories. `packages/core` stays pure — repositories live in `packages/storage`. | T-070 |
| ☐ | T-072 ★ | RQ pipeline orchestration: collect → normalise → reconcile → context → risk → recommend → roadmap. Per-stage status, per-collector partial failure. | T-030, T-071 |
| ☐ | T-073 ★ | FastAPI surface per `ARCH.md §12`. Transport only — zero business logic in route handlers. | T-072 |
| ☐ | T-073a ★ | Agent enrollment/registry backend: single-use token issuance, mTLS credential exchange, `agents`/`agent_runs` persistence (`ARCH.md §3a`, §11), spec-polling and results-ingestion endpoints. | T-070, T-073, T-031a |
| ☐ | T-074 ★ | WebSocket progress with per-collector status events. | T-072 |
| ☐ | T-075 ★ | `POST /policy/simulate` — pure re-score over stored assets, no re-scan. Must return in under 1s for 50k assets; this powers the Mosca explorer. | T-068, T-073 |
| ☐ | T-076 | Suppressions with reason and expiry; persist across scans; write to the audit log. | T-071 |
| ☐ | T-077 | Audit log for every mutating action. | T-071 |

---

## Phase 7 — Recommendation and roadmap

**Exit criteria:** every `QUANTUM_VULNERABLE` asset has a cited recommendation
with an accurate standardisation status. The roadmap renders waves and detects
at least one hybrid-bridge cycle in the demo dataset.

| | ID | Task | Blocked by |
|---|---|---|---|
| ☒ | T-080 ★ | `config/knowledge/pqc_alternatives.yaml`. Each entry: `status`, `standard`, `verified_on`, `source_url`. **FIPS 203/204/205 final; HQC selected-not-published; FIPS 206 in development.** | — |
| ☒ | T-081 ★ | CI check: fail the build if any `verified_on` in the knowledge base is older than 180 days. Forces re-verification against NIST CSRC. | T-080, T-003 |
| ☒ | T-082 ★ | Recommendation engine: select a replacement by function and constraints; emit hybrid guidance with context and reason. | T-080, T-066 |
| ☒ | T-083 | `config/knowledge/performance.yaml` — key/ciphertext/signature sizes, timings, handshake overhead. **Every row cites a primary source. Unavailable figures are `null`, never invented.** | T-080 |
| ☒ | T-084 ★ | Migration DAG builder with the six typed edges (`ARCH.md §9.1`). Include the reader-before-writer rule for data-format edges. | T-053, T-066 |
| ☒ | T-085 ★ | Topological sort into waves; order within wave by Mosca urgency; backward-schedule quarters from the binding deadline. | T-084 |
| ☒ | T-086 ★ | Cycle detection → `HybridBridgeRequirement` naming every SCC member, scheduled as its own wave. **A cycle is a finding, not an error.** | T-084 |
| ☒ | T-087 | `SCHEDULE_INFEASIBLE` flag with the specific blocking chain named. | T-085 |

---

## Phase 8 — Export

**Exit criteria:** the exported CBOM validates against the official CycloneDX
1.7 schema in CI, and the CI check rejects any risk data found inside it.

| | ID | Task | Blocked by |
|---|---|---|---|
| ☒ | T-090 ★ | CycloneDX 1.7 CBOM export. Occurrences → `evidence.occurrences[]`, provenance → `evidence.identity[].methods[]`. **No purl on `cryptographic-asset` components.** | T-022 |
| ☒ | T-091 ★ | `make schema-check`, wired into CI: validate against the official schema **and** assert no `qavach:` risk fields appear outside the documented namespace. Invariant I5. | T-090, T-003 |
| ☒ | T-092 ★ | Crypto Risk Register export + JSON Schema at `docs/schema/risk-register-1.0.json`. | T-067, T-090 |
| ☒ | T-093 | CycloneDX 1.6 downgrade export. | T-090 |
| ☐ | T-094 | **Not started (needs a PDF library dependency; on the cut list).** Executive PDF. | T-092 |
| ☐ | T-095 | **Not started (needs an XLSX library dependency; first on the cut list).** Asset register XLSX. | T-092 |
| ☒ | T-096 | SARIF export + `qavach scan --fail-on <class>` CI mode. | T-090 |
| ☒ | T-097 | Signed exports. ML-DSA-65 where the library allows; otherwise Ed25519 **with the limitation stated in the output**. | T-090 |
| ☒ | T-098 | `docs/CUSTOM_PROPERTIES.md` documenting every `qavach:` property; CI fails on an undocumented namespace. | T-090 |

---

## Phase 9 — Interface

**Exit criteria:** the full demo path in `PRD.md §7` runs from the UI with no
console commands.

| | ID | Task | Blocked by |
|---|---|---|---|
| ☐ | T-100 ★ | Vite + React + TS + Tailwind + shadcn/ui shell; TanStack Query; typed API client generated from the OpenAPI schema. | T-073 |
| ☐ | T-101 ★ | New-scan flow: **target-type selector** (FR-601 — Repository, Container Image, Network/TLS Endpoint, Directory Service, Cloud Account, Host, External upload), then target entry, systems CSV upload, collector selection, live WebSocket progress. Selecting Host routes to T-101a. | T-100, T-074 |
| ☐ | T-101a ★ | **Agent enrollment flow (sensor management, FR-133)**: generate a single-use token, show install instructions, list every enrolled agent's identity/host/online-offline status/per-run history. | T-101, T-073a |
| ☐ | T-102 ★ | Posture dashboard: counts by finding class, systems by CARAF outcome, the binding deadline banner, count of assets that miss it. | T-100 |
| ☐ | T-103 ★ | Inventory table: virtualised, faceted by class, function, algorithm, system, criticality, confidence, disputed. | T-100 |
| ☐ | T-104 ★ | Asset detail: every occurrence with locus and provenance; full risk computation with inputs visible; recommendation with citations. **The reconciliation view — one asset, N occurrences, N tools — is the single most important screen in the product. Make it obvious at a glance.** | T-103, T-067 |
| ☐ | T-105 ★ | **Mosca explorer**: `Z` slider + scenario selector, live re-sort via `/policy/simulate`, banner naming which constraint bound. | T-075 |
| ☐ | T-106 ★ | Roadmap view: Cytoscape.js + dagre DAG, waves as a timeline, hybrid-bridge cycles highlighted distinctly. | T-085, T-086 |
| ☐ | T-107 ★ | Finding-class visual language: `GROVER_AFFECTED` must **never** render in the same colour or severity band as `QUANTUM_VULNERABLE`. `CLASSICAL_WEAK` gets its own treatment with "urgent — but not a quantum issue" copy. Invariant I1, in the design system. | T-102 |
| ☐ | T-108 | Triage UI: suppress with reason and expiry; adjudicate disputes. | T-076, T-025 |
| ☐ | T-109 | Scan history and drift diff. | T-103 |
| ☐ | T-110 ★ | Unimplemented capabilities render as visible, labelled stubs. Never hidden, never fake data presented as real. | T-100 |

---

## Phase 10 — Hardening and evidence

| | ID | Task | Blocked by |
|---|---|---|---|
| ☐ | T-120 ★ | `make demo` — seeded dataset that exercises every step of `PRD.md §7`, including the planted AES-128, the planted MD5, the root-CA-vs-TLS-cert pair, and the deliberate DAG cycle. | Phase 9 |
| ☐ | T-121 | **Ground-truth accuracy run** (OQ-05): 3–5 well-known OSS repos, hand-labelled, measured precision/recall published in `docs/ACCURACY.md`. **Make no accuracy claim anywhere until this exists.** | T-120 |
| ☐ | T-122 | Threat-model review against `SECURITY.md`; verify the sandbox actually blocks egress and privilege escalation with a deliberate escape test. | T-031 |
| ☐ | T-123 | `make bundle` — air-gap offline tarball of pinned images plus the knowledge base. | T-006 |
| ☐ | T-124 | Helm chart in `deploy/helm/`. | T-123 |
| ☐ | T-125 | `docs/ARCHITECTURE_DECISIONS.md` — promote `NOTE.md §7` entries into full ADRs. | — |
| ☐ | T-126 | Load test to NFR-01/02/03. | T-120 |

---

## Cut list, in order

If time runs out, drop in this order. Everything here is unstarred above.

1. T-124 Helm · T-109 drift · T-095 XLSX · T-042 SSH
2. T-044 tracebom · T-039 theia · T-040 cloud
3. T-083 performance table (recommendations still work, just without figures)
4. T-096 SARIF/CI · T-108 triage UI
5. T-038 `cbomkit-lib` adapter (cdxgen alone covers source scanning)

**Never cut:** T-031 sandbox, T-091 schema check, T-107 finding-class visual
language, T-110 honest stubs, T-015 classification. Each of these is the
difference between a credible tool and one that misleads its operator.
