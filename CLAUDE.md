# CLAUDE.md

Operating contract for Claude Code working in this repository. Read this file
completely before your first edit. Read it again if you have been working for
more than an hour.

---

## 0. Read order

On any new session, read in this order and do not skip:

1. `CLAUDE.md` (this file) — how to work here
2. `IDEATION.md` — **why** we are building this and why not the obvious
   alternatives. Contains the evidence base, the resolved open questions and the
   amendment ledger. Read before `PRD.md`.
3. `PRD.md` — what we are building and why; the requirement IDs you must satisfy
4. `ARCH.md` — how it is built; the data model and layer contracts
5. `NOTE.md` — decisions, corrections and rejected ideas. **Read this before
   proposing any architectural change.** Most "good ideas" have already been
   considered and rejected here for a stated reason.
6. `TASK.md` — the backlog. Pick the lowest-numbered unblocked task.
7. `SECURITY.md` — before touching anything that executes a scanner, handles a
   credential, or accepts a network target.

---

## 1. What QAVACH is, in one paragraph

QAVACH is a **Cryptographic Asset Inventory and PQC migration decision system**.
It orchestrates existing open-source scanners to discover cryptographic
artefacts across source code, dependencies, binaries, container images, TLS
endpoints, certificates and cloud KMS; reconciles their conflicting output into
one canonical inventory; overlays business context; scores quantum risk using
Mosca's inequality applied per cryptographic function class and CARAF's 5-D
framework; and emits a dependency-ordered migration roadmap.

**QAVACH does not build a crypto-detection *engine*.** If you find yourself
writing an AST visitor or a crypto-detection regex pack, stop and check
`NOTE.md §3.1` first — source analysis is delegated to Opengrep and cdxgen, and
we contribute *rules*, not a matcher.

QAVACH **does** build collectors. A TLS handshake, a JKS parse, a KMS API call
and a binary import-table walk are parsers and API clients, not analysis
engines, and seven of our nine collectors are ours. See `IDEATION.md §5` for the
build/integrate line — it was drawn too broadly in an earlier revision of this
file and the correction is deliberate.

QAVACH's *value* is reconciliation, risk intelligence and sequencing. Discovery
is table stakes.

---

## 2. Non-negotiable invariants

These are correctness properties. Violating one is a bug even if tests pass.

**I1 — Four finding classes, never one.**
Every finding is classified into exactly one of:
- `QUANTUM_VULNERABLE` — Shor-breakable asymmetric (RSA, DSA, DH, ECDH, ECDSA, EdDSA)
- `CLASSICAL_WEAK` — broken today, independent of quantum (MD5, SHA-1, DES, 3DES, RC4, ECB, RSA<2048)
- `GROVER_AFFECTED` — symmetric/hash with halved effective strength (AES-128, SHA-256 in some uses). **Informational. Never rendered as "migrate now."**
- `QUANTUM_SAFE` — ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS, AES-256, SHA-384/512

A tool that flags AES-128 as "quantum vulnerable — migrate immediately" is
wrong and will be dismissed by any reviewer who knows the field. Do not let
this leak into the UI, the report, or the default severity mapping.

**I2 — Harvest-now-decrypt-later applies to confidentiality only.**
HNDL urgency is computed for KEM / key-agreement / encryption assets. For
signature and MAC assets, HNDL does not apply; their shelf life `X` is the
period the signed artefact must remain trustworthy *after* CRQC arrival.
An ephemeral TLS server certificate has `X ≈ 0`. A firmware root of trust or
an offline root CA has `X = 10–25 years`. Getting this backwards inverts the
entire priority ordering.

**I3 — `Z` (CRQC arrival) is a configurable policy input, never a hardcoded fact.**
It lives in `config/policy/*.yaml`, ships as three cited scenarios, and every
number QAVACH prints that depends on `Z` must state which scenario produced it.
See `ARCH.md §7.3`.

**I4 — Confidence is never averaged, conflicts are never silently resolved.**
When two tools disagree about the same asset, both records are retained, the
higher-precedence one becomes the *concluded* value, and the asset is marked
`disputed: true`. See `ARCH.md §6.4`.

**I5 — The exported CBOM must validate against the CycloneDX 1.7 schema.**
QAVACH-specific intelligence (risk scores, business context, roadmap position)
goes into the **Crypto Risk Register**, a separate document that references
`bom-ref` values — *not* into the CBOM body. Namespaced `qavach:` entries in
`properties[]` are permitted and must be documented in
`docs/CUSTOM_PROPERTIES.md`. A CI check enforces both rules.

**I6 — Scanner execution is untrusted-code execution.**
No scanner ever runs outside the sandbox described in `SECURITY.md §3`.
No dependency resolution (`mvn`, `npm install`, `go mod download`, `pip
install`) is ever run against a scan target with network access enabled unless
the operator has explicitly set `--allow-build-resolution` for that job.

**I8 — `UNKNOWN` is a finding class and never renders as safe.**
An asset we could not classify, an algorithm we could not resolve, or a key
whose size we could not determine is `UNKNOWN`. It is rendered distinctly
(grey/hatched, never green), counted separately in every aggregate, and reported
as a **coverage failure**, not a risk verdict.

A competitor ships a dashboard where 68% of keys are `unknown-bit` and 134 of
them are coloured as safe; an algorithm literally labelled `unknown` carries a
green bar (`IDEATION.md §2.2c`). That is how a tool tells a CISO their estate is
fine when it has simply failed to parse it. **An unclassified asset must never
contribute to a "safe" count.** "We could not classify 12% of your estate" is
the most actionable sentence on the screen, not something to hide.

**I9 — Only assets the operator can change enter the roadmap.**
Every asset carries a `MigrationAuthority` (`ARCH.md §4.1`). `SELF` units enter
the migration DAG. `VENDOR` units are dependencies with an ETA. `REGULATOR_GATED`
units are named blockers. `EXTERNAL_TRUST_ANCHOR` — public CAs, OS trust stores,
certificates embedded in third-party installers — are inventoried and **never
ranked, never alerted on, never scheduled.** Skipping this is how a real
inventory becomes an unusable ten-thousand-row HIGH bucket.

**I7 — Air-gap must remain possible.**
No feature may *require* outbound internet at scan time. Enrichment that needs
the network (advisory feeds, CT logs, registry lookups) is optional, degrades
gracefully, and is disabled by `QAVACH_OFFLINE=1`.

---

## 3. Repository layout

```
qavach/
  apps/
    api/            FastAPI service — HTTP + WebSocket. No business logic here.
    worker/         RQ workers. Runs collectors and the pipeline.
    agent/          Deployed host agent — outbound-poll-only, mTLS, typed scan-spec only. Imports packages/collectors/ directly; owns no parsing logic of its own. See ARCH.md §3a.
    web/            React + TypeScript + Vite SPA.
  packages/
    core/           Domain model, pure Python, ZERO I/O and ZERO framework imports.
      model/        CryptoAsset, Occurrence, Finding, Evidence, MigrationUnit
      normalize/    CycloneDX 1.7 canonicalisation, Cryptography Registry lookup
      reconcile/    Identity keys, merge, confidence precedence, dispute marking
      risk/         Mosca per function class, CARAF 5-D, scoring
      recommend/    PQC alternative selection, hybrid guidance, perf table
      roadmap/      Migration DAG, topological sort, cycle→hybrid-bridge
    collectors/     One module per source. All implement Collector protocol.
      source_scan/  cdxgen cbom, cbomkit-lib adapter, opengrep adapter
      sbom/         syft adapter, purl→crypto-library mapping
      container/    cbomkit-theia adapter (also used agent-side, ARCH.md §3a)
      tls/          Active TLS/certificate network collector  (QAVACH-built)
      ssh/          SSH host-key probe (network) + sshd_config (agent)
      ad/           Certipy-wrapped AD Certificate Services collector, network-mode
      cloud/        AWS KMS/ACM, Azure Key Vault, GCP KMS       (QAVACH-built)
      hsm/          PKCS#11 config + vendor library evidence     (QAVACH-built)
      artefact/     Deployed-artefact (WAR/EAR/JAR) collector, agent-only
      runtime/      tracebom adapter (optional)
    sandbox/        Container execution, resource limits, egress policy
    storage/        SQLAlchemy models, repositories, Alembic migrations
  config/
    policy/         Z scenarios, regulatory deadlines, risk tolerance
    knowledge/      Algorithm registry overlay, crypto-library DB, perf table
  docs/
  tests/
```

**Filesystem paths above map to `src/`-layout Python packages** — e.g.
`packages/core/model/` is importable as `qavach_core.model` (distribution
name `qavach-core`), not as a bare top-level `model`. Every workspace member
follows the same `packages/<x>/src/qavach_<x>/...` / `apps/<x>/src/qavach_<x>/...`
pattern (`NOTE.md §7`, T-001) — a bare top-level import name would risk
colliding with a real PyPI package.

**`packages/core` may not import** FastAPI, SQLAlchemy, requests, boto3, or
anything in `collectors/`. It is pure functions over the domain model. A test
in `tests/test_architecture.py` enforces this by import inspection. If you need
I/O in a core function, you have the layering wrong — pass the data in.

**The agent does not get its own copy of collector logic.** `apps/agent/` is
a thin runtime shell — poll loop, mTLS client, PyInstaller entrypoint — that
imports `packages/collectors/tls/` and `packages/collectors/hsm/` directly,
the same modules the sandboxed-subprocess path calls. Do not create a
`packages/collectors/host/` tree: it would fork the exact parsing logic
(`cryptography`, `pyjks`, stdlib `zipfile`) into two places that would drift
the moment either one is patched — the same failure this repo already avoids
elsewhere by keeping every source behind one `Collector` protocol
(`ARCH.md §2.1`). The deployed-artefact (WAR/EAR/JAR) collector is genuinely
new work with no existing home in `ARCH.md §2.2`'s table, and gets its own
module, `packages/collectors/artefact/`, alongside `tls/`, `hsm/` and
`cloud/` — not a subdirectory of a `host/` package, since the sandboxed path
has no use for it either.

---

## 4. Stack, fixed

| Concern | Choice | Do not substitute |
|---|---|---|
| Core language | Python 3.12 | |
| API | FastAPI + Pydantic v2 | |
| Jobs | Redis + RQ (sync workers) | Collectors are blocking subprocess calls; async buys nothing |
| DB | PostgreSQL 16, SQLAlchemy 2.0, Alembic | |
| Frontend | React 18 + TypeScript + Vite | |
| Data fetching | TanStack Query | |
| Styling | Tailwind + shadcn/ui | |
| Charts | Recharts | |
| Graph viz | Cytoscape.js (`dagre` layout) | Not D3 — we need DAG layout and 5k+ nodes |
| CBOM lib | `cyclonedx-python-lib` | |
| X.509 | `cryptography` (pyca) | |
| Sandbox | Docker or Podman, per-job container | |
| Packaging | `uv` for Python, `pnpm` for JS | |

Scanners are **never** imported as libraries. They are invoked as subprocesses
or containers behind an adapter with a JSON contract. This is what keeps a
five-runtime toolchain manageable.

---

## 5. Commands

```bash
make dev              # postgres + redis + minio, then API :8000 and web :5173
make test             # pytest + vitest
make test-unit        # pytest packages/ -m "not integration"   (no services needed)
make lint             # ruff + mypy + biome
make fmt              # ruff format + biome format  — run before every commit
make schema-check     # validate sample CBOMs against CycloneDX 1.7
make scanners-pull    # pull pinned scanner container images
make demo             # seed the demo dataset and open the UI
```

`make test-unit` must pass with **no** Docker, Postgres or network. Keep it that
way — it is the loop you will run hundreds of times.

Integration tests are marked `@pytest.mark.integration` and require `make dev`.

---

## 6. How to work

**Pick one task from `TASK.md`.** Tasks carry IDs (`T-014`). Reference the ID in
the branch name and the commit subject. Do not start a task whose `blocked-by`
tasks are open.

**Write the test first for anything in `packages/core`.** Core is pure; there is
no excuse. Collectors get integration tests against recorded fixtures in
`tests/fixtures/scanner-output/` — do not hit the network in tests.

**When you finish a task**, tick it in `TASK.md` in the same commit and append a
line to the decision log in `NOTE.md` *only if you made a decision that future
readers would otherwise have to re-derive.* Do not log routine work.

**Commit format:** `T-014: reconcile — add SPKI fingerprint identity for certs`

---

## 7. Things that will waste your time — do not do them

- **Do not build a crypto-detection engine.** See `NOTE.md §3.1`.
- **Do not invent an algorithm naming taxonomy.** CycloneDX 1.7 ships a
  Cryptography Registry with canonical algorithm families and curves precisely
  because tools disagree on naming. Use it. `ARCH.md §5.2`.
- **Do not put risk scores inside the CBOM.** Invariant I5.
- **Do not add a new runtime.** Four is already too many.
- **Do not deepen the Grype integration.** Grype finds CVEs, not cryptography.
  It is a nice-to-have edge, not a pillar. `NOTE.md §3.4`.
- **Do not write a large Opengrep rule pack.** Opengrep is the low-confidence
  breadth tier for languages the AST scanners miss. High false-positive volume
  is expected and is handled by the confidence tier, not by rule tuning.
  `NOTE.md §3.3`.
- **Do not hardcode a CRQC date.** Invariant I3.
- **Do not use an LLM anywhere.** Not in scoring, not in classification, not for
  prose. The risk engine must be deterministic, auditable and reproducible — the
  same CBOM must always produce the same risk register. **LLM-assisted narrative
  is out of scope for v1 and the feature flag ships disabled**; it will be
  ideated separately before any code is written. `NOTE.md §4.6`.
- **Do not colour an unknown asset green.** Invariant I8.
- **Do not put a public CA or an OEM firmware key in the roadmap.** Invariant I9.
- **Do not store a scalar `key_size: int`.** Ed25519 has no bit-length in the
  RSA sense and ML-DSA-65 has a parameter set. `ARCH.md §4.2`.

---

## 8. When you are unsure

If a requirement in `PRD.md` and a design in `ARCH.md` conflict, `PRD.md` wins
and you flag it in `NOTE.md`.

If `ARCH.md` is silent on something load-bearing, do not guess and do not
quietly pick. Write the question into `NOTE.md §6 Open Questions`, implement the
smallest defensible thing behind an interface, and mark the code
`# QAVACH-OPEN: <question id>`.

If a claim about a standard, a date or an algorithm matters to correctness,
**verify it against a primary source** (NIST CSRC, CycloneDX spec, the RFC,
the DST/MeitY report) and cite the URL in a code comment. Do not trust this
document's summary of an external standard over the standard itself; this file
was written on 2026-09-06 and standards move.
