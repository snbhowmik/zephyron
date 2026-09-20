# ARCH.md — QAVACH Architecture

Version 1.0, 2026-09-06. Companion to `PRD.md`. Read `NOTE.md` before proposing
changes here.

---

## 1. Shape of the system

```
                 ┌───────────────────────────────────────────┐
                 │  React SPA — dashboard, inventory, graph  │
                 └───────────────┬───────────────────────────┘
                                 │ REST + WebSocket
                 ┌───────────────▼───────────────────────────┐
                 │  FastAPI  (transport only, no logic)      │
                 └───────────────┬───────────────────────────┘
                                 │ enqueue
                 ┌───────────────▼───────────────────────────┐
                 │  RQ workers — pipeline orchestration      │
                 └───────────────┬───────────────────────────┘
                                 │
   ┌─────────────────────────────┼─────────────────────────────┐
   │                             │                             │
┌──▼──────────────┐   ┌──────────▼──────────┐   ┌──────────────▼──┐
│ L1 COLLECTION   │──▶│ L2 NORMALISATION    │──▶│ L3 RECONCILE    │
│ sandboxed       │   │ CDX 1.7 + Registry  │   │ identity, merge │
└─────────────────┘   └─────────────────────┘   └──────────┬──────┘
                                                            │
   ┌────────────────────────────────────────────────────────┘
   │
┌──▼──────────────┐   ┌─────────────────────┐   ┌─────────────────┐
│ L4 CONTEXT      │──▶│ L5 RISK             │──▶│ L6 RECOMMEND    │
│ systems, crit.  │   │ Mosca + CARAF       │   │ PQC, hybrid     │
└─────────────────┘   └─────────────────────┘   └────────┬────────┘
                                                          │
                                       ┌──────────────────▼────────┐
                                       │ L7 ROADMAP — DAG, waves   │
                                       └──────────────────┬────────┘
                                                          │
                                       ┌──────────────────▼────────┐
                                       │ L8 EXPORT — CBOM, RR, PDF │
                                       └───────────────────────────┘
```

L1 is delegated. **L2 through L7 are QAVACH.** That is the whole thesis of the
project and the honest answer to "what did you build."

---

## 2. Layer 1 — Collection

### 2.1 The Collector protocol

Every source, whether a third-party binary or something QAVACH wrote, sits
behind one interface. This is what keeps a five-runtime toolchain sane.

```python
# packages/collectors/base.py
class Collector(Protocol):
    name: str
    version: str
    default_confidence: ConfidenceTier
    requires_sandbox: bool
    requires_network: bool

    def supports(self, target: Target) -> bool: ...
    def collect(self, target: Target, ctx: RunContext) -> CollectorResult: ...

@dataclass(frozen=True)
class CollectorResult:
    raw: bytes                 # verbatim tool output, archived for audit
    raw_format: RawFormat      # CDX_1_6 | CDX_1_7 | SARIF | SYFT_JSON | QAVACH_NATIVE
    claims: list[RawClaim]     # parsed, not yet normalised
    tool: ToolIdentity         # name, version, invocation, exit code, duration
    errors: list[CollectorError]
    partial: bool              # true if the tool failed midway; claims still usable
```

Rules:
- A collector **never** writes to the database.
- A collector **never** merges or deduplicates. It reports what its tool said.
- `raw` is always retained. When a reviewer asks "did the tool really say
  that," the answer must be a stored artefact, not a reconstruction.
- A collector failing is a degraded scan, not a failed scan. `partial=True`,
  surface it in the UI, continue.

### 2.2 The collectors

**Delegated — subprocess or container, pinned by digest:**

| Collector | Tool | Gives us | Confidence |
|---|---|---|---|
| `source_scan.cdxgen` | cdxgen `cbom` command (npm package `@cdxgen/cdxgen` — renamed from `@cyclonedx/cdxgen` in v13; the old scope only receives fixes, never v13+ features. **Pin the new name.**) | Java keystore/certificate inventory, plus JS/TS source-level algorithm detection via lightweight constant propagation over `node:crypto`/WebCrypto/JWT call sites | AST |
| `source_scan.cbomkit` | **cbomkit-lib** (Apache-2.0), invoked directly — not the full CBOMkit app | Deep AST detection for Java, Python, Go (C# in development, not yet usable — `docs/THIRD_PARTY.md` note when written) | AST |
| `source_scan.opengrep` | Opengrep, SARIF out | Breadth for C/C++, C#, PHP, Ruby, Rust | PATTERN |
| `sbom.syft` | Syft | Package inventory → crypto-library mapping | DEPENDENCY |
| `container.theia` | CBOMkit-theia (Apache-2.0, Go — fully standalone, **no sonar-cryptography/GitHub-Packages dependency** unlike `cbomkit-lib`) | Five plugins: **certificates** (X.509 PEM/DER only — no JKS/PKCS12, complementary to certfinder, not redundant), **secrets** (private/public/secret key files — a hardcoded key here is a critical finding per `SECURITY.md §5.1`), **javasecurity** (executability confidence 0–1 for crypto components found in Java code — direct support for the capability-vs-usage honesty rule, `NOTE.md §3.5`), **opensslconf** (TLS protocol/cipher suites from `openssl.cnf`), and **problematicca** (undocumented in its own README — a curated list of compromised/distrusted/deprecated CAs matched by DN, with severity). Runs on container images **and local directories** — not container-only. Output is CDX 1.6; our normaliser upgrades it per `§5.1`. | DEPENDENCY |
| `runtime.tracebom` | cdxgen `tracebom` | Actually negotiated TLS suites, dynamically loaded providers, CDX 1.7 | RUNTIME |
| `ad.adcs` | Certipy (`find -json`), MIT | AD Certificate Services templates, CA configuration, ESC1–ESC8 misconfigurations | ATTESTED |
| `tls.store` | certfinder (Apache-2.0) **and** CBOMkit-theia's `dir` command (Apache-2.0) — both subprocess, both agent-side | certfinder: PEM/DER/JKS/JCEKS/PKCS#12 filesystem walk, key algorithm/size/curve, SHA-256 and **SPKI SHA-256** fingerprint (feeds the CA identity rule, §6.1). Theia `dir`: secrets/private-key detection, OpenSSL config (`opensslconf`) TLS protocol/cipher extraction, known-bad-CA flagging (`problematicca`) — additive, not overlapping (its own `certificates` plugin is PEM/DER only, no JKS/PKCS12). | ARTEFACT |

Notes that will bite you if you ignore them:
- **Correction to an earlier decision (see `NOTE.md §3.2`): do not run the
  full CBOMkit application as a sidecar.** `cbomkit-lib` (github.com/cbomkit/
  cbomkit-lib) is now its own standalone, actively-maintained, Apache-2.0 Java
  library — it is not merely a GitHub-Packages-only artifact, and it does not
  require the Quarkus/Vue/Postgres CBOMkit app at all. **The CBOMkit app's own
  README states it does not build the target repository before scanning**,
  which measurably reduces Java accuracy (unresolved symbols) — exactly the
  gap `cbomkit-action` exists to close by building first
  (`mvn clean package`) and passing jar/class directories to the scanner.
  QAVACH's own sandbox already controls build-resolution timing
  (`--allow-build-resolution`, §3.1), so build our own thin container image
  wrapping `cbomkit-lib` directly, run the target's build first when allowed,
  then invoke the scanner with jar/class paths configured — the same
  sequencing `cbomkit-action` uses, without depending on the GitHub Actions
  runtime it's built for.
- **The one real credential cost is `com.ibm:sonar-cryptography-plugin`**,
  `cbomkit-lib`'s actual detection engine, published via GitHub Packages by
  the separate `sonar-cryptography` repo and requiring a
  `~/.m2/settings.xml` PAT with `read:packages` to resolve at build time.
  This is a **one-time cost at QAVACH's own image-build/release time** — the
  credential never touches a scan job or the sandbox, since the resulting
  image is pinned by digest like any other scanner. `sonar-cryptography`'s
  own detection-rule coverage and licence are **not yet evaluated** — deferred
  deliberately; verify before this becomes a real build dependency.
- No CBOMkit sidecar, no Postgres, no OPA — drop both from `§13`'s deployment
  list; QAVACH never needed CBOMkit's own database or compliance engine, only
  its scanner.
- **cdxgen invokes real build tools** (`mvn`, `npm install`, `go mod`) to
  resolve dependencies. That is arbitrary code execution on the scan target's
  terms. Invariant I6 and `SECURITY.md §3` are not optional here.
- **cdxgen deliberately emits no purl for `type: cryptographic-asset`
  components**, and requires source-derived `assetType: algorithm` components to
  carry a known OID. Our normaliser must preserve both behaviours or exports
  fail validation.
- **`cbom`'s own crypto detection is narrower than the general SBOM-generation
  capability cdxgen is known for**: Java keystores/certificates and JS/TS
  source-level algorithms only, via lightweight constant propagation — not a
  general multi-language AST engine. It is **complementary to `cbomkit-lib`**,
  not overlapping: different languages, different mechanism. Do not expect it
  to cover Python or Go crypto usage; that is `cbomkit-lib`'s job.
- **`--component-type cryptographic-asset` requires `--spec-version 1.6` or
  newer** on cdxgen's own side — consistent with, and independent evidence
  for, the CycloneDX 1.7 canonical choice in `§5.1`.
- **Recommended install pins with `--ignore-scripts --min-release-age=2`**
  (cdxgen's own documented practice) — adopt the same when the pinned image
  in `config/scanners.yaml` is rebuilt (`SECURITY.md §7`). The `cbom` release
  binary needs no JDK on linux-amd64/arm64 (glibc), linux-amd64-musl and
  darwin-arm64/windows-amd64, but falls back to a JVM (Java 23+) on
  darwin-amd64, windows-arm64 and linux-arm64-musl — check which triple the
  pinned build target is before assuming no JDK is needed.
- **Opengrep is LGPL-2.1.** Separate process only (NFR-10).
- **Certipy is MIT-licensed and needs only LDAP plus any authenticated domain
  credential** — no host install, no agent involvement. It runs as a
  network-mode sandboxed subprocess (§2.3), the same shape as `tls.endpoint`.
  **PingCastle covers similar ground but its Non-Profit OSL 3.0 licence
  forbids commercial bundling** — it fails `NFR-10` the same way a
  hypothetical RSAL tool would. Never a shipped dependency; it may be named as
  an optional operator-supplied external-report ingestion path, the same
  shape as external CBOM ingestion (FR-180), and no more than that. ADRecon
  (AGPLv3, separate-process-only per the same rule already applied to
  Opengrep) and BloodHound CE (Apache-2.0, but an attack-path graph tool with
  no crypto-inventory purpose) were both evaluated and deprioritised — see
  `NOTE.md §7`.
- **certfinder does the filesystem walk and fingerprinting for `tls.store`; it
  does not do PKCS#7 or CycloneDX mapping.** Those stay QAVACH's own code,
  layered on top of certfinder's output inside the deployed agent (§3a). Its
  22-commit history is a maintenance risk worth re-checking before v1 ships —
  if it goes stale, the fallback is `cryptography`/`pyjks` doing the walk
  directly, which is more code but no new dependency.
- **testssl.sh (GPLv2) covers the classical half of what `tls.endpoint` needs**
  cleanly, but no existing scanner — testssl.sh, sslyze, or nmap's NSE
  scripts — probes hybrid post-quantum key-exchange groups
  (`X25519MLKEM768`), which is exactly what makes `tls.endpoint` worth owning.
  Whether to wrap testssl.sh for the classical parameters and layer a thin
  custom probe only for hybrid-group negotiation, versus keeping the whole
  collector custom, is not yet decided — track as a `TASK.md` item before
  Phase 3 implementation. sslyze (AGPL-3.0) and nmap (non-standard NPSL
  licence, and its `ssl-enum-ciphers`/`ssl-cert` scripts are flagged
  "intrusive" — too noisy for a discovery tool) were both ruled out.

**QAVACH-built — nobody provides these off the shelf, and clause (i) of the
problem statement demands them:**

| Collector | What it does | Confidence |
|---|---|---|
| `tls.endpoint` | asyncio TLS scanner. Per endpoint: protocol version, cipher suite, negotiated key-exchange group, full chain, per-cert public-key algorithm + size + curve, signature algorithm, validity, SANs, SHA-256 fingerprint, SPKI hash. Probes for hybrid group support. | RUNTIME |
| `cloud.aws` | Read-only. KMS `ListKeys`/`DescribeKey` → `KeySpec`. ACM `ListCertificates`/`DescribeCertificate`. ELBv2 TLS policies. Secrets Manager KMS key refs. | ATTESTED |
| `cloud.azure` / `cloud.gcp` | Same interface, Key Vault and Cloud KMS. | ATTESTED |
| `hsm.evidence` | PKCS#11 config files, vendor client libraries on disk, `SunPKCS11` JVM config, slot references in application config. Reports an **unresolved crypto boundary**, not a resolved asset. | EVIDENCE |
| `ssh.hostkey` | Host key algorithms, sizes, fingerprints; `sshd_config` KEX/cipher/MAC lists. | RUNTIME |

The TLS collector is the highest value-per-line-of-code component in the whole
project. It closes the largest gap in the problem-statement coverage, it is
maybe 400 lines with `cryptography` and `asyncio`, and it is the source of the
most visually convincing demo data.

### 2.3 Two execution modes

L1 collection now has two mutually exclusive execution modes, selected by the
target's type, never by collector preference:

| Mode | Applies to | Detail |
|---|---|---|
| **Sandboxed subprocess** (§3) | `source_scan.*`, `sbom.syft`, `container.theia`, `tls.endpoint`, `ad.adcs`, `cloud.*`, `runtime.tracebom`, external CBOM/SBOM ingest (FR-180) | Untrusted code runs against a mounted or fetched target on QAVACH-controlled infrastructure. Network is off by default. |
| **Deployed agent** (§3a) | `tls.store`, `hsm.evidence`, the deployed-artefact collector (WAR/EAR/JAR), and the local-file half of `ssh.hostkey` (`sshd_config`) | QAVACH-controlled code runs on operator-controlled infrastructure it does not own. There is no sandboxed-subprocess fallback for these four — a live host's filesystem, real keystores and real HSM configuration are never mounted into a sandbox. |

Why exclusive, not additive: a sandboxed subprocess reads a *mounted* target —
a copy or a network path QAVACH controls. A live host's `/etc/pki`, its JKS
files and its `sshd_config` are not something we mount; they are something we
must be pushed. Modelling this as "the same collector, plus an optional agent
transport" would leave two divergent code paths claiming to produce the same
evidence, and only one of them would ever actually run for a Host target. So:
one target, one mode, no variant.

The **TLS endpoint collector** (`tls.endpoint`) is unaffected by any of this —
it is a network probe with no filesystem access, and it stays on the
sandboxed-subprocess path even when the target is a Host. `ssh.hostkey`'s
network-probe half likewise stays sandboxed; only its `sshd_config` half moves
to the agent (`PRD.md FR-160`).

---

## 3. Layer 1 execution — the sandbox

Every collector with `requires_sandbox = True` runs in a fresh container:

```
--network=none                    (unless the collector declares requires_network)
--read-only  --tmpfs /work:size=2g,noexec  --tmpfs /tmp:size=512m,noexec
--user 65534:65534  --cap-drop=ALL  --security-opt no-new-privileges
--pids-limit 512  --memory 4g  --cpus 2
timeout: per-collector, default 900s
```

The scan target is mounted read-only. Output leaves via the container's
stdout — captured with `docker logs` after exit, before removal — not a file
on the tmpfs mount (`SECURITY.md §3` has the reason: a tmpfs mount does not
survive `docker cp` once its container has stopped, verified live in T-031).
`/work` and `/tmp` remain scratch space, still `noexec,nosuid,nodev` — `/tmp`
was added after T-032 found a real scanner (cdxgen's `cbom`) fails under
`--read-only` otherwise, hardcoding `/tmp/cdxgen-temp` regardless of `TMPDIR`.
Nothing but the one stdout blob crosses the boundary.

Build-tool dependency resolution needs network and is therefore **off by
default**. `--allow-build-resolution` enables it with an egress allowlist
(registry hosts only) and prints a warning naming the risk. Full detail in
`SECURITY.md §3`.

---

## 3a. Layer 1 execution — the deployed agent

`tls.store`, `hsm.evidence`, the deployed-artefact collector and the
`sshd_config` half of `ssh.hostkey` (§2.3) run through a small Python agent
installed on the target host, not through the sandbox in §3. The trust
direction is reversed from everything else in L1: this is **our** code,
running with real filesystem and key-material access, on infrastructure **we
do not control**. See `SECURITY.md §2a` for the threat model this implies.

### Hard rules, non-negotiable

- **Outbound-poll-only. The agent never listens.** It opens a connection to
  the backend, asks "do you have work for me," runs it, posts results, and
  closes. A listening agent turns every enrolled host into a reachable
  service on the customer's network. No configuration opens an inbound port,
  ever.
- **The wire protocol accepts a typed scan spec, not a command.** The backend
  sends `{paths: [...], collectors: [...]}` — a closed vocabulary of module
  names and filesystem paths. There is no `exec`, no shell, no arbitrary
  payload field. This is the single most important hardening property of the
  agent: a compromised backend or a spoofed spec still cannot run an
  attacker's code on the host, only re-run a collector QAVACH already ships
  against a path.
- **Least privilege.** The agent runs as a low-privilege service account.
  Where it needs to read a specific `0600` keystore or PKCS#11 config, the
  operator grants a scoped ACL or sudo rule for that path — never blanket
  root, never a standing elevated service account.
- **Redaction is never the agent's job.** `SECURITY.md §5.1`'s secret-detection
  and redaction stay authoritative on the backend. The agent may enforce a
  size cap on an oversized payload before transmitting it; it must never be
  trusted to decide what is a secret, because a compromised agent could be
  made to skip that step silently.
- **One egress target.** The agent is configured with exactly one backend URL
  and talks to nothing else — no fallback endpoint, no telemetry, no update
  channel other than the same backend connection. Same rule as `SECURITY.md
  §5`'s no-telemetry clause and `NFR-05`'s air-gap requirement, applied to a
  process that lives outside our infrastructure.
- **Python only.** `CLAUDE.md §4` — no new runtime. The agent reuses the exact
  `cryptography` / `pyjks` / stdlib `zipfile` parsing code the centralised
  collectors already call, imported from `packages/collectors/`, not
  reimplemented. It is packaged as a single-file bundle (PyInstaller or
  equivalent) so it runs on a host with no Python of its own.

### Transport

Mutual TLS. The agent presents the client certificate it received at
enrollment; it verifies the backend's certificate against a pinned CA rather
than trusting whatever is offered. There is no unauthenticated fallback mode.

### Enrollment (FR-133)

```
1. Operator generates a short-lived, single-use enrollment token from the
   dashboard, scoped to exactly one host.
2. Operator installs the agent binary and the token on that host.
3. Agent exchanges the token for a rotatable long-lived client credential
   (POST /api/v1/agents/enroll — see §12) and registers itself: identity,
   host, OS/platform.
4. The token is consumed. It cannot enroll a second host and cannot be
   replayed.
5. The dashboard's sensor-management view (FR-133) lists every enrolled
   agent's identity, host, online/offline status and per-run history.
```

The registered **agent identity** issued at step 3 — not any operator-supplied
hostname string — is what evidence is attributed to. See `HostLocus` in §6.2:
an operator-typed hostname can be wrong or spoofed; the identity the backend
itself issued cannot.

### Binary integrity

The agent artefact is signed and provenance-attested, extending `SECURITY.md
§7`'s supply-chain guarantees to a binary that runs outside our
infrastructure. Before applying an update, the agent verifies the new
artefact's signature against the pinned release key. A failed verification
aborts the update and keeps running the last-known-good binary.

### Known-paths manifest (FR-134)

In addition to whatever explicit paths the operator supplies from the
dashboard, the agent auto-scans a curated, per-OS/per-platform manifest of
common certificate, keystore, HSM-config and appserver locations —
`config/knowledge/host_known_paths.yaml` — covering Tomcat, JBoss/WildFly,
WebLogic, WebSphere, nginx, Apache httpd, IIS, the Windows certificate store
and the standard Linux certificate directories. This is the same category of
curation effort as `config/knowledge/crypto_libraries.yaml` (`NOTE.md §3.5`
calls that "genuine, unglamorous work, budget for it explicitly"; the same is
true here) — a manifest that does not exist off the shelf in usable form, and
the difference between an agent that finds what the operator remembered to
list and one that finds what is actually there.

### Storage and API surface

Agent identity and run history live in two new tables, `agents` and
`agent_runs` (§11), alongside `collector_runs` — an agent run is the host-mode
analogue of a collector run, not a new kind of scan. New endpoints for
enrollment exchange, agent listing, spec polling and result posting are in
§12.

### Containment for hostile input, without a container

`SECURITY.md §9` requires guards against zip-slip and decompression bombs when
parsing JKS/PKCS#12 — a malformed keystore is hostile input whether it is
parsed inside a sandboxed subprocess or by the agent. Under the
sandboxed-subprocess model, a parser bug is contained by `--network=none`,
`--cap-drop=ALL`, a throwaway container. The agent has no container.

**Resolved: the agent parses every fetched file in a short-lived, resource-limited
worker process, never inline in the agent's main process.** This is not a novel
design — three independent endpoint-agent projects converged on the same
pattern (osquery's watchdog/worker split, Velociraptor's "nanny," GRR Rapid
Response's dedicated unprivileged subprocess for its native artifact-parsing
libraries), and GRR's case is the direct precedent: it specifically isolates
the libraries that touch disk artifacts pulled from a possibly-compromised
host, which is exactly `cryptography`/`pyjks`/`zipfile`'s role here. Concretely:

```
1. Fork (or subprocess.run) a worker per file, or a small batch.
2. Apply resource.setrlimit: CPU time, address-space size, output size.
   Plus a hard wall-clock timeout at the supervisor level.
3. Drop the worker to the most restricted account the agent's own
   low-privilege service account can reach — no supplementary groups.
4. Pass the fetched bytes in; get RawClaims back over a pipe.
5. On any breach (timeout, OOM, non-zero exit) — kill the worker, mark the
   occurrence partial (§2.1's collector-result contract), continue with the
   rest of the batch. One crafted keystore never hangs or crashes the agent.
```

This is a resource-limited subprocess, not a full container — it does not
replace least privilege and scoped ACLs, it backstops them for the specific
failure mode a container would otherwise have caught: a parser bug or a
decompression bomb consuming the process it runs in.

---

## 4. Canonical data model

`packages/core/model/`. Pure dataclasses. No ORM, no framework, no I/O.

```python
class AssetType(StrEnum):          # CycloneDX cryptoProperties.assetType
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-crypto-material"

class CryptoFunction(StrEnum):     # drives Mosca — see §7.2
    KEY_ENCAPSULATION = "key-encapsulation"
    KEY_AGREEMENT     = "key-agreement"
    ENCRYPTION        = "encryption"
    SIGNATURE         = "signature"
    MAC               = "mac"
    HASH              = "hash"
    KDF               = "kdf"
    DRBG              = "drbg"

class FindingClass(StrEnum):       # invariant I1
    QUANTUM_VULNERABLE = "quantum-vulnerable"
    CLASSICAL_WEAK     = "classical-weak"
    GROVER_AFFECTED    = "grover-affected"
    QUANTUM_SAFE       = "quantum-safe"
    UNKNOWN            = "unknown"

class MigrationAuthority(StrEnum): # A-3 — who can actually change this
    SELF                   = "self"                    # we own the code/config/key
    VENDOR                 = "vendor"                  # OEM/SaaS firmware or product
    EXTERNAL_TRUST_ANCHOR  = "external-trust-anchor"   # public CA, OS trust store, 3rd-party installer residue
    REGULATOR_GATED        = "regulator-gated"         # NPCI/UIDAI/CCA/sector regulator specifies the crypto
    UNKNOWN                = "unknown"                 # triage queue

class ConfidenceTier(IntEnum):     # higher wins — see §6.4
    RUNTIME    = 100   # observed on the wire or in the process
    ARTEFACT   = 90    # the actual certificate or key was parsed
    ATTESTED   = 80    # a cloud/HSM API declared it
    DEPENDENCY = 60    # package identity implies the capability
    AST        = 50    # semantic source analysis
    PATTERN    = 30    # regex / textual match
    HEURISTIC  = 10    # name similarity

@dataclass(frozen=True)
class CryptoAsset:
    identity: AssetIdentity          # §6.1 — the merge key
    asset_type: AssetType
    function: CryptoFunction
    algorithm_family: str            # canonical, from the CDX 1.7 registry
    parameter_set: str | None        # "2048", "P-256", "ML-KEM-768"
    curve: str | None                # canonical, from the CDX 1.7 curve registry
    mode: str | None                 # "CBC", "GCM"
    padding: str | None              # "OAEP", "PKCS1v15"
    oid: str | None
    finding_class: FindingClass
    migration_authority: MigrationAuthority   # §4.1 — roadmap eligibility
    authority_basis: str                      # the derivation rule that fired
    occurrences: tuple[Occurrence, ...]
    concluded_from: ConfidenceTier
    disputed: bool
    disputes: tuple[Dispute, ...]

    # NOTE: there is deliberately no scalar `key_size: int` field. See §4.2.

@dataclass(frozen=True)
class Occurrence:
    locus: Locus                     # §6.2 — where, precisely
    collector: str
    tool_version: str
    confidence: ConfidenceTier
    detection_method: str            # CycloneDX evidence.identity method vocabulary
    raw_ref: str                     # pointer into the archived raw output
    observed_at: datetime

@dataclass(frozen=True)
class System:                        # the business unit of migration
    id: str
    name: str
    owner: str
    criticality: int                 # 1..5
    data_classification: DataClass
    retention_years: float
    retention_inferred: bool
    internet_facing: bool
    regulatory_regimes: frozenset[str]
    depends_on: frozenset[str]
```

**Asset vs. System is the load-bearing distinction.** Assets are what scanners
find. Systems are what humans migrate, budget for and own. Risk is computed per
asset, decided per system, and sequenced per system. Do not collapse them.

### 4.1 Migration Authority — who can actually change this

Observed evidence (`IDEATION.md §2.2d`): a competitor's shipping product ranks
`Sectigo RSA Code Signing CA` as **HIGH**, discovered inside two downloaded
installers. The operator cannot migrate Sectigo's CA. Ranking assets nobody can
act on is what turns a real inventory into an unusable 10,788-row HIGH bucket.

| Value | Treatment in the roadmap |
|---|---|
| `SELF` | A migration item. Enters the DAG (§9). |
| `VENDOR` | A **dependency**, not a task. Vendor-engagement action, unbounded ETA. |
| `EXTERNAL_TRUST_ANCHOR` | **Never ranked, never alerted on.** Inventoried for completeness only. |
| `REGULATOR_GATED` | Blocked by a named external party. Surfaced as a blocker, not a backlog item. |
| `UNKNOWN` | Triage queue. Never defaults to `SELF`. |

Derivation is rule-based and recorded in `authority_basis`:

- issuer chains to a public root **and** every locus is inside third-party
  software → `EXTERNAL_TRUST_ANCHOR`
- locus is an OEM firmware image or a SaaS endpoint we do not operate → `VENDOR`
- the system carries a regulatory regime whose crypto profile is externally
  specified (NPCI, UIDAI, CCA India PKI) → `REGULATOR_GATED`
- locus is in the operator's own repo, keystore, config or cloud account → `SELF`
- otherwise → `UNKNOWN`

**The sentence this field exists to produce:** *"You own 1,240 of these. 8,900
belong to Microsoft, Sectigo and your OEMs. 648 are gated on NPCI publishing a
PQC specification."* One field plus a derivation rule, and the headline number
becomes actionable.

### 4.2 Key size is not an integer

Observed evidence (`IDEATION.md §2.2b`): a competitor's key-size distribution
contains `0-bit` (34 assets), `unknown-bit`, `2450-bit` and `281-bit`. There is
no 2450-bit RSA key — those are parse artefacts charted as data. `0-bit` is
Ed25519 and PQC certificates forced into a field that does not apply to them.

**Rules:**

- Store `parameter_set` (the CycloneDX `parameterSetIdentifier`) and, only where
  it is meaningful, a separate modulus length. Ed25519 has no bit-length in the
  RSA sense; ML-DSA-65 has a parameter set, not a key size.
- A modulus length outside the plausible set for its family goes to the
  **data-quality queue**, not to a chart. Implausible values are a collector bug
  and must be visible as one.
- Never render "0" for "not applicable". Render the parameter set.

---

## 5. Layer 2 — Normalisation

### 5.1 Version normalisation

Inputs arrive as CycloneDX 1.4, 1.5, 1.6, 1.7, SARIF, Syft JSON or QAVACH
native. **Canonical internal form is CycloneDX 1.7.**

Why 1.7 and not 1.6 — this is a correction to an earlier decision, see
`NOTE.md §2.2`:

- 1.7 (released late Oct 2025) is backward compatible with 1.4–1.6, so we can
  ingest CBOMkit's 1.6 output without loss.
- 1.7 introduces the **CycloneDX Cryptography Registry** — authoritative,
  machine-readable definitions of algorithm families and elliptic curves,
  created specifically because different tools name the same algorithm
  differently. That is *exactly* the problem the reconciliation layer exists to
  solve, and it means we adopt an authority instead of inventing a taxonomy.
- 1.7 adds the `algorithmFamily` object and a standardised curve enumeration
  (deprecating 1.6's free-text `curve`).
- cdxgen's `tracebom` already emits 1.7.

We downgrade to 1.6 on export for consumers that need it (FR-520).

### 5.2 Algorithm canonicalisation

`packages/core/normalize/registry.py` loads the CycloneDX Cryptography Registry
JSON Schema (vendored at a pinned version into
`config/knowledge/cdx-crypto-registry/`) and resolves any tool's spelling to a
canonical `(algorithm_family, parameter_set, curve, primitive)` tuple.

The resolution order:
1. **OID.** If the tool supplied one, it is authoritative. This is why cdxgen
   drops algorithm components it cannot map to an OID, and we should be glad.
2. **Registry exact match** on family name.
3. **Registry alias table** — our overlay in `config/knowledge/aliases.yaml`
   for the spellings tools actually emit (`EC` / `ECDSA` / `ecdsa-with-SHA256`,
   `RSA` / `RSASSA-PKCS1` / `rsaEncryption`, `Curve25519` / `X25519` /
   `curve25519`, `Kyber768` / `ML-KEM-768` — the last one matters because
   pre-standardisation names are everywhere in real codebases).
4. **Unresolvable** → asset is retained with `finding_class = UNKNOWN` and
   surfaced in an "unclassified" bucket. Never silently dropped. An unresolved
   algorithm is a finding: it means something in the estate uses cryptography
   nobody recognises.

The alias table is real, curated work and one of the few knowledge assets
QAVACH must own. Budget time for it.

**Curve canonicalisation is a distinct, explicit stage (A-18).** `secp256r1`,
`prime256v1`, `P-256`, `NIST P-256` and `1.2.840.10045.3.1.7` are one curve.
Canonicalise to the OID where one exists, otherwise to the registry token,
*before* identity hashing (§6.1) — otherwise the same key lands under several
identities and `disputed` can never fire. A CI test runs the full alias corpus.

**PQC OIDs must resolve (A-19).** Observed evidence (`IDEATION.md §2.2a`): a
competitor's dashboard displays `2.16.840.1.101.3.4.3.17`,
`2.16.840.1.101.3.4.4.1` and `2.16.840.1.101.3.4.4.2` as if they were algorithm
names. Those arcs are the NIST ML-DSA/SLH-DSA signature arc and the ML-KEM arc.
A post-quantum tool that cannot name the algorithms it recommends migrating *to*
is not credible. Golden test: every OID in the NIST PQC arcs resolves to a named
parameter set and classifies `QUANTUM_SAFE`, never `UNKNOWN`. Verify each
mapping against the registry — do not hand-write them from memory.

### 5.3 Crypto-library knowledge base

`config/knowledge/crypto_libraries.yaml` maps a purl range to the cryptographic
capability it implies:

```yaml
- purl_pattern: "pkg:maven/org.bouncycastle/bcprov-jdk18on@*"
  provides: [rsa, ecdsa, ecdh, aes, sha2, sha3, ml-kem, ml-dsa, slh-dsa]
  pqc_support:
    ml-kem: ">=1.78"
    ml-dsa: ">=1.78"
  confidence: DEPENDENCY
  note: "Capability, not usage. Presence does not prove the algorithm is called."
  source: "https://www.bouncycastle.org/releasenotes.html"
```

**This mapping does not exist off the shelf in usable form.** Curating it for
the top ~150 crypto libraries across Java, Python, Go, JS, .NET, C/C++ and Rust
is a genuine deliverable, not a config file you fill in on the last day. It is
also the thing that makes an SBOM useful for PQC purposes, which is why nobody
else's SBOM tool answers this question well.

Critical honesty rule: a dependency finding proves **capability**, not **usage**.
The UI must say "this system *can* do RSA" not "this system *does* RSA" until an
AST or runtime occurrence corroborates it. Conflating the two is the single most
common way crypto inventory tools inflate their numbers.

---

## 6. Layer 3 — Reconciliation

The core contribution. Four tools scan one repository and report the same
RSA-2048 four different ways. This layer produces one asset.

### 6.1 Asset identity

```python
def asset_identity(claim: NormalisedClaim) -> AssetIdentity:
    if claim.asset_type is AssetType.CERTIFICATE:
        # A certificate is an instance, not a class. Two RSA-2048 certs are
        # two assets. Identity is the artefact itself.
        #
        # EXCEPT for CA certificates (A-7, resolves OQ-03): the risk lives in
        # the KEY, not the encoding. A CA reissued with the same key is the same
        # risk asset; a rekeyed CA is a new one. So a CA carries a two-tier
        # identity — SPKI hash is the class that holds the verdict, and each
        # fingerprint-keyed certificate is an occurrence of it.
        if claim.is_ca and claim.spki_sha256:
            return AssetIdentity(kind="ca-key", key=claim.spki_sha256)
        return AssetIdentity(kind="cert", key=claim.sha256_fingerprint)

    if claim.asset_type is AssetType.RELATED_MATERIAL:
        # Keys likewise. SPKI hash when we have the public key; otherwise the
        # keystore alias plus locus, which is weaker and is marked as such.
        return AssetIdentity(kind="key", key=claim.spki_sha256 or claim.material_ref)

    # Algorithms and protocols are classes: same algorithm in ten files is one
    # asset with ten occurrences.
    #
    # A-5: hash the CORE only. Usage qualifiers (mode, padding, digest) are
    # properties of a CALL, not of the key, and live on the Occurrence.
    return AssetIdentity(kind="algo", key=sha256_hex(canonical_json({
        "family":    claim.algorithm_family,
        "params":    claim.parameter_set,
        "curve":     claim.curve,          # canonicalised — see §5.2
        "primitive": claim.primitive,
        "oid":       claim.oid,
    })))
```

The instance/class split is the part people get wrong. Certificates and keys are
individuals — merging them destroys the inventory. Algorithms are types —
*not* merging them produces 40,000 duplicate rows and an unusable UI.

**Why `mode` and `padding` left the hash (A-5).** If they are in the identity,
an attested KMS claim (silent about call-time padding) and an AST claim that
correctly observes PKCS#1 v1.5 **hash to different identities and never
collide** — so `disputed` can never fire. You get two parallel assets, one of
them looking safe, and the real finding is hidden. Splitting identity into a
key-intrinsic **core** (hashed) and per-occurrence **usage qualifiers** is a
structural fix, not a tuning knob.

### 6.2 Locus

```python
Locus = (
    SourceLocus(repo, commit, path, start_line, end_line)
  | DependencyLocus(purl, dependency_path)
  | ContainerLocus(image_digest, layer_digest, path)
  | RuntimeLocus(process, module, observed_at)
  | NetworkLocus(host, port, sni, protocol)
  | CloudLocus(provider, account, region, resource_arn)
  | HsmLocus(module_path, slot_ref)
  | FileLocus(path, offset)                # local mount — target is implicit
  | HostLocus(host_identity, path, offset) # agent-collected — names which host
)
```

`HostLocus.host_identity` is the agent's registered identity issued at
enrollment (§3a) — never an operator-typed hostname string. A typed string
can be wrong or spoofed; the identity the backend itself issued cannot.
`FileLocus` is unchanged and stays scoped to local-mount contexts
(binary/image scanning); it is not repurposed for agent evidence.

Occurrences are **never** merged across locus types. Ten files is ten
occurrences. That is what makes the blast radius of an asset visible, and blast
radius is what drives the migration effort estimate in §8.2.

### 6.3 Merge

```
group claims by asset_identity
for each group:
    occurrences  = every claim, retained
    concluded    = per-attribute resolution (§6.4), NOT one winning claim
    usages       = union of per-occurrence usage qualifiers
    disputed     = per attribute, within a single occurrence (see below)
    finding_class = classify(concluded, worst_of(usages))
```

Core attributes (identity-bearing): `algorithm_family`, `parameter_set`,
`curve`, `primitive`, `oid`.
Usage attributes (per occurrence): `mode`, `padding`, `digest`,
`crypto_function`, protocol context.
Non-material: line numbers, tool phrasing, evidence text.

**Multi-usage is not dispute (A-5).** The same RSA key used with OAEP at one
call site and PKCS#1 v1.5 at another is two true facts, not a conflict. Dispute
fires only when two sources disagree **about the same occurrence**. The asset's
verdict is computed over the **worst** member of the usage set.

### 6.4 Confidence precedence and disputes

Precedence is the `ConfidenceTier` ordering in §4 — but it is applied **per
attribute class**, not per claim (A-5). The rationale is epistemic, not
arbitrary: a TLS handshake you observed beats a certificate you parsed beats an
API that told you beats a package that implies it beats source that might be
dead code beats a regex that might be a comment.

| Attribute class | Dominant claim type |
|---|---|
| key spec, curve, parameter set, lifecycle | `ATTESTED`/`ARTEFACT` > usage-observing > declared |
| **mode, padding, digest, function** | **usage-observing (`AST`, `RUNTIME`) > `ATTESTED`** > declared |
| locus | union — never resolved |

**Invariant: silence is not a claim.** A source that does not observe an
attribute contributes nothing to it and cannot outrank a source that does. A
cloud KMS API describes the key it holds; it says nothing about the padding an
application chose at call time, and must not win on that field by tier alone.
This is the single most likely silent-failure mode in this layer.

Disputes are therefore recorded **per attribute**: an asset can be settled on
key size and disputed on padding, and the UI must show that rather than a single
asset-level flag.

**Never average. Never silently discard.** When the AST scanner says AES-256-GCM
and the pattern scanner says AES-128-CBC at the same locus, that is not noise to
smooth over — it is either a real second call site or a real bug in one of the
tools, and the operator needs to see it. Mark `disputed`, show both, let a human
adjudicate, persist the adjudication.

A `disputed` asset is scored at its **worst** plausible claim until adjudicated.
Failing safe here is right: a tool that under-reports risk while claiming
confidence is worse than useless.

### 6.5 What this layer must never do

Do not "improve" the merge with fuzzy string similarity on algorithm names. That
is what the Cryptography Registry alias table is for, and a fuzzy matcher will
eventually merge `SHA-256` with `SHA3-256` or `X25519` with `X448` and you will
not notice for weeks.

---

## 7. Layer 5 — Risk

### 7.1 Finding classification

```
CLASSICAL_WEAK      MD5, SHA-1, DES, 3DES, RC4, ECB mode, static IV,
                    RSA < 2048, DH < 2048, PKCS#1 v1.5 encryption padding,
                    NULL/anon/EXPORT cipher suites, TLS < 1.2, SSLv3
                    → urgent, but NOT a quantum finding. Say so in the UI.

QUANTUM_VULNERABLE  RSA, DSA, DH, ECDH, ECDSA, EdDSA, ElGamal, and every
                    protocol/certificate/key whose security rests on them
                    → Shor. This is the migration programme.

GROVER_AFFECTED     AES-128, and 128-bit-output hashes used where collision
                    resistance matters
                    → informational. Recommendation is "prefer 256-bit for
                      data with long shelf life", never "migrate now".
                      Grover gives a square-root speedup; AES-128 retains
                      ~64-bit quantum security against a machine that does
                      not exist, and the parallelisation costs are brutal.
                      Redlining AES-128 destroys credibility. Invariant I1.

QUANTUM_SAFE        ML-KEM, ML-DSA, SLH-DSA, LMS, XMSS, AES-256,
                    SHA-384/512, SHA3-*, HMAC over those
                    → confirm and record. "You already did this right" is
                      a finding worth reporting.
```

**MACs and key-derivation functions (added 2026-09-20, OQ-21).** `HMAC`, `PBKDF2` and
`PBES2` are classified by the *output size of the digest they use* (the asset's
`parameter_set`): 384 or more is `QUANTUM_SAFE` ("HMAC over those" above), 128-256 is
`GROVER_AFFECTED` (informational). A MAC is not protected by its digest's collision
resistance, so `HMAC-MD5` and `HMAC-SHA1` are informational, **not** `CLASSICAL_WEAK`.
`PBES1` and `PBKDF1` are `CLASSICAL_WEAK`: RFC 8018 §5.1 and §6.1 say they are
"recommended only for compatibility with existing applications" (PBES1 supports only
56- and 64-bit encryption schemes). `CMAC`, `HKDF` and the password hashes (`scrypt`,
`bcrypt`, `Argon2`) remain `UNKNOWN` until a decision is recorded for them.

An asset may be simultaneously `CLASSICAL_WEAK` and quantum-vulnerable (RSA-1024
is both). Classification picks the **more urgent** class — classical, because
the attack works today — and the asset carries a `also_quantum_vulnerable` flag
so it still appears in the PQC programme scope.

### 7.2 Mosca, applied correctly

Mosca's inequality: **if X + Y > Z, you are already late.**

- `X` — how long the protected thing must stay secure
- `Y` — how long migration will take
- `Z` — when a cryptographically relevant quantum computer arrives

The mistake almost every implementation makes is using one `X` for everything.
`X` depends on what the cryptography is *doing* (invariant I2):

| Function | `X` is | Typical | Why |
|---|---|---|---|
| `key-encapsulation`, `key-agreement`, `encryption` | The confidentiality retention requirement of the protected data | 5–30 yr | HNDL applies. Traffic recorded today is decrypted after `Z`. |
| `signature` on **ephemeral** artefacts (TLS server certs, tokens, session auth) | ≈ 0 | 0 | Forging a signature after `Z` is useless if the artefact expired before `Z`. A 90-day cert is not an HNDL target. |
| `signature` on **long-lived** artefacts (root CA, code signing, firmware root of trust, notarisation, legal archives) | Remaining period the artefact must be trusted **beyond** `Z` | 10–25 yr | A root CA issued today and trusted until 2045 must resist forgery from `Z` to 2045. |
| `mac`, `hash` (integrity) | Same split as signature | | |
| `drbg`, `kdf` | Inherit `X` from what they feed | | |

This is why the demo in `PRD.md §7` shows an offline root CA and a TLS server
certificate — same algorithm, same key size, wildly different urgency. That
divergence is the clearest single demonstration that QAVACH's risk model is
doing real work.

**`X` is two quantities, not one (A-4).** A single `X` cannot carry both jobs,
and the national roadmap names both attack classes explicitly — *Harvest Now,
Decrypt Later* (HNDL) **and** *Trust Now, Forge Later* (TNFL) — in the DST/NQM
report, §Executive Summary. Cite it.

| | `X_conf` | `X_integ` |
|---|---|---|
| Question | How long must the data stay confidential? | How long must the signature stay unforgeable? |
| HNDL | Applies | Does not apply |
| Late migration | **Unrecoverable** — harvested ciphertext cannot be un-harvested | **Recoverable** — re-signing or re-timestamping before the deadline is a valid mitigation |
| Mitigation language in the UI | "migrate before `Z`" | "migrate or re-sign before `Z`" |

This closes the archival-signature gap: RFC 3161 timestamps, audit logs and
SCADA command logs under multi-year retention take `X_integ` from retention
policy, **not** the ephemeral-artefact exemption.

```python
def shelf_life_years(asset: CryptoAsset, system: System) -> ShelfLife:
    """Returns (x_conf, x_integ, basis). Mosca consumes max(x_conf, x_integ),
    but the two carry different rationale strings and different mitigations."""
    fn = asset.function
    if fn in CONFIDENTIALITY_FUNCTIONS:
        return ShelfLife(system.retention_years, 0.0, "hndl:data-retention")
    if fn in AUTHENTICITY_FUNCTIONS:
        lifetime = artefact_trust_lifetime(asset, system)   # cert notAfter, firmware support window
        if lifetime is None:
            return ShelfLife(0.0, 0.0, "authenticity:ephemeral")
        return ShelfLife(0.0, lifetime, "tnfl:long-lived-artefact")
    return derive_from_consumers(asset, system)


def derive_from_consumers(asset: CryptoAsset, system: System) -> ShelfLife:
    """Shared/derived key material (KDF, DRBG, a master secret feeding several
    consumers). A-4: aggregate with max() over consumers, per channel,
    propagating UPWARD along the derivation chain only.

    A root secret inherits the maximum of everything beneath it.
    A child inherits NOTHING from its parent.

    TLS 1.3 worked example: handshake traffic keys are x_conf ~ 0, but the
    resumption master secret is nonzero wherever tickets are persisted — so the
    handshake secret inherits nonzero x_conf.
    """
    consumers = derivation_consumers(asset, system)
    if not consumers:
        return ShelfLife(0.0, 0.0, "derived:no-known-consumers")   # NOT "safe" — see I8
    return ShelfLife(
        max(c.x_conf for c in consumers),
        max(c.x_integ for c in consumers),
        "derived:max-over-consumers",
    )
```

> **Directional asymmetry — this will be implemented backwards at least once.**
> Shelf life aggregates with `max()` **upward** along derivation chains.
> Shared-resource deadlines (one HSM or root CA serving many systems) aggregate
> with `min()` **downward**. See §9.2.

### 7.3 `Z` and the regulatory override

`Z` is unknowable. Any tool printing a single confident CRQC date is lying, and
a knowledgeable reviewer will say so. QAVACH ships three cited scenarios in
`config/policy/z_scenarios.yaml` and makes the choice visible everywhere:

```yaml
scenarios:
  aggressive:   { crqc_year: 2030, basis: "vendor logical-qubit roadmaps; upper-bound planning" }
  nominal:      { crqc_year: 2033, basis: "median of published expert elicitation" }
  conservative: { crqc_year: 2038, basis: "error-correction overhead scepticism" }
default: nominal
```

Then the observation that makes this actually useful for an Indian CII
operator:

```yaml
# A-1 CORRECTION: the DST/NQM roadmap is SIX dates across TWO tracks, not three.
# Source: "Quantum-Safe Ecosystem in India: Roadmap to Quantum Resiliency",
# DST / National Quantum Mission, May 2026, §7 and §9. Annexure B restates it
# operationally (critical apps Jan 2027–Dec 2029; non-critical Jan 2029–Dec 2033).
#
# CII sectors are ENUMERATED in §9: government, strategic, defence, power,
# telecom, transport, BFSI. Track selection is a stated property of the
# organisation, never an inference.
regulatory_deadlines:
  # --- CII track (urgent adopters) ---
  in_dst_cii_m1_foundations:   { date: 2027-12-31, scope: [cii],
                                 basis: "DST/NQM May 2026, Milestone 1 — inventory, governance, pilots" }
  in_dst_cii_m2_highpriority:  { date: 2028-12-31, scope: [cii],
                                 basis: "DST/NQM May 2026, Milestone 2" }
  in_dst_cii_m3_full:          { date: 2029-12-31, scope: [cii],
                                 basis: "DST/NQM May 2026, Milestone 3" }
  # --- Enterprise track (regular adopters) ---
  in_dst_ent_m1_foundations:   { date: 2028-12-31, scope: [enterprise], basis: "same, Milestone 1" }
  in_dst_ent_m2_highpriority:  { date: 2030-12-31, scope: [enterprise], basis: "same, Milestone 2" }
  in_dst_ent_m3_full:          { date: 2033-12-31, scope: [enterprise], basis: "same, Milestone 3" }
  # --- Sector-binding, as distinct from nationally scheduled ---
  in_sebi_cscrf_inventory:     { date: 2025-08-31, scope: [sebi-re], binding: true,
                                 basis: "SEBI CSCRF + June 2025 FAQ — crypto asset inventory, deadline passed" }
  nist_ir8547_deprecated: { date: 2030-12-31, scope: [us-federal],
                            basis: "NIST IR 8547 ipd (Nov 2024), still draft as of mid-2026" }
  nist_ir8547_disallowed: { date: 2035-12-31, scope: [us-federal], basis: "same" }
  cnsa2_acquisition_gate: { date: 2027-01-01, scope: [nss], basis: "NSA CNSA 2.0" }
```

```python
Z_effective = min(Z_scenario, *applicable_regulatory_deadlines(system))
```

The applicable deadline depends on **track × milestone**: an asset the operator
has marked high-priority in a CII organisation is bound by M2 (2028); the same
asset in a non-CII enterprise is bound by M2 (2030). Milestone selection is a
business-context input, not a technical property.

The UI must always state which one bound. For an Indian CII operator under the
DST roadmap, `Z_effective` is 2028 or 2029 — **years before any plausible CRQC
date.** The binding constraint is compliance, not physics. Surfacing that
inverts the whole conversation from speculative to operational, and it is the
most NTRO-relevant thing in the product.

Note the DST roadmap is advisory; enforcement sits with sector regulators. The
policy file therefore lets an operator mark a deadline `binding: true|false`,
and the UI distinguishes the two.

### 7.4 `Y` — migration time

`Y` is estimated, not guessed, from a factor model in
`config/policy/migration_effort.yaml`. Base effort by locus and asset type,
multiplied by blockers:

| Factor | Multiplier | Rationale |
|---|---|---|
| PQC-capable library version available | ×1.0 | drop-in |
| Library has no PQC support yet | ×3.0 | wait on upstream — external blocker |
| Protocol not yet PQC-standardised | ×4.0 | wait on IETF |
| Hardware / HSM bound | ×5.0 | firmware, procurement, possibly replacement |
| Third-party SaaS you do not control | ×6.0 | vendor management, contractual |
| Signature-size sensitive (embedded, constrained links) | ×2.0 | ML-DSA is much larger than ECDSA |
| Wire-format or protocol change required | ×2.5 | coordinated rollout |
| Occurrence count > 50 | ×1.5 | blast radius |

Every multiplier is an operator-overridable default with a stated rationale.
Do not present these as measured facts. They are planning heuristics and the
UI must label them as such.

**A-10 — adopt the DST/NQM factor set as the published basis.** The roadmap's
"Technology Considerations for Quantum-Safe Migration Across CII" names six
factors. Using these rather than invented weights means every factor cites the
national roadmap instead of our judgement, which is the difference between a
heuristic and a defensible one:

| DST factor | How QAVACH observes it |
|---|---|
| **Latency sensitivity** — manageable at millisecond scale, problematic at microsecond scale (defence, telecom) | System class + protocol context |
| **Handshake frequency** — long-lived sessions minimal impact; frequent renegotiation or short-lived sessions amplify PQC cost | Discoverable from TLS/config: session resumption, keep-alive, cert lifetime |
| **User/service tolerance** — safety-critical and financial systems cannot absorb degradation | Business context input |
| **Hardware constraints** — long-lived platforms, embedded devices and certified systems may lack compute headroom | Maps to `hardware-gate` (×5.0) |
| **Vendor dependence** — migration depends on OEMs for firmware and backward compatibility | Maps to `MigrationAuthority.VENDOR` (×6.0) |
| **Cross-border dependencies** — alignment with international standards bodies | Maps to `protocol-not-standardised` (×4.0) |

Handshake frequency is the factor we did not previously have and it **is**
discoverable. Add it as a multiplier. `OQ-02` remains open on calibration.

### 7.4a Policy applicability scope (A-12)

Observed evidence (`IDEATION.md §2.2f`): a competitor's compliance page reports
`CNSA 2.0 — Assessed 21224, Compliant 0, Violations 21224`. A policy that flags
100% of an estate carries no information. CNSA 2.0 binds US National Security
Systems; applying it wholesale to a commercial Indian estate is a category
error rendered as a finding.

Every policy template therefore carries an **applicability scope**, and the
engine enforces three rules:

1. A policy evaluates only assets within its declared scope. Out-of-scope assets
   are reported as `not-applicable`, never as compliant and never as violating.
2. Compliance results are always `(asset × policy)` with the **denominator
   shown**. Never render a bare violation count that can exceed the asset count.
3. A policy whose in-scope violation rate exceeds a configured threshold
   (default 95%) is flagged as a **scoping problem** in the UI, not as a result.

### 7.5 CARAF, correctly

Correction to an earlier assumption: CARAF is **not** `Risk = Timeline × Cost`.
See `NOTE.md §2.1`. CARAF (Ma, Colon, Dera, Rashidi, Garg — *Journal of
Cybersecurity* 7(1), 2021, tyab013) is a **five-dimension framework**:

| CARAF dimension | QAVACH layer |
|---|---|
| D1 Determine the threat vector | Finding classification (§7.1) |
| D2 Inventory impacted assets | L1–L3 discovery and reconciliation |
| D3 Estimate the expected value of the asset being compromised | Business-context overlay × exposure × Mosca gap |
| D4 Identify the mitigation strategy commensurate with that value | The four outcomes below |
| D5 Develop a roadmap per risk class | L7 (§9) |

CARAF explicitly incorporates Mosca's XYZ as its threat-timing model, which is
why the two compose cleanly rather than being bolted together.

**D3 — expected value of compromise:**

```
EV = business_criticality      # 1..5, from the operator
   × data_sensitivity          # 1..5, from data classification
   × exposure_factor           # internet-facing 1.5 / partner 1.2 / internal 1.0
   × mosca_gap_factor          # f(X + Y − Z_effective), clamped
```

**D4 — mitigation strategy.** Compare `EV` against migration cost and the
organisation's risk tolerance (`config/policy/risk_tolerance.yaml`):

| Outcome | When | Example |
|---|---|---|
| **Migrate** | `EV` high, migration feasible | RSA-2048 TLS on an internet-facing payments API |
| **Compensating control** | `EV` high, migration blocked (`Y` enormous, hardware-bound, vendor-controlled) | Legacy HSM-bound signing → network isolation, shortened key lifetimes, monitoring, plus a procurement plan |
| **Accept** | `EV` below risk tolerance | ECDSA on a 90-day internal service cert with no HNDL exposure |
| **Phase out** | Asset value below the cost of migrating it | An unmaintained internal tool on 3DES — decommission, do not migrate |

That "Accept" and "Phase out" are first-class outcomes is the point. A tool
whose only recommendation is "migrate everything" is useless to an enterprise
with a finite budget, and CARAF is what gives us a principled reason to say
"leave this alone." This is a real differentiator — lead with it.

---

## 8. Layer 6 — Recommendation

### 8.1 Algorithm selection

`config/knowledge/pqc_alternatives.yaml`, keyed by `(function, constraints)`:

| Replace | With | Standard | Status as of 2026-09 |
|---|---|---|---|
| RSA-OAEP, ECDH, DH (key establishment) | ML-KEM-768 | FIPS 203 | **Final**, 2024-08-13 |
| RSA-PSS, ECDSA, EdDSA (general signing) | ML-DSA-65 | FIPS 204 | **Final**, 2024-08-13 |
| Signing where lattice diversity is wanted | SLH-DSA | FIPS 205 | **Final**, 2024-08-13 |
| Firmware / boot signing, stateful acceptable | LMS or XMSS | SP 800-208 | Final |
| Backup KEM, different maths | HQC | — | **Selected 2025-03-11, standard not yet published.** Not a compliance claim. |
| Signature-size-constrained | FN-DSA (Falcon) | FIPS 206 | **In development as of mid-2026.** Do not recommend as final. |

`FR-410` is a hard requirement. Presenting HQC or FN-DSA as available standards
is the kind of error a domain reviewer catches instantly. Every entry in the
YAML carries a `status` field and a `verified_on` date; the UI renders draft
status prominently; a CI check fails the build if any `verified_on` is more than
180 days old, forcing a re-verification against NIST CSRC.

### 8.2 Hybrid guidance

Hybrid is contextual, not universal:

- **General TLS during transition → hybrid** (e.g. `X25519MLKEM768`). Preserves
  interoperability with non-PQC peers; the classical half provides security if
  the PQC half is broken and vice versa. NIST IR 8547 supports hybrid during
  transition.
- **CNSA 2.0 / national-security context → pure PQC preferred.** State the
  regime's position rather than QAVACH's opinion.
- **Constrained links, embedded, bandwidth-critical → flag the size cost.**
  Hybrid means carrying both, and ML-DSA signatures are already an order of
  magnitude larger than ECDSA. This is where FN-DSA would help, once it exists.
- **Long-term archival confidentiality → PQC must carry the weight.** After
  2035 the classical half contributes nothing.

### 8.3 Performance and cost — FR-430

`config/knowledge/performance.yaml`. Key sizes, ciphertext/signature sizes,
keygen/sign/verify/encaps/decaps timings, TLS handshake byte overhead. **Every
row cites a primary source** (FIPS documents, the NIST PQC project pages, liboqs
published benchmarks, IETF drafts) with a `measured_on` platform note.

Do not fabricate a single number here. If a figure is unavailable, the field is
`null` and the UI shows "not available" — which is honest and costs nothing.
An invented benchmark is the fastest way to lose a technical reviewer.

Optional, if time allows: a `bench` command that runs liboqs locally and writes
into the same schema, clearly marked as locally measured.

---

## 9. Layer 7 — Roadmap

### 9.1 The migration DAG

Nodes are **migration units** — normally a `(System, CryptoFunction)` pair,
because a system migrates its key establishment and its signing on different
schedules for different reasons.

Typed edges, each meaning "the tail must be done before the head":

| Edge | Meaning |
|---|---|
| `trust-anchor` | A CA must be re-keyed before its subordinates and relying parties can validate PQC chains |
| `protocol-peer` | Both ends must speak the new suite. Server before client, or hybrid to allow either order |
| `library-availability` | A system cannot migrate until its crypto library ships PQC. External blocker: a leaf with an ETA, not an assignable task |
| `hardware-gate` | HSM/TPM/secure-element firmware support |
| `data-format` | **Reader before writer.** All consumers must be able to *verify* the new signature format before any producer starts *emitting* it. Get this backwards and you break production on cutover day |
| `build-and-sign` | Code-signing infrastructure migrates before the artefacts it signs |
| `regulatory-gate` | **A-6 — resolves OQ-01.** A certification body, sector regulator or standards authority must sign off before the unit can be declared complete |

The reader-before-writer rule is the one real operators will recognise
immediately, and it is the kind of detail that signals the design came from
thinking about deployment rather than about slides.

**`regulatory-gate` is structurally different from the other six and needs node
splitting.** It gates the *end* of a unit, not its start; it allows parallel
submission; and it fails by rework-and-requeue with no vendor ETA. So every
migration unit is modelled as two nodes:

```
unit.start ──(work)──▶ unit.complete
   ▲                        ▲
   │                        │
ordinary precedence     regulatory-gate
edges land here         edges land here
```

A unit behind a regulatory gate can **start** on schedule and still be unable to
**complete**. A wave containing an unbounded gate is not a dated wave: mark it
`schedule_risk: unbounded` and render no ETA. Inventing one is worse than
admitting the gap.

This edge is real for any Indian CII operator given the TEC/STQC/BIS L1–L4
certification framework, and for BFSI given NPCI/UIDAI/CCA crypto profiles.

**Two constraint kinds that are NOT precedence edges (A-6):**

- **Key escrow / legal hold is a *retention* constraint.** Model it as
  `destroy_prohibited_until` plus a legal-hold flag that hard-blocks any destroy
  action. Add the edge most teams miss: **decrypt-capability retention** — you
  cannot remove the *classical implementation* from the codebase while escrowed
  ciphertext exists under hold. Teams delete the old code path years before the
  old keys; that is silent, permanent data loss.
- **Shared-resource capacity is a scheduling constraint, not a DAG edge.**
  See §9.2.

### 9.2 Sequencing

```
0. Filter by MigrationAuthority (§4.1). Only SELF units enter the DAG.
   VENDOR units become dependency leaves with an ETA and a contact action.
   REGULATOR_GATED units become named blockers.
   EXTERNAL_TRUST_ANCHOR units never enter the roadmap at all.
1. Topologically sort the DAG over (unit.start, unit.complete) node pairs.
2. Within each wave, order by Mosca urgency descending: (X + Y − Z_effective).
3. Assign target quarters by scheduling backwards from the binding regulatory
   deadline, respecting a per-wave capacity limit (operator-configured
   parallel-migrations-per-quarter).
4. Aggregate shared-resource deadlines with min() DOWNWARD: an HSM or root CA
   serving several systems inherits the EARLIEST of its dependents' deadlines.
5. Flag any unit whose earliest feasible completion is after its binding
   deadline as SCHEDULE_INFEASIBLE — with the specific blocking chain shown,
   and the contended resource named where contention is the cause.
```

Step 0 is what makes the roadmap usable. Without it, the DAG fills with public
CAs and OEM firmware the operator cannot touch, and the output degrades into the
same undifferentiated list every other tool produces.

**Scope honesty on step 4.** Capacity contention — one HSM firmware window
serving forty systems — is a resource-constrained project scheduling problem,
not a DAG problem. v1 **detects and names** infeasibility and the contended
resource. It does not attempt to solve the scheduling problem. Say so in the UI.

Step 4 matters. "You cannot meet Dec 2028 because your HSM vendor's PQC
firmware is not expected until Q3 2028 and eleven services depend on it" is
worth more to a CISO than any dashboard.

### 9.3 Cycles

A cycle in the DAG is not a bug in the graph builder. It is a genuine mutual
dependency — service A signs for B and B signs for A, so neither can move
first.

The real-world answer is a **hybrid / dual-stack bridge**: both endpoints run
classical and PQC simultaneously for a window, then the classical half is
retired. QAVACH detects the strongly connected component, emits a
`HybridBridgeRequirement` naming every member, and schedules the bridge as its
own wave.

Emitting this as a first-class recommendation rather than an error is a small
thing that reads as operational maturity.

**Not every cycle can use the hybrid bridge (A-6).** Certificate pinning is the
exception: a static pin-set cannot run dual-stack, so "deploy both, then retire
one" is not available. The variant is **pin-superset → rotate → prune**:

```
Phase A  Publish a pin SUPERSET containing both the classical and the PQC SPKI.
Phase B  Soak. GATE ON ADOPTION TELEMETRY, NOT ON A CALENDAR DATE.
Phase C  Rotate the server key to the PQC SPKI.
Phase D  Soak again.
Phase E  Prune the classical pin.
```

The adoption gate is the load-bearing detail. Pinning failures are silent and
total — a client with a stale pin-set simply cannot connect, and no error
reaches the operator. A time-based gate will brick the long tail. For
app-embedded pinning, model app-store update lag explicitly: it is months and it
is not under the operator's control. Require a client-version floor and a backup
pin before scheduling Phase C.

---

## 10. Layer 8 — Export

| Artefact | Format | Contents |
|---|---|---|
| CBOM | CycloneDX 1.7 JSON, schema-valid | Assets, occurrences as `evidence.occurrences[]`, provenance as `evidence.identity[].methods[]`, tool metadata |
| CBOM (compat) | CycloneDX 1.6 JSON | Downgraded |
| Crypto Risk Register | QAVACH JSON, schema in `docs/schema/risk-register-1.0.json` | Risk scores, Mosca inputs and outputs, CARAF outcome, recommendation, roadmap position — all keyed by CBOM `bom-ref` |
| Executive report | PDF | Posture, top risks, roadmap, budget envelope |
| Asset register | XLSX | One row per asset, filterable |
| CI | SARIF 2.1.0 | For pipeline gating |

**Invariant I5 restated because it will be violated otherwise:** risk scores do
not go in the CBOM. The CBOM is a standards artefact other tools consume; a
polluted one is worthless for interchange. QAVACH intelligence lives in the Risk
Register and references `bom-ref`s. Namespaced `qavach:` `properties[]` entries
are the only exception and must be documented in `docs/CUSTOM_PROPERTIES.md`.

There is IETF work in progress on exactly this boundary — a "Cryptographic Asset
Inventory" schema distinguishing an org-level inventory (covering hardware and
services) from a component-level CBOM (an SBOM extension). QAVACH produces a CAI
assembled from many CBOMs plus non-software collectors. That is the correct
framing to use when describing the output, and it is worth tracking the draft.

### 10.1 BOM scope — component, system, root

Every export in the table above accepts a **scope** parameter (FR-501):

| Scope | Boundary |
|---|---|
| `component` | One collector run or one agent run (§3a) — the output of a single scan. |
| `system` | Everything bound to one `System` (§4, `asset_systems`), including any vendor-supplied CBOM ingested under FR-180 and reconciled against it per CERT-In §8.4.1.8. |
| `root` | The whole organisation — every asset across every system. |

**These are three views over the single asset graph L3 (§6) already
reconciles — not three separately-merged documents.** Do not build `root` by
re-merging `system` BOMs, and do not build `system` by re-merging `component`
BOMs. Re-merging would duplicate L3's identity, confidence-precedence and
dispute logic in a second place, and the two would drift the first time either
one is touched. The correct implementation is **scope as a query parameter on
export** (`GET /api/v1/scans/{id}/export/cbom?scope=system&system_id=...`,
§12): filter the already-reconciled asset set by the requested scope's asset
membership, then run the existing single export path over the filtered set.
Reconciliation happens exactly once, upstream of every scope.

---

## 11. Storage

Postgres 16. Assets and occurrences are relational — they are queried,
faceted and joined constantly, and JSON blobs would make the inventory view
slow and the code awful. Raw scanner output goes to object storage (MinIO in
dev), referenced by `Occurrence.raw_ref`.

```
scan_runs        (id, target_ref, started, finished, status, policy_snapshot_json)
collector_runs   (id, scan_run_id, collector, tool_version, exit_code, raw_uri, partial)
agents           (id, identity, host, os, enrolled_at, credential_fingerprint, last_seen, status)
agent_runs       (id, agent_id, scan_run_id, scan_spec_json, started, finished, exit_code, raw_uri, partial)
crypto_assets    (id, scan_run_id, identity_key, asset_type, function, family,
                  parameter_set, curve, mode, padding, oid, finding_class,
                  concluded_tier, disputed)
occurrences      (id, asset_id, collector_run_id, locus_type, locus_json,
                  confidence, detection_method, raw_ref)
systems          (id, name, owner, criticality, data_class, retention_years, ...)
asset_systems    (asset_id, system_id)
system_deps      (from_system_id, to_system_id, kind)
risk_scores      (asset_id, policy_version, x, y, z_effective, z_source,
                  mosca_gap, ev, caraf_outcome, explanation_json)
recommendations  (asset_id, target_algorithm, hybrid, rationale_json, citations_json)
migration_units  (id, system_id, function, wave, target_quarter, feasible)
migration_edges  (from_unit_id, to_unit_id, kind, rationale)
suppressions     (id, asset_identity_key, reason, author, expires_at)
audit_log        (id, actor, action, subject, at, detail_json)
```

An `Occurrence` produced by the agent references its `agent_runs.id` the same
way a sandboxed-subprocess occurrence references `collector_runs.id` — an
agent run is the host-mode analogue of a collector run, not a new evidence
type.

`scan_runs.policy_snapshot_json` stores the **entire** policy configuration used
for that run. Without it a score is not reproducible six months later, and
reproducibility is a hard requirement (NFR-09). Never score against "current"
policy; always against the snapshot.

---

## 12. API

```
POST   /api/v1/scans                     start a scan
GET    /api/v1/scans/{id}                status and summary
WS     /api/v1/scans/{id}/progress       live per-collector progress
GET    /api/v1/scans/{id}/assets         faceted, paginated inventory
GET    /api/v1/assets/{id}               detail: occurrences, risk, recommendation
GET    /api/v1/scans/{id}/roadmap        DAG + waves
GET    /api/v1/scans/{id}/export/cbom            ?spec=1.7|1.6&scope=component|system|root
GET    /api/v1/scans/{id}/export/risk-register   ?scope=component|system|root
GET    /api/v1/scans/{id}/export/report.pdf      ?scope=component|system|root
POST   /api/v1/systems/import            CSV or YAML
GET    /api/v1/policy                    active policy + citations
POST   /api/v1/policy/simulate           re-score against a candidate policy — powers the Mosca explorer
POST   /api/v1/assets/{id}/suppress
POST   /api/v1/assets/{id}/adjudicate    resolve a dispute

POST   /api/v1/agents/enroll             exchange a single-use enrollment token for a rotatable credential
GET    /api/v1/agents                    list enrolled agents — identity, host, online/offline, last run
GET    /api/v1/agents/{id}               agent detail: per-run history
GET    /api/v1/agents/{id}/spec          agent polls this for its next scan spec (paths + collector modules)
POST   /api/v1/agents/{id}/results       agent posts collector results back
```

`POST /policy/simulate` is what makes FR-650 responsive: re-scoring is pure
computation over already-reconciled assets, so moving the `Z` slider is a
sub-second round trip with no re-scan. Design the risk layer as pure functions
over stored assets and this comes free; couple it to the database and it does
not.

---

## 13. Deployment

```
docker compose:  api, worker×N, postgres, redis, minio, web
```

No CBOMkit sidecar and no OPA — `source_scan.cbomkit` (§2.2) invokes
`cbomkit-lib` as a pinned scanner image, not the full CBOMkit application;
QAVACH never needed CBOMkit's own database or compliance engine, only its
scanner. The deployed agent (§3a) is not a compose service — it installs on
customer hosts, outside this deployment.

Scanner images are pinned by digest in `config/scanners.yaml` and pulled by
`make scanners-pull`. Air-gap: `make bundle` produces an offline tarball of
every pinned image plus the knowledge base.

Helm chart in `deploy/helm/` for enterprise. Not required for the demo; required
for the deployability claim.
