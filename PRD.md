# PRD.md — QAVACH

Product Requirements. Version 1.0, 2026-09-06.

Target: Smart India Hackathon 2026, Problem Statement **26164**, issued by the
**National Technical Research Organisation (NTRO)**, theme Blockchain &
Cybersecurity.

---

## 1. Problem

Migrating an enterprise to post-quantum cryptography requires knowing what
cryptography it currently runs. Nobody does. Cryptography is scattered across
source code, third-party libraries, container images, TLS endpoints,
certificate stores, HSMs and cloud key services, and no single team owns the
whole picture.

The tooling that exists solves the *first* step only. Scanners emit findings.
They do not tell an enterprise **what to fix first, why, in what order, and what
it will cost to defer.** That decision layer is the gap.

### 1.1 Why this is urgent in India specifically

India has published a national migration timeline, and it is more aggressive
than the US federal one:

**Citation corrected (A-1).** The report was finalised and published
**15 May 2026** as *Quantum-Safe Ecosystem in India: Roadmap to Quantum
Resiliency* (DST, National Quantum Mission). Cite the final version, not the
Feb 2026 draft. It defines **three milestones across two tracks — six dates:**

| Milestone | CII | Enterprise |
|---|---|---|
| M1 — Build foundations (inventory, governance, pilots) | **Dec 2027** | **Dec 2028** |
| M2 — Migrate high-priority systems | **Dec 2028** | **Dec 2030** |
| M3 — Full PQC adoption | **Dec 2029** | **Dec 2033** |

CII sectors are enumerated in the report: government, strategic, defence, power,
telecom, transport, BFSI. Annexure B restates it operationally — critical
applications Jan 2027 to Dec 2029, non-critical Jan 2029 to Dec 2033.

| Other anchor | Date | Source |
|---|---|---|
| MeitY / CERT-In whitepaper *Transitioning to Quantum Cyber Readiness* | Jul 2025 | MeitY, CERT-In |
| CERT-In *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM* v2.0 | 09-07-2025 | CERT-In |
| **SEBI CSCRF crypto-asset inventory — mandatory, deadline passed** | **Aug 2025** | SEBI + Jun 2025 FAQ |
| Tier-1 / Tier-2 PQC testing labs operational (TEC, STQC, BIS) | Dec 2026 | DST/NQM |
| Vendor CBOM submissions mandated in procurement | FY 2027–28 | DST/NQM |

Four facts from these documents matter enormously to this project:

1. The report proposes a national list of cryptography-dependent product
   categories with two India-specific additions, one of which is
   **"automated cryptographic discovery and inventory solutions."** QAVACH is
   that category. This is not a hypothetical market.
2. The roadmap is **advisory**; binding obligations come from sector
   regulators. The report says so explicitly — it "is not itself a regulatory
   mandate" and "enables regulators to define sector-specific timelines." So
   QAVACH must express *multiple* deadline regimes as policy inputs with a
   `binding: true|false` flag, not assume one. A SEBI-regulated entity is
   **bound** by CSCRF and **scheduled** by NQM, simultaneously.
3. **CERT-In mandates two-sided CBOM reconciliation.** §8.4.1.8: *"Consumer
   organizations must create an internal CBOM/QBOM aligned with the supplier's
   data."* Suppliers must provide a complete CBOM; consumers must reconcile it
   against what is deployed. This is not a workflow we invented to justify a
   reconciliation layer — it is a mandated one, and the inputs are ones the
   customer did not choose. See `NOTE.md §3` and `IDEATION.md §3.3`.
4. **Format is settled and not proprietary.** CERT-In §8.4.1.5 requires
   recognised industry-standard formats, *"such as SPDX or CycloneDX"*. Their
   Table 9 minimum elements for cryptographic assets map onto CycloneDX
   `cryptoProperties` almost one-to-one. There is no Indian schema to
   reverse-engineer. **Resolves OQ-06.** A **VEX** document is separately
   required on discovery of a crypto vulnerability, with four statuses
   (Not Affected / Affected / Fixed / Under Investigation).

For comparison, NIST IR 8547 (initial public draft, Nov 2024, still draft as of
mid-2026) deprecates quantum-vulnerable public-key algorithms after **2030** and
disallows them after **2035**. CNSA 2.0 gates new national-security
acquisitions from **2027-01-01**.

**Design consequence:** for an Indian critical-infrastructure operator, the
binding constraint is a *regulatory date*, not the arrival of a
cryptographically relevant quantum computer. QAVACH must compute urgency
against `min(Z_scenario, applicable_regulatory_deadline)`. See `ARCH.md §7.3`.

---

## 2. Problem statement clause mapping

The reviewer's brief has four description clauses and two deliverables. Every
one maps to numbered requirements below. Nothing in the brief is unaddressed;
where coverage is partial, it says so.

| Clause | Requirement IDs | Coverage |
|---|---|---|
| i. Catalogue all cryptographic artefacts (algorithms, keys, certificates, protocols, libraries, hardware modules, cloud services) | FR-100…FR-190 | Full for algorithms/libraries/certs/protocols/cloud; **evidence-based only** for HSM |
| ii. Comprehensive quantum risk assessment; identify vulnerable systems; highlight risk to sensitive data | FR-300…FR-360 | Full |
| iii. Classify by type, lifetime, business criticality; apply Mosca | FR-200…FR-240, FR-310 | Full |
| iv. Recommend PQC/hybrid alternatives by risk profile, latency, cost | FR-400…FR-450 | Full; latency/cost from a curated cited benchmark table, not live measurement |
| D1. Report of all crypto assets incl. versions/modes in standardised formats | FR-500…FR-530 | Full — CycloneDX 1.7 CBOM + Risk Register + PDF/XLSX |
| D2. Interactive GUI to visualise scan, risks, results | FR-600…FR-680 | Full |

---

## 3. Users

**Primary — Crypto Migration Lead** at a CII operator or PSU. Owns the
programme. Needs a defensible priority order and a budget-shaped roadmap she
can take to a steering committee. Cares that every recommendation has a
citation.

**Secondary — Application Security Engineer.** Runs the scans, triages false
positives, wires QAVACH into CI. Cares about signal-to-noise and about not
having to re-triage the same finding every build.

**Secondary — CISO / Regulator-facing.** Needs a one-page posture number, an
audit trail, and an export that satisfies a sector regulator's inventory
mandate. Cares that the artefact is standards-valid.

**Non-user:** individual developers. QAVACH is not a linter. A CI gate exists
(FR-670) but the product is not developer-first.

---

## 4. Functional requirements

Priority: **P0** = demo-critical, must work end to end. **P1** = required for
the claim to be credible. **P2** = architected, stubbed, honestly labelled.

### 4.1 Discovery (FR-1xx)

| ID | P | Requirement |
|---|---|---|
| FR-100 | P0 | Scan a Git repository (URL or local path) and produce a CBOM of cryptographic algorithms, primitives, modes, key sizes and the libraries providing them. |
| FR-101 | P0 | Support at minimum Java, Python, Go, JavaScript/TypeScript at AST confidence; C/C++, C#, PHP, Ruby, Rust at pattern confidence. **Go coverage via `cbomkit-lib` excludes `crypto/x509`** (covered instead by the cert/keystore collectors); **C# stays at PATTERN confidence via Opengrep** — `cbomkit-lib`'s C# support is explicitly "not yet meant for active usage" per its own documentation, verified 2026-09-17. |
| FR-110 | P0 | Ingest an SBOM (CycloneDX or SPDX) and derive cryptographic capability from packages via a curated crypto-library knowledge base. |
| FR-120 | P1 | Scan a container image (registry ref or tarball) for crypto libraries, embedded certificates and key material. |
| FR-130 | P0 | **Active TLS endpoint collector.** Given a host:port list or CIDR, record negotiated protocol version, cipher suite, key-exchange group, certificate chain, public-key algorithm and size, signature algorithm, validity window, SAN set, and SHA-256 fingerprint. |
| FR-131 | P1 | Certificate inventory from a directory, PEM/DER bundle, Java keystore, or PKCS#12 file. **Runs exclusively via the deployed agent (FR-132) when the target type is Host; the sandboxed-subprocess path (§6) never reads a live host's filesystem directly.** |
| FR-132 | P0 | **Deployed agent — host collector.** Installable on an operator-controlled host. Performs certificate-store, HSM-evidence, deployed-artefact and local SSH-config collection using real filesystem access, and transmits results to the engine over an authenticated, outbound-only channel. See `ARCH.md §3a`, `SECURITY.md §2a`. |
| FR-133 | P0 | **Agent enrollment and registry (sensor management).** An operator generates a scoped, single-use enrollment token from the dashboard; the agent exchanges it for a rotatable credential and registers itself. The dashboard lists every enrolled agent's identity, host, online/offline status and per-run history. |
| FR-134 | P1 | **Known-paths auto-scan manifest.** A curated, per-OS/per-platform list of common certificate, keystore, HSM-config and appserver locations that the agent scans automatically, in addition to any explicit paths the operator supplies. |
| FR-135 | P1 | **AD Certificate Services collector.** Given a domain controller address and an authenticated low-privilege domain credential, enumerate AD CS certificate templates, CA configuration, published certificates and known misconfigurations (ESC1–ESC8). Runs as a network-mode sandboxed subprocess (`ARCH.md §2.3`), wrapping Certipy — no host install, no agent. Closes a gap the problem statement's clause (i) names ("hardware modules") only partially: AD CS is a software CA embedded in a directory service most Indian BFSI/CII estates already run. |
| FR-140 | P1 | **Cloud crypto collector**, read-only: AWS KMS key specs + ACM certificates + ELB TLS policies. Azure Key Vault and GCP KMS behind the same interface. |
| FR-150 | P2 | **HSM evidence collector.** Detect PKCS#11 configuration, vendor client libraries and slot references from filesystem and config evidence. Live slot enumeration is out of scope for v1 — see §6. **Runs via the deployed agent (FR-132); reports an unresolved crypto boundary, never a resolved asset.** |
| FR-160 | P1 | SSH host key and configuration collector. **Host-key algorithm negotiation is a network-only probe requiring no agent (shares the TLS endpoint collector's transport, FR-130); `sshd_config` KEX/cipher/MAC inspection requires local file access and runs via the deployed agent (FR-132).** |
| FR-170 | P2 | Runtime observation via `tracebom` — actually-negotiated TLS parameters and dynamically loaded crypto providers. |
| FR-180 | P0 | Ingest an externally produced CycloneDX CBOM (1.4–1.7) as a first-class source. |
| FR-190 | P0 | Every discovered item carries provenance: which collector, which tool version, which detection method, which confidence tier, and the exact locus (repo@commit:path:line, image digest:layer:path, host:port, key fingerprint). |

### 4.2 Reconciliation and classification (FR-2xx)

| ID | P | Requirement |
|---|---|---|
| FR-200 | P0 | Normalise every input to CycloneDX 1.7 canonical form using the CycloneDX **Cryptography Registry** for algorithm family, parameter set and elliptic curve names. |
| FR-210 | P0 | Deduplicate across collectors using a deterministic asset identity key. Same asset found by four tools = one asset, four occurrences. |
| FR-220 | P0 | Resolve conflicting claims by confidence precedence; retain all claims; mark the asset `disputed` when sources materially disagree. |
| FR-230 | P0 | Classify every asset into exactly one of `QUANTUM_VULNERABLE`, `CLASSICAL_WEAK`, `GROVER_AFFECTED`, `QUANTUM_SAFE`. |
| FR-240 | P0 | Classify by cryptographic function: `key-encapsulation`, `key-agreement`, `encryption`, `signature`, `mac`, `hash`, `drbg`, `kdf`. This drives Mosca (invariant I2). |

### 4.3 Business context (FR-25x)

| ID | P | Requirement |
|---|---|---|
| FR-250 | P0 | Group assets into **Systems** (a deployable business service). Import system metadata from CSV/YAML or a CMDB export. |
| FR-251 | P0 | Per system, capture: business criticality (1–5), data classification, data retention requirement in years, internet exposure, regulatory regime, and owner. |
| FR-252 | P1 | Infer a default retention requirement from data classification when not supplied, and mark it as inferred. |
| FR-253 | P1 | Capture inter-system dependencies (which system calls which, which trusts which CA) from an import or from discovered evidence. |

### 4.4 Risk (FR-3xx)

| ID | P | Requirement |
|---|---|---|
| FR-300 | P0 | Compute Mosca `X + Y > Z` per asset, with `X` derived per cryptographic function class (invariant I2), `Y` from a migration-effort model, `Z` from the active policy scenario. |
| FR-310 | P0 | Compute `Z_effective = min(Z_scenario, applicable_regulatory_deadline)` and report which one bound. |
| FR-320 | P0 | Compute an HNDL exposure score for confidentiality assets: retention requirement vs. `Z_effective`, weighted by exposure and data sensitivity. |
| FR-330 | P0 | Implement CARAF's five dimensions as an explicit, inspectable pipeline: threat vector → asset inventory → expected value of compromise → mitigation strategy → roadmap. |
| FR-340 | P0 | Emit one of four CARAF mitigation outcomes per asset or system: **Migrate**, **Compensating control**, **Accept**, **Phase out**, with the reasoning shown. |
| FR-350 | P0 | Every score is deterministic and reproducible: the same inputs and the same policy file always produce the same output. No LLM in the scoring path. |
| FR-360 | P0 | Every score is explainable: the UI and the API can show the inputs, the formula, the policy values used, and the citation for each policy value. |

### 4.5 Recommendation (FR-4xx)

| ID | P | Requirement |
|---|---|---|
| FR-400 | P0 | Recommend a standardised PQC replacement per vulnerable asset: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS/XMSS (SP 800-208) for stateful firmware signing. |
| FR-410 | P0 | State the standardisation status honestly. FIPS 203/204/205 are final (published 2024-08-13). **HQC is selected (2025-03-11) but not yet a published FIPS. FN-DSA / FIPS 206 was in development as of mid-2026.** Never present a draft as final. |
| FR-420 | P0 | Recommend hybrid vs. pure PQC per context, with the reason. Hybrid (e.g. X25519MLKEM768) for general TLS during transition; note where a regime such as CNSA 2.0 prefers pure PQC. |
| FR-430 | P1 | Attach latency, key-size, signature-size and handshake-overhead figures from a **curated, cited benchmark table** in `config/knowledge/performance.yaml`. Every row cites a source. Do not fabricate numbers. |
| FR-440 | P1 | Attach a migration cost estimate in effort-days from a parameterised model the operator can override. |
| FR-450 | P1 | Flag assets where no drop-in PQC replacement exists (hardware-bound, protocol not yet standardised, third-party SaaS) and route them to compensating controls instead of migration. |

### 4.6 Roadmap (FR-46x)

| ID | P | Requirement |
|---|---|---|
| FR-460 | P0 | Build a migration dependency DAG with typed edges: trust-anchor, protocol-peer, library-availability, hardware-gate, data-format (reader-before-writer), build-and-sign. |
| FR-461 | P0 | Topologically sort into waves; order within a wave by Mosca urgency. |
| FR-462 | P0 | Detect cycles and emit them as **"requires a hybrid / dual-stack bridge"** rather than failing. A cycle is a real finding, not an error. |
| FR-463 | P1 | Assign each wave a target quarter derived backwards from the binding regulatory deadline, and flag waves that cannot fit. |

### 4.7 Reporting (FR-5xx)

| ID | P | Requirement |
|---|---|---|
| FR-500 | P0 | Export a **CycloneDX 1.7 CBOM** that validates against the official schema. |
| FR-501 | P1 | **Scoped BOM export.** Every export in §4.7 (CBOM, Risk Register, PDF, XLSX) accepts a **scope**: `component` (one collector or agent run), `system` (everything bound to one `System`, `ARCH.md §4`, including a vendor-supplied CBOM ingested under FR-180), or `root` (the whole organisation). All three are **views over the single reconciled asset graph L3 produces** — never three separately-merged documents. See `ARCH.md §10.1`. |
| FR-510 | P0 | Export a **Crypto Risk Register** (QAVACH JSON schema) referencing CBOM `bom-ref` values, carrying risk scores, CARAF outcomes, recommendations and roadmap position. |
| FR-520 | P0 | Export CycloneDX 1.6 by downgrade for tools that have not adopted 1.7. |
| FR-521 | P1 | Export an executive PDF and an asset-level XLSX. |
| FR-530 | P1 | Sign exports. Use ML-DSA-65 where the library allows, otherwise Ed25519 with the limitation stated in the output. QAVACH must not ship a PQC tool that signs its own artefacts with RSA. |

### 4.8 Interface (FR-6xx)

| ID | P | Requirement |
|---|---|---|
| FR-600 | P0 | Start a scan from the UI; live progress over WebSocket with per-collector status. |
| FR-601 | P0 | **Target-type selector.** The new-scan flow presents an explicit target-type choice before any collector configuration: Repository, Container Image, Network/TLS Endpoint, Directory Service (AD/LDAP, FR-135), Cloud Account, Host (agent-based), External CBOM/SBOM upload. Selecting Host routes to the agent-enrollment flow (FR-133) instead of a sandboxed-subprocess job. |
| FR-610 | P0 | **Posture dashboard**: asset counts by finding class, systems by CARAF outcome, the binding deadline, and the count of assets that miss it. Must show the `UNKNOWN` count as a first-class figure (invariant I8) and the split by `MigrationAuthority` (invariant I9) — "you own N of these" is the headline, not the raw total. |
| FR-615 | P0 | **Coverage panel**: what was scanned, what failed, what had no rule coverage, and the unresolved-algorithm and unknown-key-size counts. A coverage failure is reported as such, never as a clean result. |
| FR-616 | P1 | **Certificate expiry timeline**: expired / <7d / <30d / <90d / <1y / >1y. A category convention operators expect; cheap once the cert collector exists. |
| FR-617 | P1 | **Data-quality queue**: implausible parses (modulus lengths outside the plausible set, `0-bit` keys, filenames captured as algorithm names) surfaced for triage instead of being charted. |
| FR-620 | P0 | **Inventory table**: filter and facet by class, function, algorithm, system, criticality, confidence, disputed. |
| FR-630 | P0 | **Asset detail**: every occurrence with its locus and provenance, the full risk computation with inputs shown, and the recommendation with citations. |
| FR-640 | P0 | **Migration roadmap view**: the DAG as an interactive graph, waves as a timeline, hybrid-bridge cycles highlighted. |
| FR-650 | P0 | **Mosca explorer**: move `Z` between scenarios and see the priority order re-sort live. This is the single most persuasive screen in the product — it makes the uncertainty visible instead of hiding it. |
| FR-655 | P1 | **Alert relevance gate**: an alert fires only for `MigrationAuthority = SELF` assets at an operational locus. An expired root in a shipped OS trust store is a fact, not an incident. A competitor's alert list is entirely certificates that expired in 1996, 1998 and a `Test OCSP response signer`, all rated CRITICAL (`IDEATION.md §2.2e`). |
| FR-660 | P1 | Triage: suppress a finding with a reason and an expiry; suppressions persist across scans and appear in the audit log. |
| FR-670 | P1 | CI mode: `qavach scan --fail-on <class>` with SARIF output. |
| FR-680 | P1 | Scan history and drift: what changed between two scans of the same target. |

---

## 5. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-01 | A 100k-LOC repository completes discovery in under 10 minutes on 4 vCPU. |
| NFR-02 | Reconciliation and risk scoring for 50,000 assets completes in under 60 seconds. |
| NFR-03 | The UI remains interactive with a 5,000-node roadmap graph. |
| NFR-04 | `make test-unit` runs with no network, no Docker and no database. |
| NFR-05 | Full functionality in an air-gapped deployment; network-dependent enrichment degrades gracefully. |
| NFR-06 | Deployable via `docker compose` for evaluation and a Helm chart for enterprise. |
| NFR-07 | Every policy constant carries a citation to a primary source in the config file. |
| NFR-08 | All scanner execution is sandboxed per `SECURITY.md §3`. |
| NFR-09 | Scoring is deterministic and reproducible across runs and machines. |
| NFR-10 | Licence hygiene: QAVACH is Apache-2.0. Opengrep is LGPL-2.1 and is invoked as a **separate process only** — never linked or vendored into the QAVACH codebase. Record every scanner's licence in `docs/THIRD_PARTY.md`. |

---

## 6. Explicitly out of scope for v1

Stating these protects credibility. A reviewer respects a clear boundary far
more than an overclaim.

- **Live HSM slot enumeration.** Requires vendor credentials and a physical
  module. v1 detects PKCS#11 *evidence* (config, client libraries, slot
  references) and reports the HSM as an unresolved crypto boundary. This is a
  partial answer to clause (i) and is labelled as such in the UI.
- **Firmware and embedded binary analysis.** Binary crypto-constant detection
  is a research problem. Out.
- **Automated remediation.** QAVACH plans; it does not open pull requests or
  rotate keys. A migration tool that writes crypto code is a different and much
  more dangerous product.
- **QKD.** India's roadmap pairs PQC with targeted QKD, but QKD is a network
  procurement decision, not a software inventory problem.
- **Proprietary CBOM formats.** CycloneDX only.
- **Real-time continuous monitoring.** Scheduled re-scan and drift, yes.
  Streaming telemetry, no. The deployed agent (FR-132) is on-demand,
  poll-based collection against a discrete scan spec — request, run, post
  results, close — not a continuous streaming channel. Do not build it toward
  always-on telemetry; that is this exclusion, not an exception to it.

---

## 7. Acceptance — the demo that must work

This is the definition of done for the P0 set. Build toward this path first
and keep it green.

1. Operator adds a target: a Git URL, a container image, a host:port list, and
   a systems CSV carrying criticality and retention.
2. Scan runs. Live progress shows five collectors reporting independently.
3. Inventory appears. The **same RSA-2048 key** discovered by the source
   scanner, the SBOM mapper and the TLS collector shows as **one asset with
   three occurrences** and a source-precedence badge — the reconciliation layer
   made visible in one glance.
4. A deliberately planted AES-128 usage is shown as `GROVER_AFFECTED`,
   informational, **not** as an urgent migration item. A planted MD5 is shown as
   `CLASSICAL_WEAK` — urgent, but for classical reasons, and the UI says so.
5. An offline root CA signing key and an ephemeral TLS server certificate both
   use ECDSA P-256. The root CA ranks far higher. Clicking through shows why:
   different `X` because signatures are not subject to HNDL.
6. Mosca explorer: sliding `Z` from 2038 to 2030 re-sorts priorities live. A
   banner shows that for this organisation the binding constraint is the
   **Dec 2028 DST high-priority migration date**, not `Z`.
7. Roadmap view: waves render. One cycle is detected between a signing service
   and its verifier and is labelled "requires hybrid bridge."
8. Export: a CycloneDX 1.7 CBOM that passes schema validation live on screen,
   plus the Risk Register, plus an executive PDF.

If a judge asks "what did you actually build versus integrate," the answer is
step 3, step 5, step 6 and step 7. Say exactly that.

---

## 8. What success is not

Not "we detected the most algorithms." Not "we support the most languages."
Both are the delegated scanners' achievements, not ours, and claiming them
invites a comparison we lose. Success is that a migration lead can defend a
priority order to a steering committee using QAVACH's output, and that every
number in it has a source.
