# COMPETITOR.md — QCecuring Technologies

Competitive intelligence on **QCecuring**, a company building in the same space
as QAVACH (cryptographic asset discovery, CBOM generation, quantum-risk
classification). Working document — more sources to be added as they come in.

Read alongside `NOTE.md §4.1`, which already flags a separate, unrelated naming
collision (**KavachQ**, `kavachq.in`) as a distinct competitor in the Indian
PQC-roadmap space. QCecuring appears to be a third, independent player — do not
conflate the two.

---

## 1. Source log

| # | Source | Date watched | Notes |
|---|---|---|---|
| 1 | YouTube: ["CBOM Architecture Explained \| Sensors, Risk Engine & CycloneDX"](https://www.youtube.com/watch?v=Xdr-f7s8IYU) — QCecuring Technologies channel, uploaded 2026-05-18, 4:07 long, 15 views at time of watching. Video 2 of a 9-video playlist (`PLtkuxQ57SmvPnFUVkN-HjX0X4atjgH5VK`). | 2026-09-08 | Transcript (auto-captions, noisy on technical terms) + 7 slide frames, reviewed together. It's a slide-deck explainer, not a live product demo — no actual UI screenshots. Frames confirmed most of the transcript and corrected a few misheard terms (noted inline below). |

**Low visibility signal, revised after watching the full playlist:** 15 views is still true of the marketing channel, but §2.6/§2.9's live product demos (a real 21,224-asset inventory; a live install-and-scan of an actual Windows machine; a real scan of microsoft.com) show this is **not** an early prototype — it's a working, reasonably mature product with low *marketing* visibility, not low product maturity. Don't conflate the two. Worth re-checking view counts and upload cadence periodically — a jump in views would mean their marketing is catching up to their product.

### 1.1 Full playlist map (`PLtkuxQ57SmvPnFUVkN-HjX0X4atjgH5VK`)

| # | Title | Video ID | Length | Status |
|---|---|---|---|---|
| 1 | Why CBOM? The Post-Quantum Problem | `UE2Ozp1f3YY` | 4:39 | **done** — §2.5 below |
| 2 | CBOM Architecture Explained \| Sensors, Risk Engine & CycloneDX | `Xdr-f7s8IYU` | 4:07 | **done** — §2 below |
| 3 | QCecuring CBOM Platform Tour | `_K7N-eS47k0` | 2:59 | **done** — §2.6 below |
| 4 | Dashboard and Risk Summary - Understanding Quantum Risk Dashboard | `LfXfkiaNz1I` | 2:45 | **done** — §2.7 below, **important correction to §3** |
| 5 | Managing Cryptographic Assets with CBOM | `Fhp7jfY5FWk` | 2:24 | **done** — §2.8 below |
| 6 | How to Configure CBOM Sensors | `vhpuABkOkis` | 6:00 | **done** — §2.9 below, **resolves the sensor-type ambiguity from §2.7** |
| 7 | Visualizing Certificate Chains & Trust Relationships | `pGLHSktbxDI` | 1:18 | **done** — §2.10 below |
| 8 | CNSA 2.0 & FIPS 140-3 Compliance with CBOM | `0Cp9OBoY2Xk` | 1:20 | **done** — §2.11 below |
| 9 | CycloneDX CBOM Export & BOM-Link Integration | `oQ5i_8nr3UM` | 2:26 | **done** — §2.12 below — **playlist complete** |

---

## 2. What QCecuring's platform does (per source #1)

Positioned as a **CBOM (Cryptography Bill of Materials) platform** with four layers, top to bottom:

Confirmed by an on-screen architecture diagram (frames at t=00:12/00:16), four layers stacked exactly as:

```
DISCOVERY LAYER   HTTPS · Filesystem · Keystore · SSH · Windows · Source Code · Binary · AWS · AD
API LAYER         Ingestion · Risk Engine · Relationship Linker · Compliance · Export · BOM-Link · Alerts
DATA LAYER        MongoDB
UI LAYER          Dashboard · Inventory · Relationships · Compliance · Import/Export
```

Note the API layer has **7 boxes on the diagram**, not 6 — "Alerts" appears on the architecture slide but is never mentioned in narration or on the later "Central API — The Brain" detail slide (which only elaborates 6). Alerting may be a thin/planned feature not yet worth its own deep-dive slide.

### 2.1 Discovery layer — sensors
- Lightweight **Java** agents deployed anywhere — on-prem, cloud, DMZ, **air-gapped** (explicit bullet on the "Distributed Sensor Architecture" slide, t=01:20).
- **Nine sensor/scan types**, confirmed by slide: HTTPS Scanner, Filesystem Scanner, Keystore Scanner, SSH Scanner, Windows Store, Source Code, Binary Scanner, AWS Scanner, Active Directory.
- Scanners are **plugins** — added "without touching the core."
- Sensors push discovered assets to the central API **over mTLS** (slide bullet — the transcript's "authenticated with an API key" undersells this; it's mutual-TLS, not just a bearer key) — **auto-registration with the API on first connection**.
- Scheduled or on-demand scan execution.
- Content-based deduplication: same certificate on 10 servers = 1 asset, 10 locations. "Fingerprint-based identity ensures a single source of truth" (verbatim slide text — likely SHA-256 per the transcript, not shown on-slide).

### 2.2 API services — "The Brain," 6 cards on the detail slide (t=02:04)
1. **Ingestion Engine** — "Deduplicates, normalizes, and stores discovered cryptographic assets with full provenance tracking." (verbatim)
2. **Quantum Risk Engine** — "Classifies every asset by quantum vulnerability — algorithm strength, key size, and protocol version." (verbatim — corrects the transcript's implied "NIST security level 0–5" language, which does not appear on-slide and should be treated as caption noise, not a confirmed claim.)
3. **Relationship Linker** — "Builds certificate chains, key associations, and issuer hierarchies automatically." (verbatim)
4. **Compliance Engine** — "Policy assessment against CNSA 2.0, FIPS 140-3, and custom organizational policies with attestations." (verbatim — confirms "1403" = FIPS 140-3)
5. **CycloneDX Export** — "Full compliant spec with bom-ref, dependencies, OID mapping, and full component graph." (verbatim)
6. **BOM-Link Service** — "Cross-references CBOM assets with SBOM components for complete software supply-chain visibility." (verbatim)

("Alerts," the 7th box on the architecture diagram, is not among these 6 — see note above.)

### 2.3 Storage and UI
- Persisted in **MongoDB** (document store) — not a relational database.
- UI layer per the diagram: Dashboard, Inventory, Relationships, Compliance, Import/Export.
- CycloneDX export "at any time... from discovery to standard-compliant CBOM in seconds, not days, not weeks" — this speed claim is their headline pitch, repeated verbatim on the data-flow slide.

### 2.4 Data flow, end to end
Confirmed by the "End-to-End Data Flow" slide (t=03:28), 7 numbered steps:
**Sensor Scans → Push to API → Dedup & Classify → Link Relationships → Store in MongoDB → UI Displays → Export as CycloneDX.**

### 2.5 Video 1 — "Why CBOM? The Post-Quantum Problem" (`UE2Ozp1f3YY`, 4:38, captions + 6 frames reviewed)

This is their pitch/positioning video, not architecture. New facts confirmed by on-screen slides (not just narration):

**CycloneDX is ratified as an Ecma International standard, ECMA-424.** Slide: "CycloneDX CBOM — OWASP/ECMA-424. Machine-readable cryptographic inventory standard... Open Standard." QAVACH's own docs (`README.md`, `ARCH.md §5`) cite CycloneDX 1.7 and the Cryptography Registry but never mention the ECMA-424 ratification — this is a legitimate additional standards citation worth adding to QAVACH's own materials (strengthens "we're standards-compliant," costs nothing to add, should be verified against Ecma's own publication before citing).

**A NIST-derived timeline for CNSA 2.0 is stated that appears to conflict with what QAVACH cites.** Slide "Migration Timeline": 2022 White House NSM, 2024 NIST finalizes FIPS 203/204/205, **2025 CNSA 2.0 — prefer quantum-resistant algorithms, 2030 CNSA 2.0 — quantum-resistant algorithms exclusively.** QAVACH's own `PRD.md §1.1` and `ARCH.md §7.3` cite **CNSA 2.0's acquisition gate as 2027-01-01** (confirmed independently in the earlier fact-check review of this same project). These are not necessarily contradictory — CNSA 2.0 is known to have multiple milestones (a preference date, an acquisition-gate date, and a full-exclusivity date for different system categories) — but the two documents cite different numbers for what each calls "the" CNSA 2.0 deadline. **Action item for QAVACH: verify the full CNSA 2.0 milestone set against the NSA's own advisory before either document's citation is treated as complete** — right now `config/policy/regulatory_deadlines.yaml` (per `ARCH.md §7.3`) only carries the 2027-01-01 acquisition gate, and may be missing the 2025-preference / 2030-exclusive milestones QCecuring cites.

**A capability not mentioned anywhere in video 2: key lifecycle management.** Slide "QCecuring Implements CBOM End-to-End," 6th card: "Lifecycle Management — NIST SP 800-57 key states — pre-activation through destruction with full audit trail." This tracks/audits a key's lifecycle state (not necessarily performing rotation/destruction itself — consistent with QAVACH's own "not a remediation tool" stance in `README.md §"What QAVACH is not"`). QAVACH has no equivalent concept anywhere in `ARCH.md`'s data model — no `KeyState` field, no NIST SP 800-57 reference. Worth a deliberate decision: either this is genuinely out of scope for a discovery/decision tool (defensible — QAVACH plans migrations, it doesn't manage key custody), or it's a real gap in the `CryptoAsset`/`Occurrence` model that a reviewer familiar with SP 800-57 could flag.

**Risk scoring vocabulary confirmed**: "NIST Quantum Security Level (QSL) 0–5 assessment for every discovered asset" (their own card wording — read this as QCecuring's own naming for a scale they attribute to NIST, not necessarily an official NIST term; NIST's PQC standards define security categories 1–5 by comparison to AES/SHA strength, so "QSL 0-5" is plausibly their gloss on that, with 0 likely meaning "not yet assessed" or "classical/no PQC relevance" — unconfirmed, flag as inference).

**Scanner-type list on this slide differs slightly from video 2's**: this slide's automated-discovery card reads (at 512px, low confidence on exact OCR) "HTTPS, Filesystem, SSH, Windows, Source code, Binary, RMI(?), Active Directory" — video 2 listed AWS Scanner and Keystore Scanner instead of an apparent "RMI." This is very likely a mis-read of small compressed text rather than a real product difference (9 sensor types is stated consistently across both videos) — re-verify against video 6 ("How to Configure CBOM Sensors") before treating this as a real inconsistency.

**Positioning line, worth quoting directly for how they frame the problem** (this is a strong, well-put pitch, worth acknowledging as good competitive messaging rather than dismissing): *"The hard part is not the math. It is not picking the right algorithm. The hard part is the visibility... You can't migrate what you can't see."* This lands on almost exactly the discovery-is-the-gap thesis `PRD.md §1` opens with — both products are selling the same core insight, differentiated (so far) on how deep the *decision* layer goes past discovery.

### 2.6 Video 3 — "QCecuring CBOM Platform Tour" (`_K7N-eS47k0`, 2:59, captions + 12 frames reviewed)

**This is a real, working product, not a mockup or a slide deck.** The screen recording shows a populated instance with **21,224 real cryptographic assets** from an actual scan — this materially changes the read on QCecuring: they are further along than "early-stage pre-marketing" (§1) suggested from view counts alone. Revise that assessment — low YouTube views does not mean the product is immature; it may just mean the marketing/channel is new relative to the product.

**Left-nav / full feature surface, confirmed on-screen:** Dashboard, Inventory, Sensors, Alerts, Relationships, Compliance, Import/Export, Users, Settings. ("Users" and "Settings" are new — not mentioned in videos 1 or 2 at all; ordinary multi-user/RBAC-adjacent admin surface, unremarkable but confirms this is built as a real multi-tenant-capable product.)

**Dashboard**: asset-count tiles, a "Quantum Risk Distribution" donut (Critical/High/Medium/Low/None), an "Asset Type Distribution" donut (Certificates / Private Keys / Public Keys / Symmetric / Algorithms / Signatures), a "Quantum Vulnerability" panel breaking the 21,224 assets into risk bands (large majority landed in High; a small Critical bucket; a large None bucket — exact digits not reliably legible at frame resolution, treat any number here as approximate), plus bar charts for algorithm mix and key-size distribution.

**Inventory**: faceted filtering (quick filters for Quantum Critical, Quantum High-Risk, RSA-1024/Weak, RSA-2048 Certificates, All Certificates/Private Keys/Symmetric Keys/Signatures, saved searches) plus a free-text + structured search (type, risk, algorithm, key size, domain). Table columns: Name, Type, Algorithm, Size, Risk, Last Seen.

- **The demo data includes a real binary scan of a Sublime Text build** — inventory rows like "SM reference in sublime_text_build_4107_x…", "ARIA reference in…", "MD5 reference in…", "3DES reference in…" show algorithm-usage findings pulled out of an actual application binary. This is a concrete, credible demonstration of the binary-scanning sensor working on real-world software, not a synthetic fixture.
- **Asset detail panel** (opened by clicking a row) shows: fingerprint, a **Locations** list (multiple file-path occurrences for the same logical asset — confirms their dedup-to-one-asset-many-locations model from video 2 is real and visible in the UI), a **Properties** block (algorithm, alias, file path, key size), First/Last Seen timestamps, and a **Relationships** section listing directly-connected assets (e.g., a root/intermediate CA showing which certs it issued). This detail-panel design is close in spirit to QAVACH's planned `T-104` asset-detail screen (`TASK.md`) — worth a screenshot-level comparison once QAVACH's own UI exists.
- One filtered view showed **two symmetric keys with local Windows file paths** (`AES-256 symmetric key (mysecretkey)`, `HmacSHA256-256 symmetric key (myhmackey)`) — confirms a real filesystem/keystore sensor ran against an actual Windows host, not just certificates.

**Sensors**: a registered sensor (`windows-l1-desktop`, shown **offline** at capture time) with a scan-history table — columns Scanner / Target / Hostname / Started / Status / Assets. Scanner types visible in the log: `binary`, `windows-certstore`, `filesystem` — each run shows a real completed status and an asset count (12–122 range per run). Confirms per-scanner-type scan history and on-demand triggering are real, working features, matching the video-2/video-1 narration.

**Relationships**: a dedicated graph view (toggle between Graph/List) with an explicit legend — nodes colored by role (**Root CA** red, **Intermediate CA** amber, **Certificate** green, **Key** blue) and typed edges (`issuedBy`, `signedBy`, `contains` — exact edge-label set not fully legible, treat as approximate). The populated example traces a real signing chain: a leaf certificate → intermediate CA(s) → root CA, plus a separate Authenticode/code-signing branch — i.e., a working certificate-chain-plus-code-signing relationship graph, not just a cert chain. This is functionally adjacent to (but a different graph from) QAVACH's planned migration DAG (`ARCH.md §9`) — QCecuring's graph shows *trust relationships as they exist today*; QAVACH's graph shows *migration dependency order*. Both could coexist in one product; worth noting QAVACH doesn't currently have an equivalent "explore relationships as a graph, right now, pre-migration" screen — the closest is the asset-detail occurrence list, which isn't a graph.

**Compliance**: an assessment-summary header (Total Assets, Active Policies, Violations, overall Status — the populated example showed **21,224 assessed / 3 active policies / 25,112 violations / status NON_COMPLIANT**) and a per-policy breakdown. Three named policies, each with Assessed/Compliant/Violations/Warnings counts:
- **FIPS 140-3 Compliance** (cited as NIST FIPS 140-3) — mostly compliant, a small violation count.
- **CNSA 2.0** (cited as NSA CNSA 2.0) — **100% violation** in the demo (every asset flagged non-compliant) — consistent with CNSA 2.0 mandating PQC-exclusive algorithms that essentially nothing in a pre-migration estate satisfies yet.
- **NIST PQC Readiness** (cited against a NIST IR — number on-screen read as "8413," not confirmed at this resolution, verify before citing) — a mixed compliant/violation/warning split.

This is a real, working "policy vs. inventory" compliance engine, not just the "custom rules" line from video 2's transcript — worth taking the Compliance Engine claim seriously as a built feature, not vaporware.

**Import/Export**: Export offers **CycloneDX v1.6 CBOM** or a **Raw JSON** full-asset export. Import is explicitly scoped as **visualize-only**: *"Upload a CycloneDX CBOM JSON to visualize its contents. Does not modify your inventory."* — **this is a genuine, confirmed architectural difference from QAVACH.** QAVACH's `FR-180` treats an externally-supplied CycloneDX CBOM as a first-class reconciliation source (merged into the canonical inventory alongside every other collector). QCecuring's import is sandboxed — it renders someone else's CBOM for viewing but never merges it into your own inventory. If accurate (and the UI copy is unambiguous), QAVACH's reconciliation-of-external-CBOMs capability is a real, defensible differentiator, not just an architectural preference — worth stating confidently rather than hedging.

**Alerts**: a scan-schedule manager (empty in this demo — "No schedules configured") plus a live alert feed. Every visible alert in the demo is a **certificate-expiration** notice (e.g., "Certificate expired: Sublime HQ Pty Ltd," and one for a certificate with a Subject DN referencing "National Aeronautics and Space Administration" — likely picked up incidentally from a real signed binary's code-signing chain in their demo corpus, not a deliberate NASA integration). Video 3's narration claimed alerts also cover "new high-risk assets" and "scan failures," but neither is visible in this particular screen capture — plausible but not visually confirmed.

#### Net effect on the assessment in §3 below
Several rows in the comparison table below were written before this video was reviewed and assumed QCecuring's product might be lightly built (a plausible reading of a 4-minute slide-deck explainer). That assumption should be retired: **this is a real, populated, multi-feature product with working compliance, alerting, relationship-graphing, and sensor-management screens.** The genuine remaining differentiators for QAVACH are narrower and more specific than "QAVACH is more real" — they are: (1) multi-source reconciliation with confidence precedence and dispute-marking (QCecuring's dedup is single-fingerprint, single-source-of-truth, and their CBOM import is explicitly read-only/non-merging), (2) Mosca-per-function-class + CARAF risk sequencing vs. QCecuring's flatter risk-level + policy-violation model, and (3) a dependency-ordered migration roadmap, which QCecuring shows no evidence of anywhere across 3 videos so far.

### 2.7 Video 4 — "Dashboard and Risk Summary" (`LfXfkiaNz1I`, 2:45, captions + 8 frames reviewed)

**Important correction to earlier entries in this file (§2.6, §3): QCecuring already separates classical-break from quantum-vulnerability from Grover-margin from quantum-safe — the same four-way distinction QAVACH's `README.md` currently claims as a differentiator.** Verbatim narration walking through their dashboard's risk-color legend:

> "Red means critical. These are broken. MD5, SHA1, DES — they should not exist in your environment. Fix them today. Orange is high — quantum vulnerable. RSA, ECDSA, ECDH — these work fine today, but they are dead the moment a quantum computer is powerful enough. These are your migration targets. Yellow: medium — things like AES-128, still works, but... worth upgrading to 256. Green means none — quantum safe: AES-256, SHA-256, post-quantum algorithms — these are your goal states."

Mapped directly to QAVACH's `CLAUDE.md` Invariant I1:

| QCecuring dashboard tier | QAVACH finding class | Match |
|---|---|---|
| Red / Critical — MD5, SHA-1, DES | `CLASSICAL_WEAK` | Same concept |
| Orange / High — RSA, ECDSA, ECDH | `QUANTUM_VULNERABLE` | Same concept |
| Yellow / Medium — AES-128, "still works... worth upgrading" | `GROVER_AFFECTED` | Same concept — notably, QCecuring also does **not** frame AES-128 as urgent, matching Invariant I1's "never rendered as migrate now" |
| Green / None — AES-256, SHA-256, PQC | `QUANTUM_SAFE` | Same concept |

**This means QAVACH's `README.md` "What makes it different" claim — "It does not treat all quantum risk as one thing... Tools that redline AES-128 alongside RSA-2048 destroy their own credibility" — is not the differentiator it's currently written as.** At least one real competitor already gets this right. This doesn't mean the underlying engineering judgment is wrong (it's still correct and still worth keeping, per `NOTE.md §2.3`'s "damage avoided" framing) — but stating it as a point of differentiation in the pitch, rather than as a baseline correctness property, risks a reviewer who's seen QCecuring's video calling it out. **Recommend softening or removing this specific claim from `README.md`'s differentiation section**, and leaning instead on what genuinely doesn't appear anywhere in QCecuring's product across 4 videos so far: Mosca's per-function-class timing model (`X+Y>Z`), HNDL scoped to confidentiality only, CARAF's Accept/Phase-out outcomes (QCecuring's compliance engine only ever outputs compliant/violation/warning — a policy-conformance check, not a cost-aware mitigation decision), and a dependency-ordered migration roadmap. Those remain real and so far unmatched.

**Populated dashboard numbers** (from the "Quantum Vulnerability" tile, legible at this resolution): of 21,224 assets — **13 Critical, 10,788 High, 0 Medium, 10,421 None.** Zero assets landed in the AES-128/"Medium" bucket in this particular demo dataset — consistent with a corpus dominated by TLS/PKI certificates (RSA/ECDSA-heavy) and comparatively little raw symmetric-cipher usage.

**Discovery-source breakdown shown on this dashboard lists 9 categories**: source code, filesystem, binary, ssh-keys, api-triggered, active-directory, windows-certstore, https-endpoint, and one more read as "osv" at this resolution. **Resolved in §2.9: that 9th label is "aws," not "osv"** — confirmed against video 6's fully-expanded, authoritative Scanner Type dropdown. Treat the sensor-type list as settled: filesystem, binary, ssh-keys, windows-certstore, source-code, https-endpoint, aws, active-directory, plus likely a dedicated keystore type.

**Other dashboard sections observed**: certificate/key algorithm and key-size distribution charts, a signature-algorithm breakdown, a certificate-expiry timeline (bucketed: expired / <7 days / <30 days / <90 days / <1 year / >1 year — a useful UI pattern QAVACH's own posture dashboard, `FR-610`/`T-102`, doesn't currently specify at this granularity), a separate "Key Types/Algorithms/Sizes & Risk" panel distinct from the certificate panel, a "Code Signature Algorithms" + "Signature Quantum Risk" pair, and a scan-health panel (Completed/Failed/Partial counts + a recent-scans table) — narrated as: *"A healthy dashboard looks like mostly green, recent scans within 24 hours, stable numbers. If you see a spike in red or orange, investigate right away."* This scan-health-as-a-first-class-dashboard-citizen idea (distinct from asset risk) is a good, simple UX pattern QAVACH's `FR-600`/`T-101` (live per-collector WebSocket progress) doesn't currently surface as a *standing* dashboard tile — worth considering for `T-102`.

### 2.8 Video 5 — "Managing Cryptographic Assets with CBOM" (`Fhp7jfY5FWk`, 2:24, captions + 8 frames reviewed)

Mostly a deeper walkthrough of the Inventory screen already covered in §2.6 — stacked filters, a named **Save Search** feature (modal with a name field, e.g. "Expiring RSA Certs"), and a **scoped export**: whatever the current filtered view shows can be exported directly as raw JSON or CycloneDX, not only from the dedicated Import/Export page. Two things worth flagging that are genuinely new:

- **Full certificate property set confirmed in the asset-detail panel**: subject, issuer, serial number, signature algorithm, not-valid-before/after, issuer certificate fingerprint, plus a flat **Relationships** list (not just the separate graph view) showing every directly-linked asset with its own risk badge (e.g., "Sublime HQ Pty Ltd" → Sectigo RSA Code Signing CA [HIGH] → USERTrust RSA Certification Authority [HIGH] → AAA Certificate Services [HIGH]) — a full trust chain, readable as a list, right in the detail panel, no graph navigation required. This dual-representation (list in the detail panel, graph as a separate screen) is a good pattern worth considering for QAVACH's own `T-104` asset-detail screen.
- **Possible finding: an "Unknown private key" row displayed with risk = NONE** (green) in the inventory list — i.e., an asset QCecuring cannot classify by algorithm appears to default to the "quantum-safe" risk color rather than an explicit "unclassified/needs review" state. If this reading is accurate (moderate confidence at frame resolution — worth re-confirming, e.g. by finding an "Unknown" row and opening its detail panel in a future source), **this is a real, citable methodological weakness relative to QAVACH's own design**: `ARCH.md §5.2` explicitly requires an unresolvable algorithm to get `finding_class = UNKNOWN`, surfaced in a visible "unclassified" bucket, "never silently dropped" — precisely because defaulting an unknown to "safe" is how a tool quietly under-reports risk. Worth keeping this contrast explicit in any competitive positioning, once verified.

### 2.9 Video 6 — "How to Configure CBOM Sensors" (`vhpuABkOkis`, 6:00, captions + frames reviewed)

**This video shows an unedited, live, end-to-end demo — register a sensor → install it via a real PowerShell installer on an actual Windows machine → run it → see real results land in the UI within the same recording.** This is the strongest evidence yet that QCecuring is a genuinely working product rather than a polished-but-shallow demo; treat every earlier "worth verifying this is real" hedge in this file as resolved in favor of "real" unless a specific future source contradicts it.

**Sensor-type list definitively resolved.** The "Add Scanner" dialog's Scanner Type dropdown was captured fully expanded, giving an authoritative list — **filesystem, binary, ssh-keys, windows-certstore, source-code, https-endpoint, aws, active-directory** (8 visible; a 9th, likely a dedicated Java-keystore type, was probably cut off below the visible dropdown, consistent with "Keystore Scanner" appearing as its own item on video 2's architecture slide). **This confirms "aws" was correct all along** — the "RMI" reading from video 1 and the "osv" reading from video 4's dashboard chart legend (§2.5, §2.7) were both low-resolution misreads of the same "aws" label; do not treat those two speculative readings as real product differences anymore.

**Scanner configuration is genuinely YAML/JSON-editable per sensor**, confirmed on-screen (a config editor with YAML/JSON toggle buttons). Example filesystem-scanner config shown: `paths: [/etc/ssl/certs, /opt/app/keystores]`, `password: changeit`. Example binary-scanner config: `paths: [/usr/local/bin, /opt/app]`, `extensions: [.dll, .exe, .so, .jar]`. Each sensor can carry multiple scanner assignments (the demo sensor ended up with three: binary, filesystem, https-endpoint), each independently schedulable (a `daily` cadence dropdown shown) and independently on-demand-triggerable ("Scan Now" per scanner).

**The live demo scanned a real production website (microsoft.com) via the https-endpoint scanner** and returned a full, correctly-classified certificate chain: `RSA-2048 public key (microsoft.com)` → `Microsoft TLS RSA CA OCSP16` (RSA-2048) → `Microsoft TLS RSA Root G2` (RSA-4096) → `DigiCert Global Root G2` (RSA-2048), every node flagged **High** (quantum-vulnerable), alongside the negotiated cipher `TLS_AES_256_GCM_SHA384` flagged **None** (correctly *not* treated as quantum-vulnerable — AES-256/SHA-384 both land in QAVACH's own `QUANTUM_SAFE` bucket too, Invariant I1). This is a real TLS collector working correctly on a live public target, functionally equivalent to QAVACH's own `FR-130` TLS endpoint collector (`ARCH.md §2.2` — "the highest value-per-line-of-code component in the whole project").

**The live demo also scanned a real Node.js Windows installer (`node-v14.17.1-x64.msi`) via the binary scanner** and surfaced genuine embedded-crypto findings: a `3DES reference` (flagged **Critical**, matching `CLASSICAL_WEAK` in QAVACH's model), plus `MD5`, `SM`, and `AES` references, and two linked-library findings (`advapi32.dll`, `crypt32.dll` — Windows' own crypto API libraries, correctly detected as dependencies). The asset-detail panel for the 3DES finding shows a `detectorType`, `filePath`, and `rowReference` property set — a real provenance record pointing at the exact file and detection method, conceptually equivalent to QAVACH's own `Occurrence` provenance model (`ARCH.md §4`).

### 2.10 Video 7 — "Visualizing Certificate Chains & Trust Relationships" (`pGLHSktbxDI`, 1:17, captions + 4 frames reviewed)

Short, focused deep-dive on the Relationships graph already seen in §2.6/§2.8. Two things confirmed precisely here:

- **Edge legend confirmed**: `issuedBy`, `signedBy`, `containedIn` — three typed relationship kinds (not just "chain of trust"). `containedIn` (shown as a purple dashed line) is new — likely used for a key contained inside a certificate or a keystore, distinct from the CA-issuance chain.
- **A search-as-list view of relationships** (toggle next to the graph view) shows the same connected assets as flat rows with individual risk badges — e.g., searching "sublime" surfaced: `Authenticode SHA-256withRSA` signature (**High**), `SM`/`ARIA`/`AES` references and a linked-library entry (all **None**), `MD5`/`3DES` references (**Critical**), `SHA` and `RSA` references (**High**) — all from the same signed executable's embedded algorithm usage plus its code-signing chain (Sublime HQ Pty Ltd → Sectigo RSA Code Signing CA → USERTrust RSA Certification Authority). This confirms, again, granular per-finding risk classification consistent with the four-tier model in §2.7, this time applied uniformly across a mix of certificate-chain and binary-embedded findings in one unified view.

### 2.11 Video 8 — "CNSA 2.0 & FIPS 140-3 Compliance with CBOM" (`0Cp9OBoY2Xk`, 1:20, captions + 3 frames reviewed)

**Three built-in policy templates confirmed, with citations shown in the UI itself**: "CNSA 2.0" (cited as *NSA CNSA 2.0* — "Commercial National Security Algorithm Suite 2.0 — quantum-resistant algorithm requirements for National Security Systems"), "NIST PQC Readiness" (cited as **NIST IR 8413** — confirms the tentative reading in §2.6; "Post-Quantum Cryptography readiness assessment — identifies assets vulnerable to quantum attacks"), and "FIPS 140-3 Compliance" (cited as *NIST FIPS 140-3* — "minimum algorithm and key size requirements"). Narration states the CNSA 2.0 template enforces: **by 2030, only ML-KEM, ML-DSA, SLH-DSA, and AES-256** — no RSA, no ECDSA — which matches QAVACH's own PQC-alternative set (`ARCH.md §8.1`) almost exactly.

**A "Violation Details" view shows structured, per-asset, human-readable reasoning** — e.g., for a flagged asset: *"Uses prohibited algorithm: RSA (prohibited)... Algorithm not allowed per [policy]... NIST quantum level 0, below required level 3."* This is a genuine design-philosophy overlap with QAVACH's own explainability requirement (`FR-360` — "every score is explainable... can show the inputs, the formula, the policy values used, and the citation") — QCecuring is not just showing a pass/fail badge, it's showing *why*, per asset, with a numeric threshold comparison. **The "quantum level 0 below required 3" phrasing confirms a numeric quantum-security-level scale is genuinely used internally** for policy thresholds, not just cosmetic on a dashboard chart (resolves the tentative "QSL 0-5" inference from §2.5 as a real, load-bearing mechanism, not a marketing label).

### 2.12 Video 9 — "CycloneDX CBOM Export & BOM-Link Integration" (`oQ5i_8nr3UM`, 2:26, captions + frames of the actual raw JSON reviewed)

**This video shows the real, raw exported CycloneDX JSON in a code editor** — the clearest single piece of evidence in this whole review, since it's not a narrated claim but the literal file contents. Transcribed from frame (a component from a real exported CBOM):

```json
{
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-18T18:23:00.87Z",
    "tools": { "components": [ { "type": "application", "name": "QCecuring CBOM", "version": "8.0.1" } ] }
  },
  "lifecycles": [ { "phase": "operations" } ],
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "d295ea47632aaff4e99b7607c086d20636782d3447b38de775c33710517151e5e",
      "name": "app.complexspark.xyz",
      "cryptoProperties": {
        "assetType": "certificate",
        "certificateProperties": {
          "subjectName": "CN=app.complexspark.xyz",
          "issuerName": "CN=ZeroSSL RSA Domain Secure Site CA,O=ZeroSSL,C=AT",
          "serialNumber": "cd64c0e3dc6125fe82741eb4dde9c6d4",
          "notValidBefore": "Sat Nov 21 05:30:00 IST 2020",
          "notValidAfter": "Sat Feb 20 05:29:59 IST 2021",
          "certificateFormat": "X.509",
          "signatureAlgorithm": "SHA384withRSA",
          "fingerprint": { "alg": "SHA-256", "content": "d295ea47632aaff4e99b7607c086d20636782d3447b38de775c33710517151e5e" },
          "algorithmProperties": { "primitive": "pke", "algorithmFamily": "RSA", "parameterSetIdentifier": "2048" },
          "oid": "1.2.840.113549.1.1.1"
        }
      }
    }
  ]
}
```

**Correction to a concern raised while reading the transcript alone**: the narration said the schema shows "primitives, families, NIST quantum level, OID," which sounded like it might mean a vendor risk score (a "quantum level" field) is embedded directly inside `cryptoProperties` — which would have been a direct violation of the separation QAVACH's own Invariant I5 enforces (risk data must live in a separate Risk Register, never in the CBOM body). **The actual JSON on-screen shows no such field.** `cryptoProperties` here is clean: `assetType`, `certificateProperties` (subject/issuer/serial/validity/format/signature-algorithm/fingerprint), `algorithmProperties` (primitive/family/parameterSetIdentifier), and `oid` — all standard, schema-legitimate fields. **This is one component of one file, so it doesn't rule out a `qcecuring:`-namespaced `properties[]` block elsewhere carrying risk data (which would be schema-legal, exactly like QAVACH's own `qavach:` namespace) — but there is no evidence of outright CBOM pollution.** Revise the earlier hedge accordingly: no confirmed finding here, in either direction, on how cleanly they separate risk data from the CBOM body — but no red flag either.

**Dependency graph confirmed as standard CycloneDX `dependencies[]`** — e.g. `{"ref": "<cert-bom-ref>", "dependsOn": ["<issuer-CA-bom-ref>"]}` — narrated as "this cert depends on that CA, this key belongs to that keystore." Standard, unremarkable, and correct usage of the spec's own dependency-graph mechanism for exactly the kind of relationship both products need to express.

**Import supports third-party CBOMs from other tools, not just their own exports** — the demo uploads a **Keycloak-generated CBOM JSON** (a real third-party artifact, not a QCecuring file) and renders it as a browsable table (columns: Name, Type, Asset Type, Algorithm) plus a relationship graph. Confirms genuine interoperability with the wider CycloneDX ecosystem for *viewing* purposes — consistent with the read-only-import architecture already noted in §2.6/§3.

---

## 3. How this compares to QAVACH

| Dimension | QCecuring (as described) | QAVACH |
|---|---|---|
| CBOM schema version | CycloneDX **1.6**, explicitly | CycloneDX **1.7**, explicitly for the Cryptography Registry (`ARCH.md §5.1`) — QCecuring is a version behind on the exact interoperability problem QAVACH's reconciliation layer leans on |
| Storage | MongoDB (document store) | PostgreSQL 16, relational (`ARCH.md §11` — deliberate choice; assets/occurrences are queried/faceted/joined constantly) |
| Deduplication / identity | Single SHA-256 fingerprint per asset, used uniformly | Split instance-vs-class identity model (`ARCH.md §6.1`) — certs/keys as instances (fingerprint/SPKI), algorithms as classes — plus a confidence-precedence and `disputed` mechanism (`ARCH.md §6.4`, Invariant I4). No mention of multi-source conflict handling, precedence tiers, or a "disputed" concept in QCecuring's description — their model reads as single-source-of-truth by construction, which sidesteps the reconciliation problem rather than solving it (fine if they only run their own sensors; unclear how they'd handle a second tool's conflicting claim about the same asset). |
| Risk model | **Correction (see §2.7): confirmed 4-tier classification that matches QAVACH's I1 finding classes** — Critical/broken-today (MD5, SHA-1, DES) ≈ `CLASSICAL_WEAK`; High/quantum-vulnerable (RSA, ECDSA, ECDH) ≈ `QUANTUM_VULNERABLE`; Medium (AES-128, explicitly framed as non-urgent) ≈ `GROVER_AFFECTED`; None/quantum-safe (AES-256, PQC) ≈ `QUANTUM_SAFE`. **QAVACH's "we don't lump AES-128 with RSA" claim is not a clean differentiator vs. this competitor.** What's still absent from QCecuring across all 4 videos: any timing model (no Mosca `X+Y>Z`, no per-function-class shelf-life, no HNDL scoping), and their compliance engine only outputs compliant/violation/warning — no CARAF-style Accept/Phase-out cost-aware outcome. | Mosca's `X+Y>Z` applied **per cryptographic function class** (`ARCH.md §7.2`), HNDL scoped to confidentiality only (Invariant I2), CARAF 5-D framework with four mitigation outcomes including Accept/Phase-out (`ARCH.md §7.5`) — the genuine remaining differentiator is the *timing and decision* layer, not the classification tiers themselves. |
| Compliance frameworks named | CNSA 2.0, FIPS 140-3, custom rules | India DST/NQM roadmap (Dec 2027/2028/2029), NIST IR 8547, CNSA 2.0 (`PRD.md §1.1`) — QAVACH is explicitly built around the Indian regulatory deadline as the binding constraint; nothing India-specific appears in QCecuring's video, suggesting a US/general-market orientation rather than an India-CII focus |
| Migration roadmap / sequencing | Not mentioned in this video at all — no DAG, no waves, no dependency ordering, no cycle detection | Core differentiator per `ARCH.md §9` — dependency-ordered migration DAG, typed edges, wave scheduling, hybrid-bridge cycle detection |
| PQC recommendation engine | Not mentioned in this video | `ARCH.md §8` — ML-KEM/ML-DSA/SLH-DSA selection, hybrid guidance, cited performance table |
| Sensor/collector breadth | 9 types named, including **Active Directory/LDAP** (not currently a QAVACH collector) and generic "AWS services" | TLS endpoint, cert stores, cloud KMS (AWS/Azure/GCP), HSM evidence, SSH host keys, source/SBOM/container scanners (`ARCH.md §2.2`) — no AD/LDAP collector currently planned; worth a TASK.md note if this proves to be a real gap |
| Deployment model | Java sensor agents pushing to a central API over mTLS — **confirmed real in video 3**: a registered sensor shown with an online/offline status, its own scan-history log, and on-demand + scheduled scan triggers | Sandboxed one-shot collector containers per scan job (`SECURITY.md §3`) — confirmed agent-based/continuous-posture model vs. QAVACH's per-scan-run model. This is a real product-shape difference (persistent agent footprint + drift-friendly vs. sandboxed untrusted-code-execution safety per `SECURITY.md §1`) worth a deliberate, stated tradeoff rather than treating QAVACH's choice as strictly superior |
| Speed-to-CBOM claim | "seconds, not days, not weeks" — explicit headline pitch | Not directly comparable yet — QAVACH's NFR-01/02 targets (100k-LOC repo in <10 min; 50k-asset scoring in <60s) are a different kind of speed claim (throughput at scale vs. wall-clock from zero) |

### 3.1 Open questions this raises for QAVACH

- **Does QCecuring's simple SHA-256-fingerprint dedup actually handle multi-tool conflict?** If they only ever ingest their own sensors' output, they never face the problem QAVACH's confidence-precedence/dispute model exists to solve. If QAVACH's reconciliation layer is genuinely the harder, more valuable problem, that's worth stating explicitly and confidently in any comparison — but verify this isn't just missing from a 4-minute overview video before leaning on it as a differentiator.
- ~~Is the "risk engine" in this video the whole story, or a simplified demo?~~ **Resolved by video 4 (§2.7): they have a real 4-tier classification matching QAVACH's I1 finding classes.** The open question now is narrower: does QCecuring have *any* per-function-class timing model (Mosca-equivalent) or cost-aware mitigation-outcome selection (CARAF-equivalent) anywhere in their product? No evidence of either across 4 videos so far — their "Compliance Engine" checks policy conformance, not migration cost/urgency tradeoffs.
- **Continuous agent-based monitoring vs. QAVACH's per-scan model** may be a real product-positioning difference worth a deliberate decision, not an accidental one — continuous sensors give drift detection almost for free (QAVACH has this as `T-109`, unstarred/cuttable), at the cost of a persistent agent footprint QAVACH's sandboxed-per-job model deliberately avoids for the untrusted-code-execution reasons in `SECURITY.md §1`.
- **CycloneDX 1.6 vs 1.7** is a genuine, checkable interoperability gap — if QCecuring CBOMs need to interoperate with QAVACH-consumed tooling later, the version skew matters.

---

## 4. Playlist review complete — summary

All 9 videos in `PLtkuxQ57SmvPnFUVkN-HjX0X4atjgH5VK` reviewed (transcript + frames) as of 2026-09-08. Headline conclusions, most important first:

1. **QCecuring is a real, working, reasonably mature product**, not a slide-deck pitch or an early prototype — confirmed by a live sensor-registration-to-scan-results demo (§2.9) and a populated 21,224-asset inventory across every screen (§2.6–2.11). Low YouTube view counts reflect marketing reach, not product maturity — do not conflate the two in any positioning discussion.
2. **QAVACH's biggest stated differentiator needs revision**: the "we don't lump AES-128 with RSA-2048" claim in `README.md` is *not* unique — QCecuring's dashboard already implements the same 4-tier distinction (classical-broken / quantum-vulnerable / Grover-margin / quantum-safe) that maps directly onto QAVACH's Invariant I1 (§2.7). Recommend revising `README.md`'s differentiation section to lead with what remains genuinely unmatched across all 9 videos: **Mosca's per-function-class timing model (`X+Y>Z`), HNDL scoped to confidentiality only, and CARAF's cost-aware Accept/Phase-out outcomes** — QCecuring's compliance engine only ever outputs compliant/violation/warning against a policy template; it has no equivalent of "this asset costs more to migrate than it's worth, leave it alone."
3. **No migration roadmap, dependency DAG, wave sequencing, or cycle detection appears anywhere across all 9 videos.** This remains QAVACH's clearest, most defensible differentiator (`ARCH.md §9`) and should be the lead claim in any head-to-head positioning, not the finding-classification point.
4. **A real, confirmed architectural difference in CBOM ingestion**: QCecuring's CBOM import is explicitly visualize-only and never merges into the operator's own inventory (§2.6, §2.12); QAVACH's `FR-180` treats an externally-supplied CBOM as a first-class reconciliation source. If accurate, this is a genuine, citable QAVACH advantage for multi-tool environments.
5. **Two citations worth adding to QAVACH's own materials**, both surfaced by QCecuring's marketing and independently verifiable: CycloneDX's ratification as **ECMA-424** by Ecma International (§2.5), and the existence of a numeric NIST-derived quantum-security-level scale used for policy thresholds (§2.5, §2.11) — worth checking whether QAVACH's own risk model should expose something comparable for compliance-template use cases, distinct from its Mosca/CARAF scoring.
6. **A citation discrepancy to resolve, not dismiss**: QCecuring cites CNSA 2.0 milestones as 2025 (prefer) / 2030 (exclusive); QAVACH cites 2027-01-01 (acquisition gate). Both are plausibly real, different milestones within the same NSA advisory — verify the full CNSA 2.0 milestone set against NSA's own document before treating either citation as complete (§2.5).
7. **A possible design weakness to verify, not yet confirmed**: an "Unknown private key" row appeared to default to a "None"/quantum-safe risk color in one inventory view (§2.8) — if accurate, this would be a real methodological gap relative to QAVACH's explicit `UNKNOWN`-class handling (never silently marked safe). Needs a clearer screenshot to confirm before citing confidently.

## 5. Still unknown / to fill in from future sources

- Company size, funding status, founding date, target market (the product itself gives no India-specific signal — likely US/general enterprise, but unconfirmed).
- Pricing/licensing model.
- Any public customer list, case studies, or CII/government deployments.
- Whether "QCecuring" has any relation to the pre-existing `kavachq.in` / KavachQ product noted in `NOTE.md §4.1`, or is fully independent (current evidence across 9 videos: independent — different name, different market signals, no overlap mentioned anywhere).
- Whether risk-scoring data (e.g. the "NIST quantum level" concept) ever leaks into the CBOM body via a vendor-namespaced `properties[]` block, or stays fully separate — §2.12 saw one clean component but can't rule this out file-wide.
- Whether the apparent "Unknown = None risk" behavior (§2.8, item 7 above) is real or a misreading.

*(User indicated more sources will be shared — extend this file rather than replacing it.)*
