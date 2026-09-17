# NOTE.md — Decisions, Corrections and Things We Rejected

The institutional memory of this project. Read before proposing an
architectural change. Most attractive ideas have already been considered and
turned down here for a stated reason; the reason may be wrong, but argue with
it rather than rediscovering it.

Last full review: 2026-09-06.

---

## 1. About this review

The request was to run the plan past an "LLM council." I want to be precise
about what actually happened, because the distinction matters for how much
weight to give what follows.

**What did not happen:** no other models were consulted. There is no council.
I cannot poll GPT or Gemini from here.

**What did happen:** a structured adversarial review from six deliberately
distinct viewpoints — systems architect, PQC domain specialist, enterprise
product, security engineer, hackathon judge, data/schema — followed by
verification of every load-bearing external claim against primary sources
(NIST CSRC, the CycloneDX specification and registry, the CARAF paper, the
DST/NQM and MeitY/CERT-In material, and the actual upstream repository docs
for CBOMkit, cdxgen and Opengrep).

That verification is where the value came from. Four substantive errors in the
prior plan were found by checking sources, not by reasoning harder — they are
in §2. Adversarial reasoning alone would not have caught any of them.

**If you want a genuine second opinion**, the four sections most worth putting
in front of another strong model, in order of leverage:

1. `ARCH.md §7.2` — the per-function-class Mosca derivation. This is the most
   novel and therefore the most likely to be subtly wrong.
2. `ARCH.md §6` — reconciliation identity and confidence precedence. The
   instance-vs-class split for certificates is a judgement call.
3. `ARCH.md §9.1` — the migration DAG edge taxonomy. Ask specifically whether
   any edge type is missing; that list came from reasoning, not from a source.
4. §4 below — the risks. Ask what is missing rather than whether these are real.

Do not ask another model to review the whole document set. You will get
agreeable summarisation. Ask narrow, falsifiable questions about the four
above.

---

## 2. Corrections to the prior plan

Four things carried forward from earlier sessions were wrong. Each is fixed in
`ARCH.md` and each would have caused real damage.

### 2.1 CARAF is not `Risk = Timeline × Cost`

**Prior belief:** CARAF gives `Risk = Timeline × Cost`, producing four outcomes.

**Actual:** CARAF (Ma, Colon, Dera, Rashidi, Garg, *Journal of Cybersecurity*
7(1), 2021, `tyab013`) is a **5-dimension framework**:

1. determine the threat vector driving the assessment
2. inventory the impacted assets
3. evaluate the **expected value of those assets being compromised**
4. identify the mitigation strategy commensurate with that expected value
5. develop a roadmap implementing the strategies per risk class

The four outcomes are right — mitigate/migrate, compensating control, accept,
phase out — but they are the *output of D4*, selected by comparing expected
value against migration cost and risk tolerance. There is no `Timeline × Cost`
product anywhere in the paper. CARAF also explicitly incorporates Mosca's XYZ
as its threat-timing model, which is why the two compose rather than
conflicting.

**Damage avoided:** shipping a two-axis matrix labelled "CARAF" in an SIH deck
would have been immediately falsifiable by any reviewer who opened the paper.
The corrected version is also a *better* engine — expected-value-based
prioritisation is more defensible than an unmotivated product of two axes.

Fixed in `ARCH.md §7.5`. **The infographic in the existing deck showing a
Timeline × Cost decision matrix must be redrawn.**

### 2.2 Target CycloneDX 1.7, not 1.6

**Prior decision:** CycloneDX 1.6 as the canonical schema.

**Why that is now wrong:** 1.7 shipped in late October 2025 and introduced the
**CycloneDX Cryptography Registry** — authoritative, machine-readable
definitions of cryptographic algorithm families and elliptic curves, created
explicitly because different tools name the same algorithm differently and that
inconsistency was blocking policy enforcement and PQC readiness assessment in
government and critical infrastructure deployments.

That is the exact problem QAVACH's reconciliation layer exists to solve. 1.7
also adds the `algorithmFamily` object and deprecates 1.6's free-text `curve`
in favour of a standardised enumeration. 1.7 is backward compatible with
1.4–1.6, so ingesting CBOMkit's 1.6 output costs nothing. cdxgen's `tracebom`
already emits 1.7.

**Damage avoided:** we were about to hand-roll an algorithm-naming taxonomy
that an authority already publishes. That would have been weeks of work, worse
than the standard, and would have made QAVACH's output non-interoperable.

Fixed in `ARCH.md §5.1`, `§5.2`.

### 2.3 Symmetric cryptography is not a migration finding

**Prior implicit assumption:** everything quantum-affected goes in one bucket.

**Actual:** Grover gives a square-root speedup on symmetric search. AES-128
retains roughly 64-bit security against a quantum machine, and the
parallelisation and error-correction costs make even that deeply theoretical.
AES-256 and SHA-384/512 are fine. NIST's own transition work does not put
symmetric algorithms in the PQC migration programme.

Separately, MD5 / SHA-1 / DES / RC4 are broken **today**, for classical
reasons, and lumping them into "quantum risk" is equally wrong in the opposite
direction — it makes an urgent problem look speculative.

**Fix:** four finding classes — `QUANTUM_VULNERABLE`, `CLASSICAL_WEAK`,
`GROVER_AFFECTED`, `QUANTUM_SAFE`. Invariant I1 in `CLAUDE.md`.

**Damage avoided:** a tool that redlines AES-128 as "migrate immediately"
identifies itself as built by people who do not know the field, in the first
thirty seconds of a demo. This single distinction may be the highest-value
correction in this document, and it is also a *differentiator* — several
commercial scanners get it wrong.

### 2.4 HNDL does not apply to signatures

**Prior implicit assumption:** one shelf-life `X` per system.

**Actual:** harvest-now-decrypt-later is a confidentiality attack. You record
ciphertext today and decrypt it after the CRQC exists. There is no analogous
attack on a signature: forging a signature after `Z` on an artefact that
expired before `Z` accomplishes nothing.

So `X` differs by cryptographic function:
- confidentiality (KEM, key agreement, encryption) → `X` = data retention
  requirement. HNDL applies.
- authenticity on ephemeral artefacts (90-day TLS certs, session tokens) →
  `X ≈ 0`.
- authenticity on long-lived artefacts (root CAs, code signing, firmware roots
  of trust) → `X` = how long the artefact must stay trustworthy *after* `Z`,
  which is often 10–25 years.

**Damage avoided:** with one flat `X`, a fleet of short-lived TLS certificates
outranks an offline root CA by sheer count, and the priority order is exactly
backwards. Any PKI architect would spot it.

Fixed in `ARCH.md §7.2`. Invariant I2. This is now demo step 5 in `PRD.md §7`
precisely because it is the clearest evidence the risk model does real work.

---

## 3. Integration decisions and their costs

### 3.1 We do not write a crypto-detection engine

Confirmed correct, and worth restating because the temptation will recur every
time a scanner misses something. cdxgen has crypto-aware AST extraction and OID
mapping; CBOMkit-hyperion does semantic detection for Java, Python and Go;
CBOMkit-theia handles container images. Competing with them is a losing use of
the time available, and the reconciliation layer is worth more than a marginal
seventh detector.

When a scanner misses something, the fix is a knowledge-base entry or a new
*collector for a new source type*, not a new detector for an existing one.

### 3.2 CBOMkit — corrected again, 2026-09-17

**Original assumption (wrong):** "integrate CBOMkit as an ingestion source" —
implying a library dependency, when CBOMkit is a full application (Quarkus
backend, Vue frontend, Postgres).

**First correction (2026-09-06, superseded below):** run stock CBOMkit as an
optional REST sidecar rather than a build dependency, because the actual
scanner supposedly lived only on GitHub Packages behind a PAT.

**Second correction, verified against the live repos (github.com/cbomkit/*)
2026-09-17:** the first correction was itself based on a stale premise.
`cbomkit-lib` is now its own standalone, actively-maintained, **Apache-2.0**
Java repository — not merely a GitHub-Packages-only artifact — supporting
Java, Python, Go (C# in development, explicitly "not yet meant for active
usage" per its own docs). And **the CBOMkit application's own README states it
does not build the target repository before scanning**, which measurably hurts
Java accuracy (unresolved symbols) — precisely the gap `cbomkit-action` exists
to close by building first and passing jar/class paths to the scanner.

**Decision, superseding the sidecar approach:** skip the full CBOMkit
application (Quarkus/Vue/Postgres/OPA) entirely. Build a thin QAVACH-owned
container image wrapping `cbomkit-lib` directly, run inside our own sandbox
with the same `--allow-build-resolution` control every other build-invoking
collector uses — build the target first when allowed, then scan with jar/class
paths configured, matching `cbomkit-action`'s own sequencing. This is a
straight subprocess/container adapter like cdxgen or Syft, not a sidecar
service, and it removes CBOMkit's database and compliance engine from our
deployment footprint entirely (`ARCH.md §13`).

**The one real remaining cost:** `cbomkit-lib` depends on
`com.ibm:sonar-cryptography-plugin` (the actual detection engine, published
via GitHub Packages by the separate `sonar-cryptography` repo) and needs a
`~/.m2/settings.xml` PAT with `read:packages` to build. This is now a
**one-time cost at QAVACH's own image-build/release time** — never exposed to
a scan job, since the built image is pinned by digest like any other scanner.
`sonar-cryptography`'s own detection-rule coverage and licence are
**deliberately deferred**, not evaluated in this pass.

**Damage avoided by re-verifying instead of trusting the six-month-old note:**
we would otherwise have shipped an unnecessary Postgres+Vue+OPA sidecar for a
tool whose only job is producing one CBOM per scan, and inherited its
build-nothing-first accuracy gap without ever knowing a better sequencing
already existed one repository over.

### 3.3 Opengrep is the breadth tier, and we will not tune it

Opengrep (LGPL-2.1 fork of Semgrep 1.100.0) covers languages the AST scanners
miss — C/C++, C#, PHP, Ruby, Rust — via pattern matching, with SARIF output.

It will produce many false positives: crypto in test fixtures, vendored
dependencies, dead code, commented examples, string constants that look like
algorithm names.

**Decision:** Opengrep findings land at `PATTERN` confidence and are handled by
the confidence tier and the dispute mechanism, **not** by rule tuning. Do not
invest in a large custom rule pack. Ten to fifteen rules covering the obvious
API surfaces is the whole budget.

**Rejected alternative:** dropping Opengrep entirely. Language coverage is a
question judges ask, and "we cover C++ at lower confidence, and the UI says so"
is a better answer than "we do not cover C++."

**Licence note:** LGPL-2.1 means separate-process invocation only. Never link,
never vendor into the codebase. NFR-10.

### 3.4 Grype is descoped

Grype finds CVEs in packages. That is not cryptographic discovery. The only
overlap is "your crypto library has a known vulnerability," which is adjacent,
already covered by every SCA tool the target enterprise runs, and not what the
problem statement asks for.

**Decision:** dropped from the pillar set. Keep the adapter interface so it can
be re-added as an enrichment if a reviewer asks. Do not build a UI around it.

**This is a deliberate scope cut.** Naming it as one is more credible than
quietly including a tool that does not fit.

### 3.5 Syft's real cost is the knowledge base, not the adapter

The Syft adapter is trivial. What makes it useful is the purl → cryptographic
capability mapping in `config/knowledge/crypto_libraries.yaml`, and **that
mapping does not exist off the shelf in usable form.**

Curating it for the top ~150 crypto libraries across Java, Python, Go, JS,
.NET, C/C++ and Rust — including which version first shipped ML-KEM/ML-DSA
support — is genuine, unglamorous work. Budget for it explicitly (T-034) and do
not discover on day four that it is a real deliverable.

The compensating benefit: it is also a defensible asset. It is the thing that
makes an SBOM answer PQC questions, and nobody else's SBOM tool does.

**Honesty rule baked into the schema:** a dependency finding proves
**capability**, not **usage**. The UI says "this system *can* do RSA," never
"this system *does* RSA," until an AST or runtime occurrence corroborates it.
Conflating these is the most common way crypto inventory tools inflate counts,
and doing it deliberately would be the most damaging thing in this project.

---

## 4. Risks, honestly stated

### 4.1 The name collides, in two directions

**"Kavach" (कवच, shield) is already heavily loaded in India.** Indian Railways'
national train collision-avoidance system is named Kavach and is extremely well
known — an SIH judging panel will think of it first. Separately, `kavachq.in`
exists as an India-PQC-roadmap product using the name **KavachQ**, in this exact
problem space.

QAVACH is phonetically identical to Kavach.

**Not a blocker**, and the shield metaphor is genuinely apt. But decide
deliberately rather than by default:
- **Keep it** and own it: give the acronym a stated expansion, put it on slide
  one, and differentiate visually. Indian-language names land well at SIH.
- **Adjust it** to something adjacent and unambiguous.

Whatever is chosen, do a fresh search before the deck is finalised — the
`kavachq.in` overlap in particular is the sort of thing a judge with domain
knowledge may already know about.

### 4.2 Discovery coverage is the biggest honest gap

The problem statement names algorithms, keys, certificates, protocols,
libraries, **hardware modules** and **cloud services**. Source scanning and
SBOM analysis — the part that comes free from the delegated tools — covers
maybe 40% of that list.

This is why the TLS/certificate collector (FR-130) and the cloud KMS collector
(FR-140) are P0/P1 rather than nice-to-haves. They are the difference between
partially and substantially answering clause (i).

**HSM remains genuinely partial.** Live PKCS#11 slot enumeration needs vendor
credentials and a physical module. v1 detects HSM *evidence* and reports an
unresolved crypto boundary. Say that plainly in the UI and in the deck;
claiming HSM inventory and then not having it is worse than scoping it out.

### 4.3 `Z` is unknowable and pretending otherwise is fatal

No credible source can tell you when a CRQC arrives. Any single date QAVACH
prints is a policy choice wearing a lab coat.

**Mitigation, and it turns into a strength:** three cited scenarios, the choice
visible on every screen that depends on it, and the Mosca explorer (FR-650)
that lets the operator move `Z` and watch priorities re-sort. Making the
uncertainty interactive is more persuasive than hiding it, and it is the screen
most likely to be remembered.

The deeper point, and the most NTRO-relevant idea in the project: for an Indian
CII operator under the DST roadmap, the binding date is **Dec 2028 or Dec 2029**
— earlier than any plausible `Z`. The constraint is compliance, not physics.
`Z_effective = min(Z_scenario, regulatory_deadline)`. Lead with this.

Caveat to state accurately: the DST roadmap is **advisory**; binding obligations
come from sector regulators. The policy file marks each deadline
`binding: true|false` and the UI distinguishes them. Overstating the mandate
would be an error in the other direction.

### 4.4 Scope is larger than the time available

Four runtimes, seven-plus collectors, eight pipeline layers, a graph UI. This
does not all get built.

**Mitigation:** the P0 set in `PRD.md §4` and the demo path in `PRD.md §7` are
the contract. Everything else is architected, interface-defined, stubbed, and
**labelled in the UI as not yet implemented**. A visible, honest stub reads as
engineering maturity; a hidden one that breaks on stage does not.

Build the vertical slice first — one repo, one image, one endpoint list,
through all eight layers — before broadening any single layer.

### 4.5 We will be asked what we actually built

Have the answer ready and give it without defensiveness: **layers 2 through 7.**
Normalisation, reconciliation, business context, the risk engine, the
recommendation engine, the roadmap. Discovery is delegated to best-in-class
open source, deliberately, and the TLS/cloud/HSM collectors are ours because
nothing suitable existed.

Attempting to claim the scanners' detection capability invites a comparison
QAVACH loses. Claiming the decision layer invites a comparison nothing else
enters.

### 4.6 No LLM anywhere in v1

Tempting: an LLM to classify ambiguous findings or estimate migration effort.

**Rejected for scoring, permanently.** The risk engine must be deterministic,
reproducible and auditable — the same CBOM and the same policy must always
produce the same register, this year and next. A regulator-facing artefact whose
numbers move between runs is not an artefact. It also destroys the air-gap claim
and makes the scoring unexplainable in exactly the way FR-360 requires it to be
explainable.

**LLM-assisted operator-facing narrative is OUT OF SCOPE for v1** (decided
2026-09-17). An earlier revision of this section permitted it for prose
summarisation. That permission is withdrawn, because it contradicts an invariant
we hold elsewhere: any such prose necessarily contains hostnames, file paths and
which systems are weak, so an external API call is exactly the phone-home
behaviour `SECURITY.md §5` declares non-negotiable, and the feature breaks
silently in air-gapped deployments.

The feature flag `QAVACH_ENABLE_NARRATIVE` exists, **ships disabled, and has no
implementation behind it in v1.** It is future scope and will get its own
ideation pass before any code is written. When that happens, the constraints
already identified are:

- LLM output is **decorative** — never an input to reconciliation, risk or
  sequencing, and excluded from the signed artefact.
- **Pseudonymise before prompt assembly** — the model sees
  `SERVICE_A uses RSA-2048`, never a real hostname; rehydrate on render.
- Local/self-hosted endpoint only; no default endpoint value; production refuses
  to start with a non-private endpoint.

Until that ideation happens: **do not build it, do not design around it, and do
not reference it in the demo.**

### 4.6a No error-detection layer on the risk arithmetic — and that is deliberate

A consequence of 4.6: there is no model in the loop to catch an arithmetic or
banding mistake. Compensate structurally rather than with a second opinion —
build a **differential oracle**: an independent implementation of the band
arithmetic as a flat decision table, diffed against the engine in CI. The state
space is small enough to enumerate exhaustively, which is a stronger correctness
argument than any reviewer.

### 4.7 We are a tool that runs untrusted code

cdxgen invokes real build tools (`mvn`, `npm install`, `go mod`) to resolve
dependencies. That is arbitrary code execution on the scan target's terms,
inside our infrastructure. This is not a hypothetical; it is the documented
behaviour of the tool we depend on most.

Non-negotiable: the sandbox in `SECURITY.md §3`, and build resolution off by
default.

### 4.8 The CBOM is itself sensitive

A completed QAVACH inventory is a precise map of where an organisation's weak
cryptography lives — an attacker's target list, ranked by exploitability, with
file paths. For an NTRO-adjacent deployment this is close to the most sensitive
artefact on the network.

Treated as confidential throughout: encrypted at rest, RBAC, full audit log, no
telemetry, air-gap capable, signed exports. `SECURITY.md §5`.

### 4.9 QAVACH's own cryptography will be inspected

A PQC migration tool that signs its own exports with RSA-2048 is a punchline.
Sign with ML-DSA-65 where the library allows; if it does not, use Ed25519 and
**state the limitation in the output**. Prefer a TLS configuration offering
`X25519MLKEM768` where the stack supports it. Expect this to be checked.

---

## 5. Rejected alternatives

| Considered | Rejected because |
|---|---|
| Fork CBOMkit and build QAVACH inside it | Locks us to Quarkus/Vue 2, inherits the GitHub Packages credential requirement, and buries our contribution inside someone else's application |
| Build one custom scanner covering all languages | Loses to purpose-built tools; consumes the whole budget; not where the gap is |
| Single flat risk score | Unexplainable, unarguable, and unusable for a steering committee. Every score must decompose into inputs the operator can dispute |
| Put risk data inside the CBOM | Breaks schema validity and interoperability. Invariant I5 |
| Fuzzy string matching for algorithm reconciliation | Will eventually merge SHA-256 with SHA3-256 or X25519 with X448, silently. Use the CycloneDX registry plus a curated alias table |
| Neo4j for the dependency graph | The graphs are thousands of nodes, not millions. Postgres recursive CTEs plus in-memory NetworkX are sufficient and remove a service |
| Event sourcing for scan state | CBOMkit does this and it is the most complex part of their codebase. A status column and a job queue is enough |
| Kubernetes-native operator for scan jobs | Right answer for enterprise scale, wrong answer for now. Docker/Podman per-job containers, with the interface kept clean enough to swap later |
| Live HSM slot enumeration in v1 | Needs vendor credentials and physical hardware. Evidence-based detection, honestly labelled |
| Automated remediation / PR generation | A tool that writes cryptographic code is a different and far more dangerous product |
| Async workers (ARQ) | Collectors are blocking subprocess calls. Async buys nothing and complicates everything. RQ with sync workers |
| D3 for the roadmap graph | No built-in DAG layout, poor performance past ~1k nodes. Cytoscape.js with dagre |

---

## 6. Open questions

Track these here. When one is resolved, move it into the relevant document and
strike it here.

**~~OQ-01~~ — RESOLVED 2026-09-17. See `ARCH.md §9.1`, §9.3.**
A seventh edge type `regulatory-gate` is added, and it required **node
splitting** (`unit.start` → `unit.complete`) because it gates completion rather
than start, permits parallel submission, and fails by rework-and-requeue with no
ETA. Real for Indian CII given TEC/STQC/BIS, and for BFSI given NPCI/UIDAI/CCA.
Two of the other candidates turned out **not** to be precedence edges at all:
key escrow is a *retention constraint* (`destroy_prohibited_until` + legal hold,
plus decrypt-capability retention on the codebase), and certificate pinning is a
*cycle variant* needing pin-superset-then-rotate with an adoption-telemetry
gate, not the generic hybrid bridge. Shared-resource capacity is a scheduling
problem (RCPSP), deliberately out of scope beyond infeasibility detection.

**OQ-02 — How is `Y` calibrated?**
The multipliers in `ARCH.md §7.4` are plausible but unmeasured. Is there any
published PQC migration effort data to anchor against? NIST NCCoE's SP 1800-38
series may contain something usable. Until then the UI labels them planning
heuristics, which is honest but weak.

**~~OQ-03~~ — RESOLVED 2026-09-17. See `ARCH.md §6.1`.**
Two-tier identity for CA certificates: the **SPKI hash is the class that carries
the risk verdict**, and each fingerprint-keyed certificate is an *occurrence* of
it. A CA reissued with the same key is the same risk asset; a rekeyed CA is a
new one. Applies to roots and intermediates alike. End-entity certificates stay
fingerprint-keyed. This is the same core/occurrence pattern used for algorithms
(§6.1) and for usage qualifiers (§6.4) — one pattern, three applications.

**OQ-04 — Should QAVACH emit the IETF Cryptographic Asset Inventory format?**
There is an active internet-draft defining an org-level CAI schema distinct
from a component-level CBOM — which is precisely what QAVACH produces. If it
progresses, aligning to it is more valuable than the bespoke Risk Register.
Track the draft; do not depend on it.

**OQ-05 — What is the false-positive rate, actually?**
Unmeasured. Before any accuracy claim is made anywhere, run the pipeline
against 3–5 well-known open-source repositories with hand-labelled ground
truth and publish the numbers. Making no accuracy claim is far better than
making an unmeasured one.

**~~OQ-06~~ — RESOLVED 2026-09-17. No bespoke Indian schema exists.**
CERT-In *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM* v2.0
(09-07-2025) §8.4.1.5: BOMs shall use recognised industry-standard formats,
*"such as SPDX or CycloneDX"*. Their Table 9 minimum elements for cryptographic
assets (name, asset type, primitive, mode, crypto functions, classical security
level, OID; key id/state/size/dates; protocol name/version/cipher suites)
map onto CycloneDX `cryptoProperties` almost one-to-one. CycloneDX 1.7 stays
canonical. **Two new obligations fall out of the same document:** a **VEX**
document is required on discovery of a crypto vulnerability with four statuses
(Not Affected / Affected / Fixed / Under Investigation), and §8.4.1.8 mandates
consumer-side reconciliation of supplier CBOMs against deployed reality.

**OQ-07 — What is the `MigrationAuthority` derivation accuracy?**
The rules in `ARCH.md §4.1` are principled but unmeasured. How often does a
`SELF` asset get misclassified as `EXTERNAL_TRUST_ANCHOR` and silently dropped
from the roadmap? That failure mode is worse than the noise it removes. Needs a
labelled corpus alongside OQ-05, and a UI affordance to reclassify.

**OQ-08 — Does the CERT-In VEX obligation apply to us, and in what format?**
§8.4.1.6 requires VEX on vulnerability discovery, and §7.2.14 references CSAF.
Unclear whether a *cryptographic* weakness counts as a vulnerability for this
purpose or whether it applies only to CVEs in components. If it applies, VEX
generation is an export target we do not currently have.

**OQ-10 — Should `tls.endpoint` wrap testssl.sh for the classical parameter
checks, or stay fully custom?** testssl.sh (GPLv2) covers protocol
version/cipher-suite/cert-chain checking well, but no existing scanner probes
hybrid post-quantum key-exchange groups — that gap is why `tls.endpoint` is
worth owning at all. Wrapping testssl.sh as a subprocess adapter (same
separate-process-only treatment already given to Opengrep's LGPL-2.1, `NOTE.md
§3.3`) for the classical half, and layering a thin custom probe only for
hybrid-group negotiation, would cut real code at the cost of a GPLv2 line in
`docs/THIRD_PARTY.md`. Not decided; a `TASK.md` item before Phase 3
implementation, not a silent default to full custom-build.

**MODEL-01 — What is the exact shape of a `Dispute` record?** `ARCH.md §6.4`
describes dispute behaviour in prose (per-attribute, retains every
conflicting claim, "silence is not a claim") but never gives a concrete
dataclass the way it does for `CryptoAsset`/`Occurrence`. T-010 implemented
the smallest defensible shape — `Dispute(attribute, claims: tuple[
AttributeClaim, ...], adjudicated_value, adjudicated_by, adjudicated_at)`,
with `AttributeClaim(value, source_collector, confidence, locus)` — marked
`# QAVACH-OPEN: MODEL-01` in `packages/core/src/qavach_core/model/dispute.py`.
Revisit when T-023 (dispute detection) is built; real merge code may want a
different structure.

**MODEL-02 — What are `System.data_classification`'s actual levels?**
`ARCH.md §4` and `PRD.md FR-251` both require the field but neither
enumerates it. T-010 shipped `DataClass` with four common enterprise tiers
(public/internal/confidential/restricted) as a placeholder, marked
`# QAVACH-OPEN: MODEL-02` in `packages/core/src/qavach_core/model/system.py`.
Revisit once a real customer's taxonomy — or a regulatory one, e.g. an
RBI/SEBI data-classification circular — is known; FR-252's retention-inference
table will need to key off whatever this becomes.

**~~OQ-09~~ — RESOLVED 2026-09-17. See `ARCH.md §6.2`.**
`Locus`'s `FileLocus(path, offset)` has no host field — fine for a local mount
where the target is implicit, but wrong for agent-collected evidence, which
needs to say *which host*. A new variant, `HostLocus(host_identity, path,
offset)`, is added to the union. `host_identity` is the **agent's registered
identity** issued at enrollment (`ARCH.md §3a`), never an operator-supplied
hostname string — a typed string can be wrong or spoofed, the identity the
backend itself issued cannot. `FileLocus` is unchanged and stays scoped to
local-mount contexts (binary/image scanning); it is not repurposed.

---

## 7. Decision log

Append one line per decision that a future reader would otherwise have to
re-derive. Do not log routine work.

| Date | Decision | Where |
|---|---|---|
| 2026-09-06 | Canonical schema is CycloneDX 1.7, not 1.6; adopt the Cryptography Registry as the naming authority | `ARCH.md §5` |
| 2026-09-06 | CARAF corrected to the 5-D framework; expected-value-based D4 | `ARCH.md §7.5` |
| 2026-09-06 | Four finding classes; symmetric crypto is informational, never a migration item | Invariant I1 |
| 2026-09-06 | `X` derived per cryptographic function; HNDL is confidentiality-only | Invariant I2, `ARCH.md §7.2` |
| 2026-09-06 | `Z_effective = min(Z_scenario, regulatory_deadline)`; regulatory dates ship as cited policy | `ARCH.md §7.3` |
| 2026-09-06 | CBOMkit is an optional REST sidecar, never a build dependency | `ARCH.md §2.2`, §3.2 |
| 2026-09-06 | Grype descoped | §3.4 |
| 2026-09-06 | Risk data lives in a separate Risk Register, not in the CBOM | Invariant I5 |
| 2026-09-06 | No LLM anywhere in the scoring path | §4.6 |
| 2026-09-06 | Python 3.12 / FastAPI / RQ / Postgres / React+Vite fixed | `CLAUDE.md §4` |
| 2026-09-17 | DST/NQM ladder is **six dates across two tracks**, not three; cite the final May 2026 report | `PRD.md §1.1`, `ARCH.md §7.3` |
| 2026-09-17 | `UNKNOWN` never renders as safe; coverage failure ≠ risk verdict | Invariant I8 |
| 2026-09-17 | `MigrationAuthority` added; only `SELF` units enter the roadmap | Invariant I9, `ARCH.md §4.1` |
| 2026-09-17 | `X` split into `X_conf` / `X_integ`; `max()` upward over derivation consumers; TNFL cited | `ARCH.md §7.2` |
| 2026-09-17 | Confidence precedence is **attribute-scoped**; silence is not a claim; multi-usage ≠ dispute | `ARCH.md §6.4` |
| 2026-09-17 | `mode`/`padding` removed from the identity hash — they are call properties, not key properties | `ARCH.md §6.1` |
| 2026-09-17 | Seventh edge type `regulatory-gate` + node splitting; escrow is a retention constraint; pinning is a cycle variant | `ARCH.md §9.1`, §9.3 — resolves OQ-01 |
| 2026-09-17 | CA identity by SPKI hash; certificates are occurrences of it | `ARCH.md §6.1` — resolves OQ-03 |
| 2026-09-17 | CERT-In accepts SPDX or CycloneDX; no bespoke Indian schema; VEX obligation noted | resolves OQ-06 |
| 2026-09-17 | Reconciliation is **mandated** by CERT-In §8.4.1.8, not self-inflicted | `PRD.md §1.1` |
| 2026-09-17 | Policy templates carry an applicability scope; ~100% violation rate is a scoping error | `ARCH.md §7.4a` |
| 2026-09-17 | No scalar `key_size`; `parameterSetIdentifier` + data-quality queue | `ARCH.md §4.2` |
| 2026-09-17 | Adopt the DST six-factor migration-cost model as the published basis for `Y` | `ARCH.md §7.4` |
| 2026-09-17 | **LLM narrative is out of scope for v1**; flag ships disabled, no implementation; separate ideation later | §4.6 |
| 2026-09-17 | "Do not write scanners" reworded to "do not build a crypto-detection **engine**"; 7 of 9 collectors are ours | `CLAUDE.md §2`, §3.1 |
| 2026-09-17 | Design to NQM assurance level **L3**; QAVACH is itself a named product category | `SECURITY.md`, `README.md` |
| 2026-09-17 | `tls.store`, `hsm.evidence`, the deployed-artefact collector and `sshd_config` inspection move exclusively to the deployed agent; no sandboxed-subprocess variant remains for them | `ARCH.md §2.3`, §3a |
| 2026-09-17 | Agent is outbound-poll-only, accepts a typed scan spec only (no arbitrary execution), and speaks mTLS; enrollment issues the identity `HostLocus` attributes evidence to | `ARCH.md §3a`, `SECURITY.md §2a` |
| 2026-09-17 | BOM export is scoped (`component`/`system`/`root`) as three views over the one already-reconciled asset graph, never a bottom-up re-merge | `ARCH.md §10.1`, `PRD.md FR-501` |
| 2026-09-17 | New `ad.adcs` collector added, wrapping Certipy (MIT) as a network-mode sandboxed subprocess — needs only LDAP + a domain credential, no agent. PingCastle evaluated and rejected as a shipped dependency (Non-Profit OSL 3.0 forbids commercial bundling, fails NFR-10); may be named only as an optional external-report ingestion path. ADRecon (AGPLv3) and BloodHound CE (Apache-2.0, wrong tool — attack-path graph, not crypto inventory) deprioritised | `ARCH.md §2.2`, `PRD.md FR-135` |
| 2026-09-17 | `tls.store` now wraps certfinder (Apache-2.0) for the filesystem walk and SPKI fingerprinting; QAVACH keeps only PKCS#7 parsing and CycloneDX mapping. Moved from the "QAVACH-built" table to "Delegated" in `ARCH.md §2.2` since the core parsing is no longer ours | `ARCH.md §2.2` |
| 2026-09-17 | Agent-side file parsing runs in a short-lived, resource-limited worker process (rlimits + wall-clock timeout + further-dropped privilege), never inline in the agent's main process — pattern confirmed against osquery/Velociraptor/GRR Rapid Response prior art, GRR's isolated native-artifact-parsing subprocess being the direct precedent. Resolves the containment gap the sandboxed-subprocess model closed with a throwaway container and the bare agent model did not | `ARCH.md §3a` (Containment for hostile input), `SECURITY.md §2a` |
| 2026-09-17 | `tls.endpoint` stays substantially custom — testssl.sh/sslyze/nmap all lack hybrid-PQ-group probing (`X25519MLKEM768`); whether to wrap testssl.sh (GPLv2) for the classical parameters is left open, not yet a decision | `ARCH.md §2.2` |
| 2026-09-17 | **Re-corrected `source_scan.cbomkit`**: drop the full CBOMkit sidecar app (Quarkus/Vue/Postgres/OPA) entirely; wrap `cbomkit-lib` (Apache-2.0, now a standalone repo) directly as a pinned build-then-scan container, matching `cbomkit-action`'s own sequencing. The GitHub Packages PAT for `com.ibm:sonar-cryptography-plugin` is a one-time QAVACH-side image-build cost, never exposed to a scan job | `NOTE.md §3.2`, `ARCH.md §2.2`, §13 |
| 2026-09-17 | cdxgen's npm package renamed `@cyclonedx/cdxgen` → `@cdxgen/cdxgen` in v13 (org moved to github.com/cdxgen/cdxgen); the old scope only receives fixes, never v13+ features. `config/scanners.yaml` must pin the new name. `cbom`'s own crypto detection is Java keystores/certs + JS/TS source-level algorithms only — complementary to `cbomkit-lib`'s Java/Python/Go coverage, not overlapping | `ARCH.md §2.2` |
| 2026-09-17 | Re-verified Syft (no native crypto capability, purl-mapping layer still required) and Grype (still pure CVE/vulnerability scanning, no crypto-asset capability) against their live repos — both confirm the existing decisions (`NOTE.md §3.4`, §3.5) unchanged | `NOTE.md §3.4`, §3.5 |
| 2026-09-17 | Re-verified Opengrep (LGPL-2.1, Semgrep v1.100.0 fork, SARIF confirmed — no changes) and CBOMkit-theia against live repos. Theia is under-documented in our own spec: standalone (no GitHub-Packages dependency, unlike `cbomkit-lib`), runs on directories as well as images, and ships `secrets`/`javasecurity`/`opensslconf`/`problematicca` plugins beyond bare certificate discovery — its `certificates` plugin is PEM/DER only, so it stays complementary to certfinder's JKS/PKCS12 coverage, not redundant | `ARCH.md §2.2` |
| 2026-09-17 | `tls.store` (agent-side) now also invokes CBOMkit-theia's `dir` command alongside certfinder — free, additive coverage (secrets, OpenSSL config, known-bad-CA flagging), both Apache-2.0, no new credential cost | `ARCH.md §2.2`, `TASK.md` T-036 |
| 2026-09-18 | **T-016a, T-016b done — Phase 1 complete.** `reconcile/authority.py`: `derive_migration_authority` implements ARCH.md §4.1's four rules exactly, taking pre-decided context flags rather than inventing an undocumented heuristic for "is this locus third-party" or "does this regime externally specify crypto" — ARCH.md never specifies how to derive those from raw Locus/System data, so this function doesn't guess. File placed in `reconcile/` as a judgement call (§4.1 sits under "canonical data model" in ARCH.md, not "reconciliation", but no other layer is named) — flagged here, not silently decided. `normalize/quality.py`: plausible-modulus table deliberately includes historically-real-but-weak sizes (512/768/1024 bit RSA) since IDEATION.md §2.2b lists them in the same distribution as genuine parse artefacts (2450/281-bit) without calling them wrong — classifying weak-but-real keys is classify.py's job, not the data-quality queue's. Filename detection uses deterministic string checks (SECURITY.md §9), not regex | `packages/core/src/qavach_core/reconcile/authority.py`, `packages/core/src/qavach_core/normalize/quality.py` |
| 2026-09-18 | **T-014 done.** `normalize/cbom.py` extracts `cryptographic-asset` components from a parsed 1.4-1.7 CBOM into `NormalisedClaim`s. Checked the actual vendored 1.7 schema directly rather than trusting ARCH.md §5.1's summary, and found two concrete version-compatibility details neither the summary nor a guess would have caught: (1) `algorithmProperties.curve` is **deprecated** in 1.7 in favour of `ellipticCurve` — both are checked, `ellipticCurve` preferred; (2) `evidence.identity` can be a **single object** (deprecated, pre-1.6) or an **array** (1.6+) per the schema's own `oneOf` — always normalised to a tuple here. **Real bug caught by the Phase-1-exit-criteria test itself:** `resolve_algorithm` (T-012) ignored a claim's own self-reported `parameterSetIdentifier` whenever the OID/alias target didn't specify one (e.g. the generic `rsaEncryption` OID applies to any RSA key size) — `RawAlgorithmClaim` gained a `parameter_set` field, used as a fallback in all three resolution branches. Also found: CDX's `identity[].field` enum is `{group, name, version, purl, cpe, omniborId, swhid, swid, hash}` — my first schema-validation attempt used `"algorithm"`, an invalid value, which the vendored schema itself correctly rejected. A hand-cdxgen-style 1.7 fixture (not a *real* recorded cdxgen output — that's T-024's fixture-corpus job in Phase 2) proves both documents converge to the same resolved result for the Phase 1 exit criterion | `packages/core/src/qavach_core/normalize/{cbom,resolve}.py`, `tests/core/test_cbom_normalisation.py` |
| 2026-09-18 | **T-013, T-015, T-015a, T-015b, T-015c, T-016 done.** `config/knowledge/aliases.yaml` (67 entries — OIDs, names, curve aliases). Every PQC OID cross-checked against 3 independent primary sources (NIST CSOR, IETF draft-ietf-lamps-dilithium-certificates, RFC 9814) before use, not hand-written (A-19). **Real gap found and fixed:** most concrete algorithm names tools actually emit (`SHA-256`, `AES-256`, `RSA-2048`) are NOT literal registry family names — the registry groups them under abstract families (`SHA-2` covers 224/256/384/512) — so these needed explicit name aliases too, beyond the PQC/curve ones originally planned. **Second gap:** `X25519`/`Curve25519` are NOT cross-referenced as aliases in the vendored registry (unlike P-256's rich cross-references) — added `AliasTable.curve_aliases` as a new overlay, proven necessary by a test that shows resolution genuinely fails without it. `classify.py` is table-driven from `classification_rules.yaml` (T-015); the "no symmetric algorithm → QUANTUM_VULNERABLE" property test runs over **every symmetric family the real registry defines** (~80 families), not a hand-picked sample. Invariant I8 (T-015a) got a real foundational contract — `FINDING_CLASS_TOKEN` + `aggregate_by_finding_class`, since no aggregation/UI layer exists yet to test against directly. Golden PQC test (T-015b) is 36 assertions (18 OIDs × resolve + classify). Curve corpus (T-015c) extended to P-192/224/256/384/521 and secp256k1 using the registry's own cross-references, plus the X25519/X448 overlay. One known, deliberately-out-of-scope data quality nuance: a handful of obscure WTLS-era curves (e.g. K-233) appear under two different OID arcs in the vendored registry with overlapping names — not disambiguated, not relevant to any target this project scans | `config/knowledge/aliases.yaml`, `classification_rules.yaml`, `packages/core/src/qavach_core/risk/classify.py`, `packages/core/src/qavach_core/normalize/function.py` |
| 2026-09-18 | **T-012 done.** `normalize/{registry,aliases,resolve}.py` implement the 4-step order against the *real* vendored registry, not synthetic fixtures. Since the vendored registry has no algorithm-family OID data (T-011's finding), step 1 (OID) consults `AliasTable.by_oid` — QAVACH's own curated table (T-013's data) — not the vendored file; only curve OIDs come from the registry itself. `primitive` resolution trusts a claim's self-reported value first and only fills in from the registry when a family has exactly one possible primitive (AES spans block-cipher/ae/key-wrap/mac — guessing among those without the claim's own mode context would be a guess, not a resolution, so it returns `None` deliberately in that case). **Bug caught by a real-data test, not a synthetic one:** curve lookup by OID string (as opposed to a name like "P-256") initially failed — the registry only indexed curves by name/alias, not by the OID itself; fixed and covered by `test_curve_aliases_collapse_to_the_same_oid`, which proves `secp256r1`/`prime256v1`/`P-256`/the OID all resolve to one canonical value using the actual vendored data. `packages/core`'s zero-I/O rule holds throughout: `CryptographyRegistry.from_dict`/`AliasTable.from_dict` take already-parsed dicts; the actual file read happens in test code (ordinary test I/O) — production wiring (reading the files at pipeline startup) is left to whichever future task first needs it (T-072 or similar), not invented here | `packages/core/src/qavach_core/normalize/`, `tests/core/test_registry.py` |
| 2026-09-18 | **T-011 done.** Vendored 5 files from `CycloneDX/specification` tag `1.7.2` (commit `349314a`), not just the main schema — `bom-1.7.schema.json` `$ref`s `cryptography-defs.schema.json`, `jsf-0.82.schema.json` and `spdx.schema.json` by relative filename; vendoring only the main file would have silently needed the network (or failed) on first real validation, breaking invariant I7. Verified genuinely offline: `socket.socket` replaced with a function that raises, then a real ML-KEM-768 component validated successfully and a malformed document was correctly rejected — codified as `tests/test_cdx_registry.py`, not a one-off check. **Important finding for T-012:** `cryptography-defs.json` has no OID→family lookup table, only canonical names/patterns — OID resolution (§5.2 step 1) needs a separate NIST-sourced table, this vendored file only covers steps 2–3 | `config/knowledge/cdx-crypto-registry/`, `tests/test_cdx_registry.py` |
| 2026-09-18 | **T-010 done.** Domain model implemented per `ARCH.md §4` as `src`-layout submodules (`model/{enums,locus,identity,dispute,asset,system}.py`). Two things ARCH.md never gives a concrete shape for — `Dispute`'s exact fields and `System.data_classification`'s enum levels — got the smallest defensible implementation, marked `# QAVACH-OPEN: MODEL-01`/`MODEL-02` in code and logged in `NOTE.md §6`, rather than silently guessed. `CryptoAsset`/`System` carry light `__post_init__` validation (occurrences non-empty, disputed⇒disputes non-empty, criticality 1..5, retention_years ≥ 0) — correctness checks, not I/O, so they stay inside T-004's zero-I/O contract. 40/40 tests pass, mypy strict clean on 13 source files | `packages/core/src/qavach_core/model/`, `tests/core/test_model.py` |
| 2026-09-18 | **ruff config gap fixed before it caused damage.** ruff 0.16+ formats Python code blocks embedded in Markdown by default — `ruff format .` was about to rewrite ARCH.md/CLAUDE.md's hand-aligned pseudocode examples. Added `extend-exclude = ["*.md"]`. Caught during T-010, before `make fmt` was ever run unscoped; no doc file was actually touched | `pyproject.toml` |
| 2026-09-18 | **T-005 done.** `docs/THIRD_PARTY.md` — verifying licences live caught a real error in the draft: Redis is tri-licensed (RSALv2/SSPLv1/AGPLv3) **only starting at Redis 8**; `redis:7-alpine` (what `docker-compose.yml` actually pins) is still BSD-3-Clause. Would have shipped an incorrect licence claim if not checked against the live `LICENSE.txt` instead of general knowledge | `docs/THIRD_PARTY.md` |
| 2026-09-18 | **T-006 done.** `config/scanners.yaml` pins real, live-verified digests for the three upstream-published images (cdxgen, syft, cbomkit-theia); the three QAVACH-must-build wrappers (opengrep, cbomkit-lib, certipy) are left `digest: null` naming the building task, not faked. `scripts/pull_scanners.py` verified end-to-end — all three real images pulled successfully by exact digest. **`ghcr.io/cdxgen/cdxgen` is 15.5GB** (bundles a Java+Node toolchain) — worth knowing before T-032 (adapter) or T-123 (air-gap bundle) budgets pull time/storage | `config/scanners.yaml`, `scripts/pull_scanners.py` |
| 2026-09-18 | **T-004 done.** `tests/test_architecture.py` uses **default-deny AST inspection**, not "try to import qavach_core and see if it raises." The latter would not catch a violation: this is a shared workspace venv, so FastAPI/SQLAlchemy are genuinely installed for sibling packages and a stray `import fastapi` in core would succeed at runtime. Every absolute import is classified as self / stdlib-pure / stdlib-io / allowed-third-party / forbidden, with the third-party allowlist starting **empty** (matches `packages/core/pyproject.toml`'s zero declared deps) — this also subsumes "nothing from collectors" for free, since `qavach_collectors` isn't stdlib and isn't allowlisted. Verified the detection logic actually fires by injecting `import fastapi` into a real core file, confirming the test failed with a correct file:line message, then reverting | `tests/test_architecture.py` |
| 2026-09-18 | **T-003 done.** `.github/workflows/ci.yml` runs the exact same commands as the Makefile (`make lint`, `make test-unit`) plus `uv lock --check` / `pnpm install --frozen-lockfile` to catch lockfile drift — one source of truth for "passing," never a CI-only check that can diverge from the local loop. biome/vitest inherit the Makefile's honest-stub skip until `apps/web` exists (T-100). Every Action version tag (`actions/checkout@v4`, `astral-sh/setup-uv@v3`, `pnpm/action-setup@v4`, `actions/setup-node@v4`) and input name verified against the live `action.yml` before use, not assumed | `.github/workflows/ci.yml` |
| 2026-09-17 | **T-002 done.** `docker-compose.yml` (postgres:16-alpine, redis:7-alpine, minio). **MinIO no longer publishes to Docker Hub** — `minio/minio` 404s on the registry as of this date; the only current source is `quay.io/minio/minio`. Verified against the live Quay API before pinning. `make dev` (default `ENGINE=docker`, override to `podman`) brings all three up and waits for health via `docker compose up --wait`; verified end-to-end against both engines on this machine | `docker-compose.yml`, `Makefile` |
| 2026-09-17 | **T-001 done.** Repo skeleton uses a `src/` layout per Python workspace member (`packages/core/src/qavach_core/...`), not the flat layout the `CLAUDE.md §3` ASCII tree literally shows — a bare top-level import name like `core` or `collectors` risks colliding with a real PyPI package once dependencies are added. Distribution names are `qavach-core`, `qavach-collectors`, etc.; import names are `qavach_core`, `qavach_collectors`, etc. The tree's *logical* grouping (`packages/core/model/` → `qavach_core.model`) is unchanged. `uv sync` and `pnpm install` both verified clean; `make test-unit` and `make lint` pass with no Docker/network/DB | `CLAUDE.md §3` |
