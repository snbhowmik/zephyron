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

**OQ-10 — RESOLVED 2026-09-19, T-035: `tls.endpoint` stays fully custom,
does not wrap testssl.sh.** Neither horn of the original dilemma survived
contact with what's actually available: Python 3.12's stdlib `ssl` module
cannot produce a full certificate chain at all (`SSLSocket.
get_unverified_chain()`/`get_verified_chain()` are 3.13+ only, confirmed
live) and has no public API for the negotiated TLS 1.3 group (confirmed
live: no `group()` method anywhere on `SSLSocket`, and `set_ecdh_curve()`
rejects hybrid PQ group names outright — `unknown elliptic curve name
'X25519MLKEM768'`) — so satisfying ARCH.md's "full chain" and "probe for
hybrid group support" requirements from stdlib alone was never actually an
option, regardless of the testssl.sh question. What *does* work, confirmed
live against both a real public endpoint and an offline `openssl s_server`
fixture: the system's own `openssl s_client -showcerts -groups <name>`
prints the full PEM chain, the negotiated protocol/cipher, and a
`Negotiated TLS1.3 group: ...` line for *any* group name OpenSSL 3.2+
recognises, hybrid ones included (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`SecP384r1MLKEM1024` — the exact list `openssl list -tls-groups` reports).
This is not "wrapping testssl.sh": `openssl` is the same Apache-2.0-licensed
library Python's own `ssl` module binds to, already present wherever Python
is, not a new dependency, and testssl.sh's actual value-add (broad
legacy-protocol/vulnerability-scanning breadth) was never the goal here —
ARCH.md's own framing is "the largest gap in the problem-statement
coverage," a narrower, precise per-cert-inventory-plus-hybrid-detection
task testssl.sh doesn't uniquely solve anyway. Net result: zero new
licence entries in `docs/THIRD_PARTY.md`, and the hybrid-group probe (the
actual reason to own this collector) works, which was never guaranteed by
either original option on its own.

**OQ-11 — How does CBOMkit-theia run agent-side, given it has no binary
releases?** Discovered during T-036 and raised with the user rather than
picked around silently. `ARCH.md §2.2` specifies `tls.store` as certfinder
**and** CBOMkit-theia's `dir` command, both "subprocess, both agent-side,"
and `§2.3` says `tls.store` runs *exclusively* via the deployed agent with
no sandboxed-subprocess fallback. But theia publishes **zero binary assets
on every GitHub release** (checked live: `v1.1.0`, `v1.1.1`, `v1.1.2`) — it
ships as a container image only, and the agent has no container runtime by
`§3a`'s own hard rule ("Python only... no new runtime"). certfinder, by
contrast, publishes real per-OS/arch binaries with checksums, which is why
that half was buildable immediately. Three viable resolutions, none free:
(a) **cross-compile theia from Go source** (Apache-2.0, so redistributing a
built binary is fine) into a companion binary shipped with the agent —
needs a Go toolchain build step and a per-OS/arch release matrix, the same
category of work as T-031c's PyInstaller matrix; (b) **give `tls.store` a
sandboxed-subprocess variant after all** for hosts that do have a container
runtime — reopens `§2.3`'s "one target, one mode, no variant" rule, which
exists for a good reason (two divergent code paths claiming to produce the
same evidence); (c) **drop theia's half**, losing real capability
(secrets detection, `opensslconf`, `problematicca`) the spec currently
counts on. **Decision 2026-09-19: build the certfinder half now, defer the
rest as `T-036c`** — option (a) is the most likely landing place but is
genuine release-engineering work, not something to improvise mid-collector.

**OQ-12 — What does `requires_sandbox` mean for QAVACH's *own* network
collectors?** `ARCH.md §2.3` lists `tls.endpoint`, `cloud.*` and `ad.adcs`
under "sandboxed subprocess," and `SECURITY.md §3` says every
`requires_sandbox = True` collector runs in a fresh per-job container. Built
so far, the three behave differently: `ad.adcs` genuinely runs Certipy in the
container; `tls.endpoint` (T-035) sets `requires_sandbox = True` but runs
inline in the worker, shelling to the host's `openssl`; `cloud.aws` (T-040)
sets `False` and runs inline. The flag is currently used inconsistently. The
defensible reading — "needs `packages/sandbox`'s per-job container because it
executes a *third-party binary* against untrusted input" — makes `tls.endpoint`
and `cloud.aws` `False`, but that revises what `ARCH.md §2.3`'s table appears
to say, so it is recorded here rather than silently flipped. Note the network
posture for those two is enforced elsewhere (SSRF policy; read-only IAM
self-check), not by `--network=none`.

**OQ-13 — Where do non-algorithm findings go?** `ad.adcs` reports ESC1–ESC8
misconfigurations (`PRD.md FR-135`: "maps onto QAVACH's finding classes"). An
ESC1 template is dangerous because of who can enrol and what it permits, not
because of a weak primitive, so forcing it into invariant I1's four classes
(`QUANTUM_VULNERABLE`/`CLASSICAL_WEAK`/`GROVER_AFFECTED`/`QUANTUM_SAFE`) would
mislabel it, and `RawClaim` is algorithm-shaped with nowhere to carry it. For
now `AdcsFinding` is a typed side-channel recoverable from `CollectorResult.raw`
(`findings_from_raw`); the algorithm-shaped part (a template's minimum RSA key
length) does become a claim. Also unresolved: no `Locus` exists for
directory-service objects, so template claims use
`CloudLocus(provider="ad-cs", ...)` with one distinct `resource_arn` per
template — distinct because two sizes at one locus would read as a dispute.

**OQ-17 — `runtime.tracebom` cannot observe TLS negotiation or cipher suites inside the sandbox.** Its eBPF tracing needs `CAP_BPF` (removed by `--cap-drop=ALL`, deliberately) and TLS needs network (denied). `PRD.md FR-170`'s "actually-negotiated TLS parameters" is therefore *not* delivered by this collector as sandboxed; only loaded-library evidence is. Options: accept and re-scope FR-170 to loaded providers, or design an operator-approved privileged mode (a real security decision — not made here). The RUNTIME-tier crypto-asset path is untested against real output. Code marked `# QAVACH-OPEN: OQ-17`.

**OQ-16 — Scope and execution mode of `binary.static` (T-036b).** `PRD.md §6` puts firmware/embedded binary analysis out of scope; `TASK.md` schedules a shallow binary collector. Built evidence-side only (imports, dependent libraries, four constant tables, PE signing chain), no disassembly. `ARCH.md §2.3` assigns it no execution mode; it parses hostile input in-process, so callers must run it under the agent parser worker or a worker container. Needs a decision on whether it joins the agent-collector set. Code marked `# QAVACH-OPEN: OQ-16`.

**OQ-15 — No `EVIDENCE` confidence tier and no first-class "unresolved boundary" type.** `ARCH.md §2.2` lists `hsm.evidence` at confidence `EVIDENCE`, which is not in `ConfidenceTier` (§4/§6.4); T-041 uses `HEURISTIC`. The model also lacks a distinct type for an unresolved crypto boundary (HSM, undecryptable keystore): both are nameless claims today. Needs a decision before the risk layer treats them differently. Code marked `# QAVACH-OPEN: OQ-15`.

**OQ-14 — No per-target allow mechanism for the SSRF denylist.** The default
`network_policy.yaml` denies RFC 1918 space, which is exactly where an AD domain
controller (and most internal TLS endpoints) live. `network_policy.yaml`'s
header says operators opt in per target, but that mechanism does not exist yet:
today the only way to scan a private DC is to hand the collector a policy with
the private ranges removed. Needs a scoped, audited allow (per-target, not a
global relaxation) before `ad.adcs`/`tls.endpoint` are usable on an internal
estate. Same gap affects T-035.

**LOCUS-01 — Is `FileLocus.offset` a line or a column?** `ARCH.md §6.2` says
only `FileLocus(path, offset)`. CycloneDX occurrences carry both `line` and
`offset` (a column). Found while wiring T-038: the shared CBOM mapper preferred
`offset`, so a real cbomkit-lib detection came back as 10 (a column) rather than
5 (the line). Loci are part of identity, so two tools reporting one call site
differently could never corroborate each other. Line is now used (falling back
to offset); code marked `# QAVACH-OPEN: LOCUS-01`. Confirm or amend `ARCH.md`.

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
| 2026-09-19 | **T-044 done — `runtime.tracebom`, and what it can and cannot do inside the sandbox.** `runtime/tracebom.py`, `docker/tracebom/`. tracebom *executes the target's program* (operator-supplied `options["cmd"]`, target mounted read-only as cwd, no network/caps/writable root); the command reaches the container as an environment variable, never in a shell string (a test plants `; rm -rf /` and asserts it appears in no argv). **Bisected against the real tool, three findings:** (1) its native helper `safer-exec-rt` ships mode `0444`, so as uid 65534 spawn fails `EACCES` — fixed by a one-line derived image (`chmod` only) rather than weakening the sandbox; (2) **it then exits 0 with an empty BOM** — the failure is only on stderr; (3) bisecting each sandbox flag showed the *only* one it needs relaxed is **`/tmp` exec** (cap-drop, seccomp, no-new-privileges, read-only rootfs, uid 65534 all pass) — added as `SandboxConfig.tmp_exec`, default False, a named exception like `requires_network`, documented in `SECURITY.md §3`, `/work` stays `noexec`, and only this collector sets it. **Silent-failure handling (I8):** an empty BOM is a non-fatal coverage gap ("not evidence of no cryptography"), a trace-failure line on stderr is fatal even at exit 0 — while a genuinely quiet command (`true`, loads only glibc) correctly yields no claims and no error; the integration test asserts both sides. **What it delivers:** the shared libraries the process *actually loaded* (`libcrypto.so.3`, `libssl.so.3`, `_hashlib`), as **capability** claims at `DEPENDENCY` — the load was observed but "the library can do AES" is not "the process did AES" — not the `RUNTIME` tier `ARCH.md §2.2` lists. **What it cannot:** the eBPF cipher-suite tracing needs `CAP_BPF`, which `--cap-drop=ALL` removes on purpose, and TLS negotiation needs a network the sandbox denies, so **no run here produced a `cryptographic-asset` component**. The path that would normalise those (at `RUNTIME`) exists but is tested against hand-written input only — **`OQ-17`**. Deterministic: `observed_at` comes from the BOM timestamp, not the clock. Real recorded BOM in `tests/fixtures/scanner-output/tracebom/` | `packages/collectors/src/qavach_collectors/runtime/tracebom.py`, `docker/tracebom/Dockerfile`, `tests/collectors/test_tracebom.py`, `packages/sandbox/src/qavach_sandbox/runner.py`, `SECURITY.md §3` |
| 2026-09-19 | **T-037 done — Opengrep adapter.** `source_scan/opengrep.py`, `docker/opengrep/`, `config/opengrep-rules/crypto.yaml` (14 rules: C/C++, C#, PHP, Ruby, Rust; inside the `NOTE.md §3.3` 10-15 budget). Built and **run for real** — five findings-bearing languages, all 11 planted call sites found at exact lines, the benign file clean, under the sandbox's actual flags (`--network=none`, read-only rootfs, noexec tmpfs, uid 65534, no caps). **Four findings from the real tool that no spec mentioned:** (1) the release binary unpacks a bundled Python+OCaml engine into `$XDG_CACHE_HOME` and *execs it*, which the sandbox's `noexec` tmpfs forbids (`couldn't launch child (exec): Permission denied`) — fixed in the image by unpacking once at build time into the read-only rootfs, not by weakening `SECURITY.md §3`; (2) it reads rule files with the process locale, and Debian-slim's is ASCII, so an em dash in a rule comment crashed the run (`UnicodeDecodeError`) — the image sets `C.UTF-8` and a test asserts the rule file is pure ASCII; (3) **SARIF results carry `ruleId` but not the rule `metadata`**, so the adapter maps `ruleId` to the algorithm through the same `crypto.yaml` the image was built from (single source; the image gets it as a BuildKit named context), matching by suffix because Opengrep prefixes ids with the config path (`opt.qavach.rules.<id>`); (4) v1.30 has no `--metrics` flag (the OCaml CLI differs from Semgrep-Python). **Drift detection is a feature, and it fired for real:** I renamed a rule after building the image and the next run reported `finding from unknown rule` as a non-fatal error rather than guessing. Ambiguous rules were split rather than approximated (an `md5|sha1` rule would have labelled SHA-1 as MD5; Ruby `OpenSSL::Cipher.new` is only AES when the argument says so — a `metavariable-regex`, which is start-anchored, needed `.*aes`). **Sandbox bug found and fixed while doing this:** a relative `target_mount` was passed to `docker create -v` verbatim, which Docker reads as a *named volume* — silently mounting an empty one instead of the target. Now `.resolve()`d, with a regression test. Recorded real SARIF is in `tests/fixtures/scanner-output/opengrep/` (the first entry in T-024's corpus). Limits: linux/amd64 image only; rules cover API names, not usage, so false positives (tests, comments, dead code) are expected and left to the confidence tier | `packages/collectors/src/qavach_collectors/source_scan/opengrep.py`, `docker/opengrep/`, `config/opengrep-rules/crypto.yaml`, `tests/collectors/test_opengrep.py`, `packages/sandbox/src/qavach_sandbox/runner.py` |
| 2026-09-19 | **T-036b done — `binary.static`, shallow.** `packages/collectors/src/qavach_collectors/binary/`, `config/knowledge/binary_crypto.yaml`. Reads ELF (`DT_NEEDED` + undefined dynsym), PE (import/delay-import + Authenticode certificate table → PKCS#7 → chain via the existing `tls.chain`) and Mach-O (dependent dylibs only), plus four constant tables. **No disassembly or data-flow; the coverage report says so per file** (`coverage.disassembly: false`, `imports: full|partial-or-absent`, `signature: parsed|not-present|present-not-parsed|not-applicable`). Confidence: imported symbol `ARTEFACT`, library capability `DEPENDENCY` (capability, not usage — same contract as `crypto_libraries.yaml`), constant table `PATTERN`, signing-chain keys `ARTEFACT`. Decisions: (1) **constant tables are computed from their defining mathematics** (FIPS 197 S-box, FIPS 180-4 SHA-2 `K`, RFC 1321 MD5 `T`), never typed in, and a test pins the published anchor values (`428a2f98`, `c67178f2`, `d76aa478`, `637c777b…`) — a transcription typo is impossible; searched in both byte orders, 32-byte needles only; (2) SHA-256/SHA-512 tables are shared with SHA-224/384, so the reported parameter is the table's *width class* — a deliberate simplification; ChaCha/Salsa "expand 32-byte k" was **not** included because both use it and the family would be a guess; (3) **pure-Python parsers only** (pyelftools, pefile, macholib): a memory-safe parser turns a hostile header into an exception rather than corruption; every parse is wrapped so third-party failures become non-fatal notes; caps on file size/count/depth/symbols; symlinks never followed; (4) the PE certificate table's `VirtualAddress` is a *file offset*, not an RVA — a table pointing outside the file is refused and reported `present-not-parsed` (test forges one); (5) a Java `.class` shares `0xCAFEBABE` with a fat Mach-O — disambiguated by the next u32 (arch count < 45 vs class version ≥ 45); (6) every name in the YAML is re-resolved through `resolve_algorithm` on each test run. **Verification:** ELF is a real gcc build linked to libcrypto (real imports, and real compiled constant arrays in both K tables); PE is a real Windows executable found on this host (imports) with a *hand-injected* Authenticode blob (PKCS#7 built by `cryptography`, spliced into the security directory) — real parse path, synthetic signature; Mach-O is a real universal dylib for structure plus a synthesised one for the libcrypto case. **No real Authenticode-signed binary, no real Mach-O code signature, and no Mach-O symbol table was tested or is read.** **`OQ-16`:** `PRD.md §6` lists "firmware and embedded binary analysis" as out of scope while `TASK.md` schedules this shallow collector; resolved by staying strictly on the evidence side (imports, dependencies, signing) — flagged per `CLAUDE.md §8` rather than silently reconciled. Also unresolved: `ARCH.md §2.3` classifies no execution mode for it. It parses hostile binaries in-process, so it must run under the agent parser worker (`ARCH.md §3a`) or a worker container; `requires_sandbox = False` and it is **not** added to the agent's `AGENT_COLLECTOR_NAMES` (that would change a contract §2.3 fixes at four) | `packages/collectors/src/qavach_collectors/binary/`, `config/knowledge/binary_crypto.yaml`, `tests/collectors/test_binary_static.py` |
| 2026-09-19 | **T-041 done — `hsm.evidence` (`FR-150`), agent-side.** `packages/collectors/src/qavach_collectors/hsm/evidence.py`, `config/knowledge/hsm_vendors.yaml`. Six evidence kinds: vendor client library by filename, p11-kit `*.module`, SunPKCS11 `.cfg`, `security.provider.N=SunPKCS11`, OpenSSL `MODULE_PATH`, RFC 7512 `pkcs11:` URIs in app config. **Every finding is a claim with no algorithm name**, so it resolves to `UNKNOWN` (I8) — the boundary is a coverage gap for the operator to close, and nothing here asserts an algorithm, key or size because none was observed. Decisions: (1) **PINs are redacted at parse time**, before an evidence object exists (`pin-value`/`pin-source` in URIs; `pin`/`password` keys in configs are never retained) — a test greps raw payload, claims and errors for the planted secret; (2) **`system_trust` modules (`p11-kit-trust.so`) are recorded but never emitted as a boundary** — they expose the OS trust-anchor store, not an HSM, and reporting them would be an I9 violation and a false HSM on every Linux box; (3) `x-*` attributes inside a `.module` file are p11-kit directives, not slot references, and are not URI evidence; (4) a generic `library:` key in unrelated YAML must not read as SunPKCS11 — requires a shared-object value plus a `.cfg` file or slot selector; (5) hostile tree — symlinks never followed, file/depth/size caps, over-cap yields a non-fatal note and `partial=True`. Real `/usr/share/p11-kit/modules/*.module` files from this host are a test fixture. **Verification limit stated plainly:** only OpenSC, p11-kit-trust and gnome-keyring library names were confirmed against real files; the Thales/Entrust/Utimaco/AWS/Securosys/Yubico/Fortanix/SafeNet filenames are from vendor documentation and unconfirmed against a real install (the YAML header says so). **`OQ-15` (`QAVACH-OPEN`):** `ARCH.md §2.2` gives this collector an `EVIDENCE` confidence tier that `ConfidenceTier` does not have; `HEURISTIC` (lowest) is used. Separately, the model has no first-class "unresolved boundary" type, so an HSM boundary and an undecryptable keystore are both nameless claims — distinguishable today only by `detection_method="evidence"` and the raw payload | `packages/collectors/src/qavach_collectors/hsm/`, `config/knowledge/{hsm_vendors,host_known_paths}.yaml`, `tests/collectors/test_hsm_evidence.py` |
| 2026-09-19 | **T-042 done — `ssh.hostkey` network probe (`FR-160`).** `packages/collectors/src/qavach_collectors/ssh/`. Two reads, no authentication: the server's own `SSH_MSG_KEXINIT` (RFC 4253 §7.1 — sent in the clear before key exchange, so it is the server's full statement of KEX/host-key/cipher/MAC support, including PQ hybrids like `mlkem768x25519-sha256`), parsed in pure Python because it is a length-prefixed format with nothing to wrap; and the host keys via `ssh-keyscan` (the actual key only travels inside the KEX), sized with `cryptography`. **Claims record what the server *offers*, not what a given client would negotiate** — an offered `3des-cbc` is a finding about the server's configuration, not proof any session used it. Decisions: (1) resolve-then-pin via the shared SSRF policy, and `ssh-keyscan` is handed the pinned IP; (2) hostile-server hardening — banner capped in lines/bytes, packet length capped at RFC 4253 §6.1's 35000 *before* allocation, name-list lengths bounds-checked; (3) **an algorithm we cannot map is emitted under its own name so it surfaces as `UNKNOWN` (I8), never dropped** — `sntrup761x25519-sha512` is deliberately in that bucket (NTRU Prime is not a NIST-standardised scheme and the registry has no family for it); a test asserts every *mapped* name resolves in the registry, so the table cannot silently rot into all-UNKNOWN; (4) hybrids emit the ML-KEM claim only, as `tls.endpoint` does; (5) `ssh-keyscan` is run once per type so a type the local OpenSSH refuses (`-t dsa`) cannot discard the rest. Tests use a real unprivileged `sshd` plus scripted hostile servers. `sshd_config` half remains agent-side | `packages/collectors/src/qavach_collectors/ssh/`, `tests/collectors/test_ssh_hostkey.py`, `tests/collectors/_sshd_fixture.py` |
| 2026-09-19 | **T-043 done — external CBOM ingestion (`FR-180`).** `packages/collectors/src/qavach_collectors/cbom_upload.py`, `TargetType.CBOM_UPLOAD`. A vendor CBOM is a claim about their product that QAVACH did not observe, so `ATTESTED` tier, retained verbatim in `raw`; whether those assets are `MigrationAuthority.VENDOR` (invariant I9) is the authority layer's decision, not this collector's. Treated as **untrusted input per `SECURITY.md §9`**: the size cap fires on `stat()` *before* the file is read (asserted: an over-cap file yields empty `raw`, i.e. it was never loaded); a 200,000-deep nested-JSON bomb (which raises `RecursionError`, not `JSONDecodeError`) degrades rather than propagates; every one of CycloneDX 1.4/1.5/1.6/1.7 is tested. **Two design decisions worth recording**: (1) each component is normalised **on its own**, so one malformed component is reported individually (non-fatal, named by `bom-ref`) instead of `normalise_bom` raising on the first bad one and discarding a vendor's whole document — the healthy component in the test survives its broken neighbour; (2) loci get a per-upload provenance prefix (`vendor-a!src/Crypto.java`), because two vendors reporting the same relative path are two different files and identical loci would make one place appear to disagree with itself. That prefix is why `normalised_to_raw_claims` gained `locus_prefix` | `packages/collectors/src/qavach_collectors/{cbom_upload,cbom_claims}.py`, `tests/collectors/test_cbom_upload.py` |
| 2026-09-19 | **T-039 done — CBOMkit-theia for container images — and a real Phase 1 bug found by its real output.** `container.theia` takes a local image *archive* (`docker save`/OCI tarball) as its target: the sandbox has no Docker socket and no network, and this collector must never hold registry credentials or reach a registry, so acquiring the image is the orchestration layer's job. Verified live: pinned theia, sandboxed, over a real `docker save` of busybox returns a valid CycloneDX 1.6 CBOM (≈106 s — hence integration tier). **Found by real data, invisible to every hand-written fixture:** theia emits `"components": null` when it finds nothing, and `normalise_bom` (T-014, Phase 1 core) did `document.get("components", [])`, which does not replace an explicit JSON null — so it iterated `None` and crashed with `TypeError`. Fixed at the source (`or []`) with a regression test; this is the strongest argument yet for T-024's real recorded fixtures. **A second sandbox finding, and the answer to something suspected but never pinned down in T-032:** uid 65534 has no home directory, and theia creates `$HOME/.cbomkit-theia`, so with `HOME` unset it tried `//.cbomkit-theia` on the read-only root (`EROFS`). Rather than patch it per collector, every sandboxed container now gets `HOME=/tmp` (the writable tmpfs) unless overridden, and `SandboxConfig.env` carries other non-secret variables (secrets stay name-only in `secret_env`). Deployment gotcha recorded in the module: the archive is read as uid 65534 via a bind mount — Docker Desktop hid host permissions here (a `0600` file was readable), but on a plain Linux engine the file mode applies, so whatever writes the archive must make it world-readable | `packages/collectors/src/qavach_collectors/container/theia.py`, `packages/core/src/qavach_core/normalize/cbom.py`, `packages/sandbox/src/qavach_sandbox/runner.py`, `tests/collectors/test_theia.py`, `tests/core/test_cbom_normalisation.py` |
| 2026-09-19 | **T-038, T-040, T-045 done — the three "credential-blocked" tasks, unblocked by removing the need for the credential rather than working around it.** **T-038 (cbomkit-lib):** the PAT wall was real *for the prebuilt package* — `com.ibm:sonar-cryptography-plugin` is published only to GitHub Packages and is not on Maven Central (queried: 0 results; `repo1.maven.org` 404) — but both projects are Apache-2.0 (`LICENSE.txt` checked in each; `THIRD_PARTY.md` had said the plugin's licence was "not evaluated" — now it is), so `docker/cbomkit-lib/Dockerfile` builds the plugin from its pinned `1.7.0` tag inside the image build. No credential exists at build or scan time. Every input is pinned (base images by digest, both sources by full commit SHA). Verified for real, not assumed: the image built, then ran sandboxed (`--network=none`, read-only, non-root) over a Python file and reported `AES-CBC` line 9, `RSA-2048` line 6, `SHA-256` line 14 from actual AST analysis. Stated limit: Java is scanned source-only, because the sandbox has no network and never builds the target (cbomkit-lib itself calls this its least accurate mode). A locally built image is referenced by its content-addressed image ID until it is published and gets a registry digest; `digest: null` stays in `scanners.yaml` until then rather than an invented one. **T-040 (AWS):** tested against `moto`, so no credentials exist anywhere; `docs/iam/aws-readonly.json` is the exact minimum policy (`SECURITY.md §6`). The collector *simulates* KMS write actions against the credential it is handed and hard-refuses (raises, not `partial=True` — degrading would still have used it) if any is allowed; if the self-check itself is denied it proceeds with an explicit non-fatal warning rather than pretending the credential was verified. moto does not implement `simulate_principal_policy` (raises a Python `NotImplementedError` real AWS never would) and ignores `request_certificate(KeyAlgorithm=...)` (always `RSA_2048`), so both are handled honestly in the tests rather than papered over. **T-045 (AD CS):** Certipy accepts a password only as `-p` on argv or via an interactive `getpass`, which falls back to **stdin** with no TTY — so the secret travels in an env var (by *name*) and is piped to stdin; verified live that the pinned Certipy image consumes it that way and then really attempts the LDAP connection. It appears in no argv, no `docker inspect`, no recorded `ToolIdentity`, no `repr`. **Not verified against a real domain — there is none here**; the parser fixture is *derived from Certipy's source* at the pinned commit and is named as such (recording a lab-domain run is T-024). **Bugs found by their own tests:** the ELBv2 cipher parser matched the `DES` token in `DES-CBC3-SHA` and reported 3DES as single DES; my first `ad.adcs` draft bind-mounted the worker's own working directory into the container (`target_mount=Path(".")`) — fixed by letting `SandboxConfig.target_mount` be `None`, meaning nothing from the host is mounted; and the pin validator accepted any string containing `@sha256:` (now requires 64 hex chars). See OQ-12/13/14 and LOCUS-01 | `docker/cbomkit-lib/`, `docker/certipy/`, `docs/iam/`, `packages/collectors/src/qavach_collectors/{source_scan/cbomkit,cloud/aws,ad/adcs,cbom_claims}.py`, `packages/sandbox/src/qavach_sandbox/runner.py`, `tests/collectors/test_{cbomkit,aws,adcs}.py` |
| 2026-09-19 | **T-036a done — deployed-artefact collector (A-20).** `packages/collectors/src/qavach_collectors/artefact/{archive,parse,collector}.py`, agent-side. `IDEATION.md §5.1`'s premise — "in an SI-built Indian BFSI estate the customer usually does not hold the repository" — drives the whole design: everything reads what is actually deployed, assuming no repo, build system or lockfile exists anywhere. **`SECURITY.md §9`'s archive guards are satisfied by construction, not by path-checking**: nothing is ever extracted to disk, so zip-slip and symlink escape stop being a category to defend against (there is no destination path to traverse out of); entries are read in memory under three caps — total uncompressed bytes, per-entry uncompressed bytes, entry count — plus a nesting-depth bound, with the same budget applied across nested archives, since a bomb one layer down is still a bomb. Tested against a **real** decompression bomb (an 8 MiB zero-filled deflated entry) and against a many-small-entries case that a per-entry-only cap would miss. **The class-file constant-pool parser is verified against genuinely `javac`-compiled classes** (JDK 25 is present on this machine), not hand-crafted byte blobs — specifically including a source that forces `CONSTANT_Long` and `CONSTANT_Double` entries, because those occupy **two** constant-pool slots each (JVM spec §4.4.5) and are the single most common way a hand-written class parser silently desynchronises and loses everything after them. It parses correctly. **Deliberate line on depth, per `CLAUDE.md §1`**: the collector reports that a class *references* `javax.crypto.Cipher` **and** *contains* the string `"AES/CBC/PKCS5Padding"` — co-occurrence, at `PATTERN` confidence. Proving the string reaches that specific call is constant propagation, i.e. an analysis engine, which this project delegates rather than builds; claiming `AST` tier for a co-occurrence would be exactly the kind of overstated confidence the tier system exists to prevent. Maven coordinates from an embedded `pom.properties`, by contrast, are exact, so they become `DEPENDENCY`-tier claims resolved through T-034's curated `crypto_libraries.yaml` — the same capability evidence `sbom.syft` derives from a lockfile, obtained here from the deployed jar itself, which is the entire point of this collector. **Keystores "sitting beside" artefacts are intentionally not re-implemented here** — `tls.store` (T-036) already walks host paths with certfinder and the agent runs both over the same scan-spec paths; two collectors both claiming the same keystore would be the "two divergent code paths claiming to produce the same evidence" problem `ARCH.md §2.3` rules out elsewhere | `IDEATION.md §5.1`, `SECURITY.md §9`, `CLAUDE.md §1`, `packages/collectors/src/qavach_collectors/artefact/`, `tests/collectors/test_artefact_{archive,parse,collector}.py`, `tests/collectors/_java_fixture.py` |
| 2026-09-19 | **T-036 (certfinder half) done — certificate store collector.** `packages/collectors/src/qavach_collectors/tls/{store,pkcs7,chain}.py`, agent-side only (`requires_sandbox = False`; `Target.type is HOST`, `target.ref` a host filesystem path — `apps/agent`'s own scan-spec convention). **The theia half is split out to `T-036c` after a live finding, not skipped quietly**: CBOMkit-theia publishes zero binary assets on every release and ships as a container image only, which the agent cannot run — see OQ-11 above for the full three-way decision this forces and why it was raised with the user instead of improvised. **Verified against the real, checksummed tool, not a fixture**: `tests/collectors/_certfinder_fixture.py` downloads the pinned certfinder v0.7.0 linux/amd64 binary and re-verifies its SHA-256 against `config/scanners.yaml`'s own recorded value (`cb59af8f…`, which matched exactly — T-006's pin is still good) on every run, then the integration tests run it against a real `openssl`-generated certificate and a real `keytool`-generated password-protected JKS. That second case surfaced a design point worth recording: certfinder has no password flag at all, so a protected keystore comes back as a `pkcs12_encrypted_content` record with **no algorithm information whatsoever** — which is exactly right, and is mapped to a `RawClaim` carrying a locus but no name/OID, so it resolves to `UnresolvedAlgorithm` → `FindingClass.UNKNOWN` downstream (invariant I8) instead of being dropped as "nothing to report." On a real estate, "we found 40 keystores we cannot open" is the actionable sentence, not silence. **QAVACH's own additions on top** (`ARCH.md §2.2`): `pkcs7.py` covers `.p7b`/`.p7c` `SignedData` bundles, a real gap — certfinder's own `--help` lists PEM/DER/JKS/JCEKS/PKCS#12 and no PKCS#7 — and `chain.py` stitches scattered individual certificates into trust chains by subject/issuer DN. A **real bug in `chain.py` was caught by its own tests**: the first leaf-detection pass excluded every self-signed subject from the "is somebody's issuer" set, so a root CA *with children* looked like a leaf and got emitted both as its own one-link chain and again inside its leaf's chain — double-counting the same certificate in any aggregate built from the output. Fixed by only discounting a certificate naming *itself* as issuer | `ARCH.md §2.2`, `§2.3`, `NOTE.md` OQ-11, `packages/collectors/src/qavach_collectors/tls/{store,pkcs7,chain}.py`, `tests/collectors/test_tls_{store,pkcs7,chain}.py`, `tests/collectors/_certfinder_fixture.py` |
| 2026-09-19 | **T-035 done — TLS endpoint collector.** `packages/collectors/src/qavach_collectors/tls/{endpoint,ssrf,collector}.py`. `endpoint.py` shells out to the system's `openssl s_client` for the classical handshake (protocol, cipher suite, full chain via `-showcerts`) and per-candidate hybrid-group probing — see `NOTE.md §6`'s OQ-10 resolution for the full reasoning and the two dead-end stdlib limitations (no chain access, no group visibility on Python 3.12) that made this the only viable design, not merely the chosen one. `ssrf.py` implements `SECURITY.md §4`'s denylist as `config/security/network_policy.yaml` (cloud-metadata IPs, link-local/loopback, RFC 1918/4193 private space, TEST-NET/benchmarking/multicast reserved ranges, `metadata.google.internal`/`metadata.goog`, optional Kubernetes-service-CIDR auto-detection via `KUBERNETES_SERVICE_HOST`) with `resolve_and_validate` doing SECURITY.md's literal "resolve then pin" — one `getaddrinfo` call, validated, connected to by address with SNI set separately, never re-resolved. **Explicitly out of scope for this collector, left for the scan-orchestration layer that will call it** (not silently dropped): per-target rate limiting (needs state shared across worker processes, which don't exist yet), CIDR-range expansion with its `/22` cap (a multi-target orchestration concern, this collector takes one endpoint), and audit-log writes (needs the storage layer's `audit_log` table, not built). **Genuinely verified, not just unit-tested with mocks**: a real self-signed certificate (via `cryptography`, not shelled out), served by a real local `openssl s_server` test fixture (`tests/collectors/_tls_test_server.py`) configured with `-groups X25519MLKEM768:X25519`, is correctly detected by `probe_hybrid_groups` as accepting the hybrid group when offered alone, and correctly reports nothing accepted when the same fixture is reconfigured classical-only (`-groups X25519:secp256r1`) — proving the probe distinguishes real support from a coincidental default-handshake match, the actual point of owning this collector at all | `NOTE.md §6` OQ-10, `SECURITY.md §4`, `config/security/network_policy.yaml`, `packages/collectors/src/qavach_collectors/tls/{endpoint,ssrf,collector}.py`, `tests/collectors/test_tls_{ssrf,endpoint,collector}.py`, `tests/collectors/_tls_test_server.py` |
| 2026-09-19 | **T-034a done — `config/knowledge/host_known_paths.yaml`.** ARCH.md §3a / PRD.md FR-134's curated manifest: Linux/Windows OS trust-store and private-key locations, plus real, documented config/keystore conventions for Tomcat, JBoss/WildFly, WebLogic, WebSphere, nginx, Apache httpd and IIS — 45 entries. A `kind: demo_credential` tag specifically flags the two most-cited vendor-shipped-and-left-in-production examples from appserver hardening guides (WebLogic's `DemoIdentity.jks`/`DemoTrust.jks`, WebSphere's `DummyServerKeyFile.jks`/`DummyServerTrustFile.jks`) — a genuinely actionable finding class ("still using the vendor demo cert"), not just an inventory entry. `apps/agent/src/qavach_agent/known_paths.py` loads and resolves the manifest against a *real* host at scan time, not just parses it: OS entries are filtered by the running platform, appserver entries are only included when their `relative_to` environment variable (`CATALINA_BASE`, `JBOSS_HOME`, `DOMAIN_HOME`, `WL_HOME`, `WAS_HOME`) is actually set on this host — an unset variable means that platform genuinely isn't installed here, not a guessed default install root — and globs are expanded against the real filesystem, verified with actual files under `tmp_path` in tests rather than asserted against this dev machine's own (irrelevant) OS/installed appservers. Wiring this into the agent's `poll_once` alongside operator-supplied paths is left for whichever of T-036/T-036a/T-041 lands first and has a real collector to hand resolved paths to — this task's own scope was the manifest and its loader, matching how T-034's `CryptoLibraryMapping` preceded `T-033`'s actual use of it | `ARCH.md §3a`, `PRD.md` FR-134, `config/knowledge/host_known_paths.yaml`, `apps/agent/src/qavach_agent/known_paths.py`, `tests/agent/test_known_paths.py` |
| 2026-09-19 | **T-034 done — `config/knowledge/crypto_libraries.yaml`.** 45 real libraries across pypi/maven/golang/npm (`cryptography`, `bouncycastle`, `golang.org/x/crypto`, `node-forge`, etc.), each entry naming the algorithm families it genuinely implements or exposes — capability, never usage, enforced structurally (`CryptoLibraryEntry`'s fixed fields admit no `used`/`confidence` field) and by a real test (`test_schema_never_smuggles_in_usage_semantics`) that fails if one is added. **Every `provides` value is a real vendored-registry family name (`AES`, `RSASSA-PKCS1`, `ECDSA`, `EdDSA`, `ECDH`, `SHA-2`, ...), not "AES-256"/"SHA-256"-style loose spellings** — key size and hash width are parameters of a family, not separate families, in the registry's own vocabulary (`config/knowledge/cdx-crypto-registry/cryptography-defs.json`) — and every single one was checked live against the real `resolve_algorithm` (T-012) before being written, not assumed correct by inspection: `tests/collectors/test_crypto_libraries_yaml.py` re-runs that same check on every test run, so a future typo'd family name fails a test immediately instead of silently becoming an `UNKNOWN` finding (invariant I8) at scan time months later. Deliberately a first pass, per `TASK.md`'s own "start with 40 libraries" wording — coverage is uneven by design (well-documented, widely-depended-on libraries only), not a survey of every crypto package in four ecosystems | `config/knowledge/crypto_libraries.yaml`, `tests/collectors/test_crypto_libraries_yaml.py` |
| 2026-09-19 | **T-033 done — Syft adapter.** `packages/collectors/src/qavach_collectors/sbom/syft.py` runs syft (`ENTRYPOINT` is the absolute path `/syft`, invoked directly — no `sh -c` needed at all, since `-o cyclonedx-json -q` writes clean JSON straight to stdout) and maps each detected package's purl against `crypto_libraries.CryptoLibraryMapping` (`sbom/crypto_libraries.py`) to emit one `RawClaim` per capability at `ConfidenceTier.DEPENDENCY` — "you depend on library X which provides Y" is real evidence, weaker than an AST/runtime observation of Y being called, matching `ARCH.md §2.2`'s own tier assignment for this collector. Real purl parsing via `packageurl-python` (the reference implementation), not hand-rolled. **The real 40-library `crypto_libraries.yaml` curation is `T-034`, deliberately not built here** — tests use a 3-entry hand-written fixture mapping, the same "the real data file is a separate task" pattern this repo already established for CBOM fixtures (`NOTE.md`'s T-014 entry). **The T-032 entrypoint fix paid off immediately here**: the real Docker integration test (a `requirements.txt` pinning `cryptography`+`pyjwt`, verified live to be reliably catalogued by syft — a bare `package.json` with no lockfile was tried first and produces zero components, since syft needs a lockfile or a simple-enough manifest format to enumerate concrete versions from) passed on the first attempt, no debugging saga required, because `command[0]` was correctly sent as `--entrypoint` from the start | `ARCH.md §2.2`, `packages/collectors/src/qavach_collectors/sbom/{syft,crypto_libraries}.py`, `tests/collectors/test_syft.py` |
| 2026-09-19 | **T-032 done — cdxgen adapter, and a real bug found in already-committed T-031 sandbox infrastructure.** `packages/collectors/src/qavach_collectors/source_scan/cdxgen.py` invokes cdxgen inside the sandbox (`SECURITY.md §3`) and turns its CycloneDX output into `RawClaim`s via the T-012/T-014 normalise layer — one `RawClaim` per `evidence.occurrences[]` entry, falling back to a repo-root locus when cdxgen supplies none. Build resolution (`--install-deps`, which **defaults true upstream**, the opposite of what `SECURITY.md §3.1` requires) is forced to `--no-install-deps` unless `RunContext.allow_build_resolution` is set, which also flips `requires_network`. **The real Docker integration test failed for hours against what turned out to be three separate real findings, not one**, each verified live rather than guessed: (1) cdxgen hardcodes `/tmp/cdxgen-temp` for scratch space regardless of `TMPDIR`, so `--read-only` alone breaks it with `EROFS`; fixed by giving `packages/sandbox` a second, equally-`noexec,nosuid,nodev` tmpfs at `/tmp` (`SandboxConfig.tmp_tmpfs_size`, default 512m) — a real, general capability gap, not a cdxgen-only patch, likely to recur for other real scanners. (2) The `cbom` release-binary alias (distinct from the base `cdxgen` entrypoint, confirmed to exist inside the pinned image via `--entrypoint cbom`) appeared to ignore `-o` entirely, matching its README's own warning that its CLI contract is narrower than documented; switched the adapter to the base `cdxgen --include-crypto` invocation instead, which the tool's own README recommends for anything beyond bare defaults and which was confirmed live to honour `-o` correctly. (3) **The actual root cause, found only after (1) and (2) turned out to be red herrings**: `packages/sandbox/src/qavach_sandbox/runner.py`'s `build_sandbox_args` never overrode `--entrypoint`, so a `SandboxConfig.command=("sh","-c","...")` was silently *appended* to whatever `ENTRYPOINT` the image itself bakes in rather than replacing it — the pinned cdxgen image has `ENTRYPOINT ["cdxgen"]`, so the actual process every affected collector was launching was the nonsensical `cdxgen sh -c "<script>"`, with cdxgen receiving "sh"/"-c"/the whole script string as its own garbled positional CLI arguments. This is why cdxgen kept writing a hardcoded relative `bom.json` against whatever confused CWD it ended up computing (`EROFS`/`EACCES` depending on exactly where that landed) no matter what absolute `-o` path was given, and why it was maddeningly inconsistent across `docker run`/`create+start`/attached/detached variants — none of those variables were the actual cause; every single manual bisection command that "worked" during debugging had, without my noticing at the time, an explicit `--entrypoint` override (`sh`, or `cbom`) that the *adapter's own* generated args lacked. **This bug was invisible in T-031's own test suite** because its test fixture, `busybox`, has no conflicting `ENTRYPOINT` to collide with — a `("sh","-c",...)` command sent to a shell-less-entrypoint image happened to work by coincidence, not because the mechanism was correct. Fixed by making `build_sandbox_args` always send `command[0]` as `--entrypoint` and only `command[1:]` as the trailing CMD, with a regression test (`test_command_first_element_becomes_the_entrypoint`) added specifically so this cannot silently regress again. **Lesson for future collector work, recorded here rather than left to be rediscovered**: when a sandboxed collector run misbehaves in a way that doesn't match manual `docker` CLI testing, diff the *exact* generated `docker create` argument list (`build_sandbox_args`) against whatever manual command "works," rather than assuming the difference must be in something more exotic (network, cgroup limits, seccomp, TTY, environment variables — all bisected and ruled out here before the actual cause was found) | `SECURITY.md §3`, `packages/sandbox/src/qavach_sandbox/runner.py`, `tests/sandbox/test_runner.py`, `packages/collectors/src/qavach_collectors/source_scan/cdxgen.py`, `tests/collectors/test_cdxgen.py` |
| 2026-09-18 | **T-031b done — resource-limited parsing worker.** `apps/agent/src/qavach_agent/parser_worker.py` implements `ARCH.md §3a`'s "Containment for hostile input, without a container": every fetched file is parsed by re-execing the agent's *own* process (`sys.executable`, frozen-binary-aware — the agent has no `python3` on the host to shell out to) with a hidden `_parse-worker` subcommand, under real `resource.setrlimit` (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`) plus a supervisor-level wall-clock timeout, never inline in the agent's main process. **Genuinely verified against the kernel, not just constructed and inspected**: real fixture parse functions (`tests/agent/_fixture_parsers.py`) that busy-loop, sleep, over-allocate, or raise outright each produced the *specific* containment failure they should — a CPU-bound infinite loop is killed by `RLIMIT_CPU` (SIGXCPU) well before the wall-clock timeout fires, while a `time.sleep`-blocked worker (no CPU burned) is caught by the wall-clock timeout instead, proving the two mechanisms are independently wired rather than one silently doing both jobs; a 2 GiB allocation is refused by a 64 MiB `RLIMIT_AS` inside the child rather than actually consuming host memory. All of these come back as `WorkerResult(ok=False, ...)`, never an escaped exception. **Privilege-dropping (step 3, "drop the worker to the most restricted account reachable") is implemented — `WorkerLimits.drop_to_uid`/`drop_to_gid`, `os.setgroups([])` + `setgid` + `setuid` in the child's `preexec_fn` — but not exercised end-to-end**: this development environment has no root/`CAP_SETUID` (`os.getuid()` is a plain `1000`), so nobody has watched a real uid switch happen. What *is* verified live: attempting the drop without sufficient privilege fails as `OSError`/`subprocess.SubprocessError` inside `preexec_fn`, and the supervisor correctly turns that into `WorkerResult(ok=False)` rather than letting it escape as an uncaught exception — the one piece of this path testable without root. Revisit under a real deployment or a root-capable CI runner before treating this as fully proven | `ARCH.md §3a`, `apps/agent/src/qavach_agent/parser_worker.py`, `apps/agent/src/qavach_agent/__main__.py` (hidden `_parse-worker` subcommand — `argparse.SUPPRESS` on a subparser's own `help=` was tried first and confirmed live to print the literal string `"==SUPPRESS=="` instead of hiding the line; fixed by omitting `help=` entirely and overriding the group's `metavar` instead), `tests/agent/test_parser_worker.py`, `tests/agent/_fixture_parsers.py` |
| 2026-09-18 | **T-031a done — agent runtime.** `apps/agent/src/qavach_agent/` implements `ARCH.md §3a`'s client-side mechanics: `spec.py` (the typed scan-spec protocol — `parse_scan_spec` rejects any field outside `{paths, collectors}` and any collector name outside the closed, cited vocabulary `AGENT_COLLECTOR_NAMES`, so a compromised or buggy backend cannot get the agent to run anything beyond its own shipped modules against a path); `enrollment.py` (the agent generates its own P-256 keypair and CSR locally — the private key never crosses the wire — and exchanges the CSR plus a single-use token for a signed client certificate over server-authenticated TLS); `transport.py` (`AgentTransport`, a context manager materialising the mTLS client cert/key/pinned-CA to a private `0600` temp dir on enter and shredding it on exit); `runtime.py` (`poll_once`/`run_forever` — GET spec, run whichever named collectors are actually registered in this build, skip the rest without failing the cycle, POST results; flagged `# QAVACH-OPEN: AGENT-01` since the results wire-shape isn't pinned down by `ARCH.md`/`PRD.md` anywhere yet — revisit at `T-073a`); `__main__.py` (a real `enroll`/`run` CLI, since `ARCH.md §3a` explicitly requires "packaged as a single-file bundle," not just importable library code). **`T-073a`'s real backend (Phase 6) doesn't exist**, so every test in `tests/agent/` runs against a genuine local mTLS server built for the purpose (`tests/agent/_pki.py` — a real throwaway CA signing real server/client certificates; `tests/agent/_mock_backend.py` — a real `ThreadingHTTPServer` wrapped in `ssl.SSLContext`, implementing the three `ARCH.md §12` agent endpoints), not mocked `httpx` calls — this proves actual TLS handshakes, actual CSR signing, actual peer-certificate checks, including two genuine negative cases (wrong enrollment token → HTTP 403; backend certificate signed by a CA the agent isn't pinned to → the client's own TLS verification fails before any request completes). **Real, live-verified fix along the way**: `httpx`'s `verify=<path-string>` is deprecated in favour of an explicit `ssl.SSLContext` — caught as a live `DeprecationWarning` during the first test run, not from documentation, and fixed in both `enrollment.py` and `transport.py` before it could later break on an `httpx` version bump. **PyInstaller packaging verified for real, not assumed**: built an actual single-file ELF binary (`pyinstaller --onefile`) and ran its `enroll` subcommand — with `PATH`/`HOME` stripped to bare minimum and no project venv on `PATH` — against the real mock backend; it completed a genuine enrollment round-trip and wrote a real credential file. The per-OS CI build matrix `ARCH.md`'s task line calls for (PyInstaller does not cross-compile) is **not done** — this machine only proves the Linux leg — and is split out as `T-031c` rather than silently left implied-done by T-031a's checkbox | `ARCH.md §3a`, `ARCH.md §12`, `apps/agent/src/qavach_agent/`, `tests/agent/` |
| 2026-09-18 | **T-031 done — sandbox runner.** `packages/sandbox/src/qavach_sandbox/runner.py` builds the exact `docker create` flags `SECURITY.md §3` specifies (`--network=none` unless `requires_network`, `--read-only`, tmpfs `/work` `noexec,nosuid,nodev`, `--user 65534:65534`, `--cap-drop=ALL`, `--security-opt=no-new-privileges` + a real vendored seccomp profile, cgroup limits, orchestrator-side timeout) and, since a bypass flag would defeat the whole point, there is no code path that can build a container invocation skipping any of them. **Real, live-verified correction to the documented output-retrieval mechanism**: `SECURITY.md §3`/`ARCH.md §3` said output "crosses the boundary as one JSON file on the tmpfs mount," retrieved after the container exits. Tested directly against this machine's Docker: a `--tmpfs` mount is torn down the instant its container *stops*, not when it is `rm`'d, so `docker cp <container>:/work/result.json -` 404s against an already-exited container even with the container object still present and unremoved — the literal mechanism as written cannot work with an ephemeral per-job container. Fixed by retrieving the container's **stdout** via `docker logs` instead (verified live to survive exit reliably, with correctly separated stdout/stderr streams, because the log driver captures the stream continuously while the process runs rather than reading it back from a torn-down filesystem afterward); `/work` remains real scratch space for anything a scanner needs to write mid-run, just not the retrieval channel — a collector whose scanner insists on a file needs a command ending `&& cat <file>`. Both spec docs corrected to match. **Second finding, environment-specific but worth recording**: this machine's Docker Desktop refuses to bind-mount bare `/tmp` ("mounts denied" — Docker Desktop only shares paths configured under Resources → File Sharing, home/project directories by default); tests mount a repo-relative scratch directory instead, which is also the more representative choice since real scan targets will live under a QAVACH-controlled directory, never `/tmp`. Verified end-to-end against the live daemon, not just asserted on argument lists: network-none actually blocks egress, read-only rootfs actually blocks a write outside `/work`, the container actually runs as uid 65534, a hung container is actually killed at the timeout (`SECURITY.md §3`'s "orchestrator, not the container" requirement), a crashed scanner comes back as empty output with a real exit code, never an exception | `SECURITY.md §3`, `ARCH.md §3`, `config/seccomp/scanner.json` (vendored from `moby/profiles`, the primary source Docker's own default profile now lives in — the old `moby/moby` path is gone, superseded by this dedicated repo), `packages/sandbox/src/qavach_sandbox/runner.py`, `tests/sandbox/test_runner.py` |
| 2026-09-18 | **T-030 done — Phase 3 begins.** `packages/collectors/src/qavach_collectors/base.py` implements ARCH.md §2.1's `Collector` protocol as a `typing.Protocol` (structural, no inheritance required — proven by a real `_FakeCollector` test, not just an abstract shape nobody implements). **Real cross-package gap caught while adding the first non-core package**: `qavach_core` had no PEP 561 `py.typed` marker, so `mypy` treated it as untyped the moment anything *outside* `packages/core` imported it — every careful type annotation from Phase 0-2 would have silently stopped being checked the instant a second package existed. Added `py.typed` to every package/app now, not just core, and extended `make lint`'s mypy coverage to `packages/collectors` (non-strict, since real I/O-heavy collector code will need `Any` from untyped third-party libraries more often than core's pure functions do) | `packages/*/src/*/py.typed`, `packages/collectors/src/qavach_collectors/base.py`, `Makefile` |
| 2026-09-18 | **T-022, T-023 done — Phase 2's completable subset finished.** `reconcile/merge.py` implements per-attribute precedence for `mode`/`padding` — the two usage qualifiers left out of the identity hash (A-5) — using a **separate ranking from `ConfidenceTier`'s own ordering**: usage-observing tiers (RUNTIME, AST) outrank ATTESTED for these two attributes specifically, the exact reversal ARCH.md §6.4 calls "the single most likely silent-failure mode in this layer" (an ATTESTED cloud KMS API, tier 80, must not outrank an AST claim, tier 50, for padding it never observed). `concluded_from` (the asset's overall provenance tier) correctly uses the *other*, plain ordering — the two are tested separately so a future refactor can't quietly collapse them into one. Dispute detection groups by `(identity, locus)`: same-locus disagreement is a dispute (ARCH.md §6.3's AES-256-GCM/AES-128-CBC-at-the-same-locus example); different-locus disagreement is multi-usage, not a dispute; silence never competes (A-5). **T-024 and T-025 remain correctly blocked** — T-024 needs real recorded scanner output (T-030, Phase 3, not built) and T-025 needs the HSM evidence collector (T-041, Phase 3) — neither was faked to force "Phase 2 complete"; TASK.md's own rule against starting a task with open blockers was followed, not worked around | `packages/core/src/qavach_core/reconcile/merge.py`, `tests/core/test_merge.py` |
| 2026-09-18 | **T-020, T-021 done.** `reconcile/identity.py`'s `IdentityClaim` is deliberately a different type from T-014's `NormalisedClaim` — checked the vendored 1.7 schema directly and found `certificateProperties` has **no first-class SPKI or is-CA field** at all (only a generic `fingerprint` hash object and an optional `certificateExtensions` array that may carry `basicConstraints`). Extracting `is_ca`/`spki_sha256` needs real X.509 parsing (collector-layer I/O), so `asset_identity()` takes them as already-decided inputs rather than trying to derive them from a bare CDX document itself. `model/locus.py` gained `locus_to_dict`/`locus_from_dict`/`locus_type_name` for ARCH.md §11's `(locus_type, locus_json)` storage columns — round-trip-tested for all 9 Locus variants including `RuntimeLocus`'s datetime field | `packages/core/src/qavach_core/reconcile/identity.py`, `packages/core/src/qavach_core/model/locus.py` |
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
