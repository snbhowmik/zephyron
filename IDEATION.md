# IDEATION.md — QAVACH

**What we are building, why it is the right thing to build, and what evidence
says so.** This document sits *above* `PRD.md` and `ARCH.md`. They say what and
how. This says **why**, and why not the obvious alternatives.

Read this second, after `CLAUDE.md`, before `PRD.md`.

> Rule for this file: every claim is either cited to a primary source, derived
> from observed evidence, or explicitly marked as judgement. If you cannot tell
> which one a sentence is, that is a defect — fix it.

---

## 1. The thesis, in one page

Every PQC guide opens with "inventory your cryptography first." A dozen products
now do that. **Discovery has become commodity. Decision has not.**

The failure mode is not that organisations cannot find their cryptography. It is
that when they do, they get tens of thousands of undifferentiated findings, most
of which they cannot act on, with no basis for choosing an order. A migration
lead with 20,000 findings and a 2028 deadline is no better off than one with
none.

QAVACH's contribution is the four layers that come *after* discovery:

| | Capability | One-line test of whether it works |
|---|---|---|
| **1** | **Reconcile** N inventories — ours, the vendor's, the customer's other tools' — into one asset identity with provenance and confidence | The same key found by three tools is one row, not three |
| **2** | **Contain** — bind every asset to carrier → component → purpose → data → owner → **who can change it** | The UI can answer "what breaks if this rotates, and who do I call" |
| **3** | **Decide** — Mosca per function class, against a dated regulatory ladder, inside CARAF, with the arithmetic exposed | Moving `Z` visibly re-sorts the list, and the reason is readable |
| **4** | **Sequence** — dependency-ordered waves, cycles resolved by hybrid bridge, infeasibility surfaced | One item is provably blocked by another and the UI says why |

Discovery is layer 0. We do it because a demo needs it and because some
collectors genuinely did not exist — not because it is the differentiator.

**The sentence to lead with:** *QAVACH turns cryptographic inventories into a
dated, dependency-ordered migration plan you can defend to a steering committee
and hand to a regulator.*

---

## 2. Evidence: the competitor's own dashboard proves the thesis

We have screen captures of a shipping competitor's product (see `COMPETITOR.md`
for provenance). This is the strongest evidence in the project, because it is not
our argument — it is their product, on their data, in their marketing material.

### 2.1 The headline number

Their dashboard, on a real 21,224-asset scan:

```
Quantum Risk Distribution        Asset Type Distribution
  CRITICAL      13                 Certificates   10,628
  HIGH      10,788                 Private Keys      226
  MEDIUM         0                 Public Keys        47
  LOW            2                 Symmetric           2
  NONE      10,421                 Algorithms     10,317
                                   Signatures          4
```

**10,788 findings rated HIGH.** Half the estate, in one bucket, with no ordering
inside it. This is the 40,000-findings problem rendered as a donut chart. It is
the exact situation `PRD.md §1` describes, produced by a product built to solve
it. Put this screenshot on a slide next to QAVACH's wave view.

Note also `MEDIUM 0` — the middle of their scale is empty. A risk scale with an
unused middle band is a classification scheme that is really binary.

### 2.2 Six concrete data-quality failures, and what each one demands of us

These are not cheap shots. Each one is a requirement we must satisfy, and each
one is visible in a single screenshot.

**(a) Unresolved OIDs — including the PQC ones.**
Their "Certificate Key Algorithms" panel lists, as if they were algorithm names:
`2.16.840.1.101.3.4.3.17`, `2.16.840.1.101.3.4.3.20`, `2.16.840.1.101.3.4.4.1`,
`2.16.840.1.101.3.4.4.2`, `2.16.840.1.101.3.4.3.26`, `2.16.840.1.101.3.4.3.30`,
`1.2.643.2.2.19`, `1.2.643.7.1.1.1`, `1.2.3.4`, `null`, `Unknown`.

Those NIST arcs are the ML-DSA / SLH-DSA signature arc
(`2.16.840.1.101.3.4.3.x`) and the ML-KEM arc (`2.16.840.1.101.3.4.4.x`); the
`1.2.643.x` values are GOST. **Verify each mapping against the registry before
citing it publicly** — but the shape of the finding does not depend on the exact
mapping: a post-quantum migration tool is displaying post-quantum algorithms as
raw dotted-decimal strings.

→ **Requirement.** OID canonicalisation is not a nice-to-have, it is correctness.
`ARCH.md §5.2` already adopts the CycloneDX Cryptography Registry as the naming
authority. Add a golden test: `2.16.840.1.101.3.4.3.17` must render as a named
ML-DSA parameter set, and a certificate whose signature algorithm is a PQC OID
must classify as `QUANTUM_SAFE`, never as `Unknown`. A tool that cannot name the
thing it recommends migrating *to* is not credible.

**(b) Key size is being modelled as an integer, and it is not one.**
Their key-size distribution contains `0-bit` (34), `unknown-bit` (5), `2450-bit`
(1), `281-bit` (1), `192-bit`, `768-bit`, `512-bit`.

There is no 2450-bit or 281-bit RSA key. Those are parse artefacts. `0-bit` is
almost certainly Ed25519 and PQC certificates being forced into an integer field
that does not apply to them.

→ **Requirement.** Never store a scalar `key_size`. Store
`parameterSetIdentifier` (CycloneDX) plus, where meaningful, a modulus length.
Ed25519 has no bit-length in the RSA sense; ML-DSA-65 has a parameter set, not a
key size. Add a validator that rejects implausible modulus values into a
**data-quality queue** rather than charting them.

**(c) Unknown is being rendered as safe. This is the most serious one.**
Their key panel: **188 of 275 keys are `unknown-bit`** (68%). The risk split
beside it reads `HIGH 139 / NONE 134 / LOW 2`. In the signature panel, an
algorithm literally labelled `unknown` carries a green bar. In the inventory,
`SHA reference in sublime_text…` is rated **NONE**, and `SM reference…` is rated
**NONE** — but SM2 is elliptic-curve and Shor-breakable.

You cannot know a key is safe if you do not know its size. Defaulting unknown to
green is how a tool tells a CISO their estate is fine when it has simply failed
to parse it.

→ **Requirement.** This is Invariant I1's gap. Four finding classes are not
enough. Add a fifth: **`UNKNOWN`** — rendered distinctly (grey/hatched, never
green), counted separately in every aggregate, and reported as a *coverage*
failure rather than a risk verdict. A dashboard must be able to say "we could not
classify 12% of your estate" as a headline, because that number is itself the
most actionable thing on the screen. **Never let an unclassified asset
contribute to a "safe" count.**

**(d) They are inventorying assets the operator cannot migrate.**
Their asset-detail panel shows `Sectigo RSA Code Signing CA`, rated **HIGH**,
found at two `file://` locations — both inside downloaded installers
(`Git-2.32.0-64-bit.exe`, `sublime_text_build_4107_x64_setup.exe`). Their
relationship graph walks the chain up through USERTrust to AAA Certificate
Services.

Those are public trust anchors embedded in third-party software. The operator
cannot migrate Sectigo's CA. Ranking it HIGH alongside their own keys is what
inflates 10,788 into an unusable number.

→ **Requirement, and this is a genuinely new concept for us.** See §4.1 below —
**Migration Authority**.

**(e) Alert noise from trust-store fixtures.**
Their alerts list is entirely "Certificate expired," all CRITICAL, including
certificates that expired in **1996** and **1998**, and one named
`Test OCSP response signer`. These are Windows trust-store residue and test
fixtures, not operational certificates.

→ **Requirement.** An alert needs a *relevance* gate, not just a truth gate. An
expired root in a shipped trust store is a fact, not an incident. Gate alerting
on Migration Authority = `self` and on the asset being in an operational locus.

**(f) Compliance headline numbers without denominators.**
Their compliance page: `TOTAL ASSETS 21224`, `ACTIVE POLICIES 3`,
`VIOLATIONS 25112`. More violations than assets — true, because an asset can
violate several policies, but incoherent as a headline. And `CNSA 2.0: Assessed
21224, Compliant 0, Violations 21224` — a policy that flags 100% of the estate
carries no information.

→ **Requirement.** Compliance results are always `(asset × policy)` with the
denominator shown. A policy whose violation rate is ~100% must be flagged as a
**scoping problem**, not rendered as a finding. CNSA 2.0 applies to US National
Security Systems; applying it wholesale to a commercial Indian estate is a
category error, and our policy templates must carry an applicability scope.

### 2.3 What they do well, and we should not pretend otherwise

- **The certificate relationship graph is good** — typed edges (`issuedBy`,
  `signedBy`, `containedIn`), clean layout, list/graph toggle.
- **The certificate expiry timeline is a genuinely useful panel**
  (Expired 90 / <7d / <30d / <90d / <1y 2,929 / >1y 7,582). We should have it.
- **Per-asset violation reasoning** ("NIST quantum level 0, below required level
  3") is real explainability, not a badge.
- **Sensor management** — registration, online/offline, per-scanner run history
  with asset counts — is a mature operational surface.
- **The binary scan is credible.** Real algorithm references pulled from real
  installers, with the code-signing chain reconstructed.

**And the sharpest observation: they have the chain and do not schedule it.**
Their graph shows `Sublime HQ Pty Ltd → Sectigo RSA Code Signing CA → USERTrust
RSA CA → AAA Certificate Services`. That is a migration ordering constraint,
drawn on screen, and used only for browsing. QAVACH takes the identical graph and
emits waves. Same data, one more layer, and it is the layer nobody has.

---

## 3. Regulatory ground truth

This is the spine of the risk engine. `Z` is not a forecast we make; it is a
deadline we read. Every value below must exist in `config/policy/*.yaml` with a
citation.

### 3.1 India DST/NQM — six dates, not three

**Correction to earlier drafts.** `README.md` and `PRD.md §1.1` currently cite
2027/2028/2029. That is only the CII track. The roadmap defines three milestones
across **two tracks**:

| Milestone | CII | Enterprise |
|---|---|---|
| M1 — Build Foundations (inventory, governance, pilots) | **2027** | **2028** |
| M2 — Migrate high-priority systems | **2028** | **2030** |
| M3 — Full PQC adoption | **2029** | **2033** |

Source: *Quantum-Safe Ecosystem in India: Roadmap to Quantum Resiliency*, DST,
National Quantum Mission, May 2026 — §7 and §9. Annexure B restates it
operationally: critical applications from January 2027 to December 2029,
non-critical from January 2029 to December 2033.

**CII sectors are enumerated:** government, strategic, defence, power, telecom,
transport, and BFSI. Track selection is therefore a *stated* property of the
organisation, not an inference.

→ `Z_effective = min(Z_scenario, deadline(track, milestone(asset)))`. The
milestone depends on whether the asset is "high-priority", which is a business
context input. This makes the ladder richer than a single date and is a better
scheduling target than any other national roadmap offers.

### 3.2 Other anchors, with their legal force — they differ, and that matters

| Anchor | Force | What it binds |
|---|---|---|
| **SEBI CSCRF** | **Mandatory, live, deadline passed** | Securities REs must inventory keys, certificates and algorithms, describe which application uses what cryptography and for what purpose, and prioritise PQC migration by risk and criticality. Also: key management must stay within India. |
| **CERT-In Technical Guidelines v2.0** (09-07-2025) | Directive for govt/PSU/essential services | CBOM/QBOM required in procurement; **SPDX or CycloneDX** accepted; VEX required on vulnerability discovery |
| **DST/NQM roadmap** | **Advisory to regulators, not directly binding** | Explicitly: "not itself a regulatory mandate… enables regulators to define sector-specific timelines." Sets the national schedule and the L1–L4 assurance vocabulary. |
| **NIST IR 8547** | Foreign, draft | Deprecate 2030 / disallow 2035 |
| **CNSA 2.0** | US NSS only | **Applicability-scoped.** See §2.2(f). |

**Design consequence.** A framework is a **profile object**, not a report
template. It sets `Z`, the algorithm allowlist, the hybrid stance, the permitted
decision set, the evidence format, and an **applicability scope**. An
organisation can have several active simultaneously — an RE is *bound* by SEBI
and *scheduled* by NQM — and QAVACH must detect where they conflict.

### 3.3 Two findings that change the product, not just the citations

**CERT-In mandates two-sided CBOM reconciliation.** §8.4.1.8: *"Consumer
organizations must create an internal CBOM/QBOM aligned with the supplier's
data."* Suppliers must provide a complete CBOM; consumers must reconcile it
against what is deployed.

This closes the standing objection that our reconciliation layer is a
self-inflicted problem created by running five overlapping scanners. It is not.
It is a mandated workflow, and the inputs are ones the customer did not choose.
`NOTE.md` should record this as the resolution.

**QAVACH's product category is named for future compliance.** The roadmap
directs that India's list of cryptography-dependent product categories add
*"automated cryptographic discovery and inventory solutions"* and mobile phones,
and that inclusion "constitutes a future compliance requirement for vendors."

So QAVACH would itself be certifiable under the L1–L4 ladder — L3 (Enterprise
Infrastructure Security) for BFSI/telecom use, with crypto-agility validation,
CI/CD integration testing, CERT-In-empanelled VA/PT, and supply-chain
verification. Most of that is already in `SECURITY.md`. **Design to L3 now**; it
is a positioning asset no competitor is building toward.

---

## 4. Concepts this ideation adds

These are new. They are not yet in `ARCH.md`; §9 lists exactly where each lands.

### 4.1 Migration Authority — the field that fixes the 10,788 problem

Every asset carries **who can actually change it**:

| Value | Meaning | Treatment |
|---|---|---|
| `self` | Operator owns the code, config or key | A migration item. Enters the roadmap. |
| `vendor` | OEM/SaaS firmware or product | A **dependency**, tracked with a vendor-engagement action and an unbounded ETA |
| `external_trust_anchor` | Public CA, OS trust store, third-party installer residue | **Not a migration item.** Inventory it, never rank it, never alert on it |
| `regulator_gated` | NPCI, UIDAI, CCA, sector regulator specifies the crypto | **Blocked by an external party.** Surfaced as a named blocker |
| `unknown` | Not yet determined | Triage queue |

This is derived, not asserted: a certificate whose issuer is a public root and
whose only locus is inside a third-party binary is `external_trust_anchor`; a key
in the operator's own keystore is `self`.

**Why it matters more than it looks.** It converts an unusable "10,788 HIGH" into
"you own 1,240 of these. 8,900 belong to Microsoft, Sectigo and your OEMs. 648
are gated on NPCI publishing a PQC specification." That is the single most
valuable sentence the product can produce, and it is one field plus a derivation
rule.

It also gives us the honest, defensible answer for the large Indian estate: a
bank cannot unilaterally migrate its UPI stack, its Aadhaar integration, or its
India PKI certificates, because NPCI, UIDAI and the CCA specify that
cryptography. Saying so is more useful than pretending otherwise.

### 4.2 `X_conf` and `X_integ` — and the national roadmap names both

Invariant I2 is right that HNDL is confidentiality-only, but a single `X` cannot
carry both jobs. Split it:

- **`X_conf`** — how long the data must stay confidential. HNDL applies. Late
  migration is **unrecoverable**; harvested ciphertext cannot be un-harvested.
- **`X_integ`** — how long a signature must remain unforgeable. HNDL does not
  apply, but **forward re-signing is a valid mitigation** — you can re-timestamp
  an archive before the deadline.

Aggregation over derived key material is `max()` over consumers, propagating
**upward** along the derivation chain only. A root secret inherits the maximum of
everything beneath it; a child inherits nothing from its parent. For TLS 1.3:
handshake traffic keys are `X_conf ≈ 0`, but the resumption master secret is
nonzero wherever tickets are persisted.

The DST report names both attack classes explicitly — "Harvest Now, Decrypt
Later (HNDL)" **and** "Trust Now, Forge Later (TNFL)". Cite it. It also closes
the archival-signature gap: RFC 3161 timestamps, audit logs and SCADA command
logs get `X_integ` from retention policy, not the ephemeral-artefact exemption.

**Watch the directional asymmetry — it will get implemented backwards.** Shelf
life aggregates with `max()` upward. Shared-resource deadlines (one HSM or root
CA serving many systems) aggregate with `min()` downward.

### 4.3 Attribute-scoped confidence precedence

Invariant I4 is sound but has a silent-failure mode. If the identity hash
includes `mode`/`padding`, then an attested KMS claim (silent on call-time
padding) and an AST claim that correctly observes PKCS#1 v1.5 **hash to different
identities and never collide** — so `disputed` never fires. You get two parallel
assets, one looking safe.

**Structural fix — split identity in two:**

| Field class | Role |
|---|---|
| **Core (hashed)** | algorithm family, parameter set, curve, OID — intrinsic to the *key* |
| **Usage qualifiers (attributes on occurrences)** | mode, padding, digest, function, protocol context — properties of a *call* |

Then precedence is per attribute class:

| Attribute class | Dominant claim type |
|---|---|
| key spec, curve, parameter set, lifecycle | attested (KMS/HSM/cert parse) > usage-observing > declared |
| mode, padding, digest, function | **usage-observing > attested** > declared |
| locus | union — never resolved |

**New invariant: silence is not a claim.** A source that does not observe an
attribute contributes nothing to it and cannot outrank one that does. That single
sentence is the actual bug.

And distinguish **multi-usage from dispute**: the same RSA key used with OAEP in
one call site and PKCS#1 v1.5 in another is two true facts. Dispute fires only
when two sources disagree *about the same occurrence*. The asset verdict is
computed over the **worst** member of the usage set.

### 4.4 A seventh DAG edge type, and two cycle variants

Resolves **OQ-01**.

**`REGULATORY_GATE`** is structurally distinct from library-availability: it
gates the *end* of a migration unit, allows parallel submission, and fails via
rework-and-requeue with no vendor ETA. Model it by **splitting the node**: every
migration unit becomes `start` → `complete`. Ordinary precedence edges land on
`start`; regulatory gates land on `complete`. A wave containing an unbounded gate
is not a dated wave — mark it `schedule_risk: unbounded` and do not render an ETA.

Given India's TEC/STQC/BIS L1–L4 certification framework, this edge is real for
any CII operator.

**Certificate-pinning cycles cannot use the generic hybrid bridge** — static
pin-sets cannot run dual-stack. The variant is: publish a **pin superset** →
soak → rotate → soak → prune. The gate between phases must be an
**adoption-telemetry threshold, not a time threshold**; pinning failures are
silent and total, and a calendar gate will brick the long tail. Model app-store
update lag explicitly for embedded pinning.

**Key escrow is not a precedence edge — it is a retention constraint.** Model
`destroy_prohibited_until` plus a legal-hold flag that hard-blocks any destroy
action. And add the edge most teams miss: **decrypt-capability retention** — you
cannot remove the *classical implementation* from the codebase while escrowed
ciphertext exists under hold. Teams delete the old code path years before the old
keys. That is silent data loss.

### 4.5 Shared-resource contention

One HSM or one root CA serving systems with different deadlines inherits
`min()` of dependent deadlines. If that is earlier than the earliest feasible
completion given `Y`, emit `SCHEDULE_INFEASIBLE` naming the contended resource.

**Scope honestly:** capacity contention (one firmware window, forty systems) is
a resource-constrained project scheduling problem, not a DAG problem. **Detect
and name infeasibility; do not attempt to solve the scheduling problem in v1.**

---

## 5. Build versus integrate — the line has moved

`CLAUDE.md §2` says "QAVACH does not write scanners." That rule was drawn too
broadly. Most of what a competitor ships as nine "sensors" are parsers and API
clients, not analysis engines.

| Collector | Build? | Reasoning |
|---|---|---|
| TLS/HTTPS endpoint | **Build** | A handshake plus a cert parse. High visual payoff |
| Certificate & keystore (PEM/DER/JKS/PKCS#12/PKCS#7) | **Build** | `cryptography` + `pyjks`. Produces the chains that feed the roadmap |
| Filesystem walk | **Build** | Dispatch by type |
| SSH | **Build** | Banner + KEX negotiation |
| Cloud KMS/ACM (AWS/Azure/GCP) | **Build** | Read-only API calls |
| Windows cert store / AD | **Build** | API calls. AD is a gap worth a `TASK.md` line |
| Binary (imports, strings, known constants, Authenticode chain) | **Build, shallow** | Pattern matching, not analysis. Scope honestly: no symbolic execution |
| **Source code** | **Integrate** | The only real engine. Write our own *rules*; use someone else's matcher |
| SBOM / dependency | **Integrate** | Syft/cdxgen. Nobody gives credit for redoing it |

So: own the sensor architecture, own seven of nine collectors, own every rule,
lean on exactly two upstream tools behind an adapter boundary. That is "our own
scanner" in every sense a judge or a customer means, without spending two weeks
rebuilding a Java AST parser.

**`NOTE.md §3.1` and `CLAUDE.md §2` should be amended** to say *"do not build a
crypto-detection **engine**"* rather than *"do not write scanners"* — the current
phrasing forbids work we should be doing.

### 5.1 Deployed-artefact scanning beats repo scanning for Indian BFSI

In an SI-built estate — and Indian BFSI is overwhelmingly SI-built, on Java core
banking products — the customer frequently **does not have the source**. The
integrator holds the repository. What the customer has is WARs, EARs, JARs,
appserver configuration, keystores and certificates.

A repo-scanning-first product fails in the first meeting with an Indian bank.
Java archives are zip files with readable manifests, embedded
`pom.properties`, and classes inspectable for JCA call sites — and the
JKS/PKCS#12 keystores sit in the same directory tree.

→ Prioritise the filesystem/keystore/binary collectors over the source collector
for the demo corpus. This is a market-fit decision, not a technical one.

---

## 6. The demo narrative

Three beats. Parity, then the two things that cannot be copied in a weekend.

**Beat 1 — Parity (≈60s).** Scan a real, recognisable target: a live TLS
endpoint, a keystore directory, and a real installer binary. Inventory populates
with five-figure asset counts. We look like a peer product.

> Volume matters. A sparse demo looks like a prototype next to a competitor
> screenshot showing 21,224 assets. A filesystem walk of `/usr/lib` plus a
> container image scan reaches five figures without faking anything.

**Beat 2 — Reconcile (≈45s).** Ingest a supplier-provided CBOM alongside the
discovered inventory. They disagree on a padding mode. One asset, both
provenances, `disputed` surfaced at the attribute level. State that CERT-In
§8.4.1.8 mandates exactly this and that the competitor's CBOM import is
visualise-only.

**Beat 3 — Decide and sequence (≈90s).** This is the whole pitch.
- Migration Authority splits the HIGH bucket: *"9,000 of these are not yours."*
- Mosca explorer: move `Z`, priorities re-sort live, banner names the binding
  constraint as the Dec 2028 DST date, not a CRQC guess.
- The certificate chain from Beat 1 becomes a wave-ordered roadmap: the root
  before the intermediate before the leaves, with the reason on screen.
- One cycle detected, labelled "requires hybrid bridge."
- Export a schema-valid CycloneDX 1.7 CBOM, live.

**The line to say out loud:** *"Everything up to this point, a competitor can
show you. From here on, nobody can."*

This aligns with `PRD.md §7`; treat that as normative and this as the narration.

---

## 7. Anti-goals

Do not build, do not claim, do not drift into:

- A new crypto-detection engine (`NOTE.md §3.1`)
- QBOM — it inventories quantum *devices* (model, vendor, hardware,
  environmental impact). Different object. Say so explicitly so nobody assumes
  coverage. AIBOM and HBOM likewise
- Remediation: no PRs, no key rotation, no config push
- CRQC forecasting — we consume a horizon, we do not produce one
- An accuracy claim before `OQ-05` is measured
- Multi-tenant SaaS
- Symbolic execution or decompilation of stripped binaries
- **An LLM anywhere in the scoring path.** See §8.1
- Cloning the competitor's UI. Take the certificate-expiry panel and the typed
  relationship graph as *category conventions*; do not reproduce their layout or
  copy

---

## 8. Known-weak reasoning, stated so it can be attacked

**8.1 — ~~The LLM narrative feature~~ — RESOLVED 2026-09-17: out of scope.**
The contradiction was real — prose summarisation necessarily carries hostnames,
file paths and which systems are weak, so an external API call is exactly the
phone-home behaviour `SECURITY.md §5` declares non-negotiable, and it breaks
silently air-gapped.

**Decision: LLM-assisted narrative is out of scope for v1.** The flag
`QAVACH_ENABLE_NARRATIVE` ships disabled with no implementation behind it. It is
future scope and gets its own ideation pass before any code is written. Do not
build it, do not design around it, do not reference it in the demo. The
constraints already identified (decorative-only, pseudonymise before prompt
assembly, local endpoint only) are recorded in `NOTE.md §4.6` for that future
pass. No LLM appears anywhere in v1 — scoring, classification or prose.

**8.2 — `Y` is unmeasured.** (`OQ-02`) The DST report supplies six factors we
should adopt verbatim in place of invented weights, because they carry national
authority: latency sensitivity (manageable at millisecond scale, problematic at
microsecond scale — defence, telecom), handshake frequency (long-lived sessions
minimal, frequent renegotiation amplifies), user/service tolerance, hardware
constraints (long-lived platforms, embedded devices, certified systems lacking
compute headroom), vendor dependence, cross-border dependencies.

**8.3 — Cross-service dependency edges are frequently absent.** Within an
application, SBOM trees and certificate chains give real edges. Across services,
most organisations have no reliable map. Derive what we can, allow manual edges,
and show a coverage banner stating derived vs asserted vs unknown. Do not
oversell "we know your dependency graph." The roadmap is still valuable with
partial edges — cert chains and library-before-application ordering alone produce
real sequencing.

**8.4 — No error-detection layer on the risk arithmetic**, deliberately, since
there is no LLM in the loop. Compensate with a **differential oracle**: a second,
independent implementation of the band arithmetic as a flat decision table,
diffed in CI. The state space is small enough to enumerate exhaustively.

**8.5 — Curve-name canonicalisation is unspecified.** `secp256r1` =
`prime256v1` = `P-256` = `1.2.840.10045.3.1.7`. Needs an explicit normalisation
stage before identity hashing, canonicalising to OID where one exists, with a CI
test over an alias corpus. This is a bug waiting, not a nicety.

**8.6 — The Risk Register is discoverable evidence.** A document ranking your own
weaknesses is subpoenable. Practical mitigation: record decisions, inputs and
dates — not speculative prose about how bad things are. Retention policy applies.

**8.7 — Two named competitors, one naming collision.** `KavachQ` (kavachq.in) is
live, India-specific, DST-roadmap-aligned, and phonetically our name. That is a
branding decision, not a footnote. `QCecuring` is the product analysed in §2.
Neither has a sequencing layer. Both have shipping scanners.

---

## 9. Amendment ledger — **all applied 2026-09-17**

Every row below has been applied to the named file. Kept as a record of what
changed and why, so a future reader can see the delta rather than re-derive it.

| # | Change | File |
|---|---|---|
| A-1 | NQM ladder is **six dates across two tracks**, not three | `README.md`, `PRD.md §1.1`, `config/policy/` |
| A-2 | Add **Invariant I8 — `UNKNOWN` is a fifth finding class and never renders as safe** | `CLAUDE.md §2`, `ARCH.md §7.1` |
| A-3 | Add **Migration Authority** to the asset model and to roadmap eligibility | `ARCH.md §4`, §9.2 |
| A-4 | Split `X` into `X_conf` / `X_integ`; `max()` upward aggregation; cite TNFL | `ARCH.md §7.2`, Invariant I2 |
| A-5 | Attribute-scoped precedence; "silence is not a claim"; multi-usage ≠ dispute | `ARCH.md §6.1`, §6.4, Invariant I4 |
| A-6 | Seventh edge type `REGULATORY_GATE` + node splitting; pin-superset cycle variant; retention constraints | `ARCH.md §9.1`, §9.3 — **resolves OQ-01** |
| A-7 | CA identity by SPKI hash, certificates as instances by fingerprint | `ARCH.md §6.1` — **resolves OQ-03** |
| A-8 | Format answer: CERT-In accepts **SPDX or CycloneDX**; no bespoke Indian schema | **resolves OQ-06** |
| A-9 | Reconciliation is mandated by CERT-In §8.4.1.8, not self-inflicted | `NOTE.md §4`, `PRD.md §1` |
| A-10 | Adopt the DST six-factor cost model in place of invented `Y` weights | `ARCH.md §7.4` — partially addresses OQ-02 |
| A-11 | Reword "do not write scanners" → "do not build a crypto-detection **engine**" | `CLAUDE.md §2`, §7; `NOTE.md §3.1` |
| A-12 | Policy templates carry an **applicability scope**; ~100% violation rate is a scoping error | `ARCH.md §7`, compliance module |
| A-13 | `parameterSetIdentifier`, never a scalar key size; implausible values → data-quality queue | `ARCH.md §4`, §5.2 |
| A-14 | Alert relevance gate: `migration_authority = self` + operational locus | new, `PRD.md §4.8` |
| A-15 | Certificate expiry timeline panel (category convention) | `PRD.md §4.8` |
| A-16 | **LLM narrative out of scope for v1**; flag disabled, no implementation; separate ideation later | `NOTE.md §4.6`, `CLAUDE.md §7`, `SECURITY.md §5` |
| A-21 | Differential oracle for the band arithmetic, since there is deliberately no model in the loop | `NOTE.md §4.6a` |
| A-17 | Design to NQM assurance **L3**; note QAVACH is itself a named product category | `SECURITY.md`, `README.md` |
| A-18 | Curve-name canonicalisation stage + alias corpus test | `ARCH.md §5.2` |
| A-19 | Golden test: PQC OIDs resolve to named parameter sets and classify `QUANTUM_SAFE` | `TASK.md` Phase 1 |
| A-20 | Prioritise deployed-artefact collectors over source for the demo corpus | `TASK.md` Phase 3 |

---

## 10. How to judge whether this was worth building

Not "we detected the most algorithms" — that is the delegated scanners'
achievement (`PRD.md §8`).

The test is a single screen: an operator looks at 20,000 findings and, within
thirty seconds, can say **which 1,200 are theirs, which 40 come first, why, and
what happens if they do nothing until 2028** — with every number traceable to a
source and a policy version.

If the product cannot do that, nothing else about it matters.
