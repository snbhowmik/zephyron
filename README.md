<div align="center">

# QAVACH

**Enterprise Cryptographic Asset Inventory & Post-Quantum Migration Planning**

Find every cryptographic artefact in your estate. Understand which ones actually
put you at risk. Get a migration order you can defend to a steering committee.

Smart India Hackathon 2026 · Problem Statement **26164** · NTRO ·
Blockchain & Cybersecurity

</div>

---

## The problem

Every PQC migration guide starts with the same instruction: *inventory your
cryptography first.* India's DST Task Force under the National Quantum Mission
makes it a deadline — and not one deadline but **six, across two tracks**:

| Milestone | CII | Enterprise |
|---|---|---|
| Build foundations — inventory, governance, pilots | **2027** | **2028** |
| Migrate high-priority systems | **2028** | **2030** |
| Full PQC adoption | **2029** | **2033** |

CII means government, strategic, defence, power, telecom, transport and BFSI.

Scanners exist. They emit findings. Here is a shipping competitor's dashboard on
a real 21,224-asset scan: **CRITICAL 13 · HIGH 10,788 · MEDIUM 0 · LOW 2 ·
NONE 10,421.** Half the estate in one undifferentiated bucket, produced by a
product built to solve exactly that problem.

What no tool answers is the question the migration lead actually has:

> Given 20,000 cryptographic findings, a fixed budget and a 2028 deadline —
> **which ones are even mine, what do I fix first, and what can I safely leave
> alone?**

QAVACH answers that question.

---

## What QAVACH does

**Discovers** across source code, dependencies, container images, live TLS
endpoints, certificate stores, cloud KMS and HSM configuration — by orchestrating
best-in-class open-source scanners rather than reinventing them.

**Reconciles** their conflicting output into one canonical inventory. The same
RSA-2048 key found by four tools in four places becomes one asset with four
occurrences and a confidence-ranked conclusion — not four rows.

**Contextualises** with the business facts scanners cannot see: which system
this belongs to, how critical it is, how long its data must stay confidential,
whether it faces the internet.

**Scores** using Mosca's inequality applied *per cryptographic function class*,
inside CARAF's five-dimension risk framework — producing one of four honest
outcomes per asset: **Migrate**, **Compensating control**, **Accept**, or
**Phase out**.

**Recommends** standardised PQC replacements with citations, hybrid guidance
that depends on context, and accurate standardisation status.

**Sequences** it all into a dependency-ordered migration roadmap that respects
trust anchors, protocol peers, hardware gates and the reader-before-writer rule
— and tells you when a cycle means you need a hybrid bridge.

---

## What makes it different

**It only ranks what you can actually change.** Every asset carries a
*Migration Authority*: yours, a vendor's, a public trust anchor's, or gated on a
regulator. A public CA found inside a downloaded installer is inventoried and
then left alone — it is not your migration. This is the difference between
"10,788 HIGH" and "you own 1,240 of these; 648 are gated on NPCI."

**Unknown is never green.** An algorithm we cannot resolve or a key whose size
we cannot determine is reported as a *coverage failure*, counted separately, and
never allowed into a safe total. Tools that default unknown to safe tell a CISO
their estate is fine when they have simply failed to parse it.

**It does not treat all quantum risk as one thing.** Four finding classes:
`QUANTUM_VULNERABLE` (Shor-breakable asymmetric), `CLASSICAL_WEAK` (MD5, SHA-1,
3DES — urgent, but broken *today*, not by quantum), `GROVER_AFFECTED` (AES-128 —
informational, never an urgent migration item), and `QUANTUM_SAFE`. Tools that
redline AES-128 alongside RSA-2048 destroy their own credibility.

**It knows that harvest-now-decrypt-later applies to confidentiality only.**
A 90-day TLS certificate and an offline root CA can use the identical algorithm
and identical key size and have wildly different urgency — because you cannot
usefully forge a signature on something that already expired. QAVACH derives
shelf life per cryptographic function, so root CAs and firmware signing keys
rank where they belong.

**It refuses to pretend it knows when quantum computers arrive.** `Z` is a
configurable, cited policy input with three scenarios, and the UI lets you move
it and watch priorities re-sort. More usefully: for an Indian CII operator the
binding constraint is the **Dec 2028 regulatory date**, not the arrival of a
CRQC. QAVACH computes `min(Z_scenario, regulatory_deadline)` and tells you which
one bound.

**"Accept" and "Phase out" are first-class outcomes.** A tool whose only
recommendation is "migrate everything" is useless to an organisation with a
finite budget. CARAF gives us a principled basis for saying *leave this alone*.

**Every number is explainable and reproducible.** Same inputs plus same policy
snapshot always produces the same register. No LLM anywhere in the scoring path.
Every policy constant carries a citation to a primary source.

---

## What QAVACH is not

We are explicit about this, because overclaiming is how tools in this space lose
technical credibility.

- **Not a crypto scanner.** Discovery is delegated to cdxgen, CBOMkit,
  CBOMkit-theia, Syft and Opengrep. We built the TLS, certificate, cloud and HSM
  collectors ourselves because nothing suitable existed. Everything else is
  integration, deliberately.
- **Not an HSM inventory tool.** v1 detects PKCS#11 *evidence* and flags an
  unresolved crypto boundary. Live slot enumeration needs vendor credentials and
  physical hardware.
- **Not a remediation tool.** QAVACH plans. It does not open pull requests or
  rotate keys. A tool that writes cryptographic code is a different and far more
  dangerous product.
- **Not making accuracy claims yet.** Precision and recall against hand-labelled
  ground truth is task T-121. Until it exists, we claim nothing.

---

## Standards and status

| | Status as of 2026-09 |
|---|---|
| ML-KEM — FIPS 203 | **Final**, published 2024-08-13 |
| ML-DSA — FIPS 204 | **Final**, published 2024-08-13 |
| SLH-DSA — FIPS 205 | **Final**, published 2024-08-13 |
| LMS / XMSS — SP 800-208 | Final |
| HQC | **Selected 2025-03-11. Standard not yet published.** Not a compliance claim. |
| FN-DSA — FIPS 206 | **In development.** Do not treat as available. |

Output format: **CycloneDX 1.7** CBOM (schema-validated in CI), with 1.6
downgrade export. Algorithm naming uses the CycloneDX **Cryptography Registry**
as the canonical authority. Risk intelligence ships as a separate **Crypto Risk
Register** keyed by CBOM `bom-ref` — the CBOM itself stays standards-clean and
interoperable.

Policy anchors shipped with citations: India DST/NQM *Quantum-Safe Ecosystem in
India: Roadmap to Quantum Resiliency* (May 2026) — CII 2027/2028/2029 and
enterprise 2028/2030/2033; SEBI CSCRF crypto-asset inventory (mandatory,
deadline passed); CERT-In *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and
HBOM* v2.0 (09-07-2025) — SPDX or CycloneDX accepted, VEX required; MeitY–CERT-In
*Transitioning to Quantum Cyber Readiness* (2025); NIST IR 8547 (deprecated 2030
/ disallowed 2035, still draft); NSA CNSA 2.0 (US NSS scope only —
applicability-scoped, see `ARCH.md §7.4a`).

**Assurance target.** India's roadmap names *"automated cryptographic discovery
and inventory solutions"* as a product category for future vendor compliance.
QAVACH is designed against **assurance level L3 (Enterprise Infrastructure
Security)** of the TEC/STQC/BIS framework — crypto-agility validation, CI/CD
integration testing, CERT-In-empanelled VA/PT, supply-chain verification.

---

## Quick start

```bash
git clone <repo> && cd qavach
make dev              # postgres, redis, minio, API :8000, web :5173
make scanners-pull    # pull pinned scanner images
make demo             # seed the demo dataset
open http://localhost:5173
```

```bash
make test-unit        # no Docker, no network, no database
make test             # everything
make lint             # ruff + mypy + biome
make schema-check     # validate CBOM output against CycloneDX 1.7
make bundle           # offline tarball for air-gapped deployment
```

---

## Architecture at a glance

```
COLLECT ──▶ NORMALISE ──▶ RECONCILE ──▶ CONTEXT ──▶ RISK ──▶ RECOMMEND ──▶ ROADMAP ──▶ EXPORT
delegated   CDX 1.7 +     identity,     systems,   Mosca +   PQC,        DAG,         CBOM,
+ 4 built   Registry      merge,        criticality CARAF    hybrid      waves,       Register,
in-house                  disputes                                       bridges      PDF
```

Layers 2 through 7 are QAVACH. Layer 1 is mostly delegated, by design.

Python 3.12 · FastAPI · RQ · PostgreSQL 16 · React 18 · TypeScript · Vite ·
Cytoscape.js. Scanners run as sandboxed containers — never linked, never
in-process.

Full detail in [`ARCH.md`](ARCH.md).

---

## Security

QAVACH executes untrusted third-party scanners against untrusted input and
produces a ranked map of an organisation's cryptographic weaknesses. Both halves
are security problems and both are addressed in [`SECURITY.md`](SECURITY.md):
per-job sandboxing with no network by default, build resolution off by default,
SSRF controls on network targets, and CBOM output treated as confidential
throughout.

QAVACH signs its own exports with ML-DSA and publishes its own CBOM. A PQC tool
that signs with RSA would be a punchline.

---

## Documentation

| File | For |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Working in this repo — invariants, layout, what not to do |
| [`PRD.md`](PRD.md) | Requirements, PS 26164 clause mapping, the demo that must work |
| [`ARCH.md`](ARCH.md) | Data model, reconciliation, risk engine, roadmap algorithm |
| [`NOTE.md`](NOTE.md) | Decisions, corrections, rejected ideas, open questions |
| [`TASK.md`](TASK.md) | Phased backlog with dependencies |
| [`SECURITY.md`](SECURITY.md) | Threat model and controls |

**Read `NOTE.md` before proposing an architectural change.** Most attractive
ideas are already there, with the reason they were turned down.

---

## Licence

Apache-2.0. Third-party scanner licences in `docs/THIRD_PARTY.md`. Opengrep is
LGPL-2.1 and is invoked as a separate process only — never linked, never
vendored.
