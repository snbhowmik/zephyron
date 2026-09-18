# SECURITY.md — QAVACH

Security model for QAVACH as a deployed system. Read before touching anything
that executes a scanner, handles a credential, accepts a network target, or
writes an export.

---

## 1. The uncomfortable summary

QAVACH is a system that **executes untrusted third-party code against untrusted
input and produces a ranked map of an organisation's cryptographic weaknesses.**

Both halves of that sentence are security problems:

- The execution half: scanners like cdxgen invoke real build tooling (`mvn`,
  `npm install`, `go mod download`) to resolve dependencies. That is arbitrary
  code execution on the scan target's terms, inside our infrastructure. This is
  documented upstream behaviour, not a hypothetical.
- The output half: a completed QAVACH inventory tells an attacker exactly where
  the weak cryptography lives, ranked by exploitability, with file paths, host
  names and certificate fingerprints. In an NTRO-adjacent deployment it is
  close to the most sensitive artefact on the network.

Everything below follows from those two facts.

---

## 2. Trust boundaries

| Zone | Trust | Notes |
|---|---|---|
| Scan target (repo, image, host, cloud account) | **Untrusted** | Even a first-party repo. Compromise is the scenario we are defending against. |
| Scanner processes | **Untrusted** | Third-party code processing untrusted input. Assume compromise. |
| Sandbox container | Containment boundary | The only thing between a hostile repo and the worker host. |
| Worker | Semi-trusted | Orchestrates; must never parse untrusted input in-process. |
| API / DB | Trusted | Holds the crown jewels. |
| Operator credentials | Highly sensitive | Git PATs, cloud keys, registry creds. |
| CBOM / Risk Register | **Highly sensitive** | An attacker's target list. |
| Deployed agent (on customer host) | Our code, elevated exposure | Runs QAVACH's own code with real filesystem and key-material access, persistently or on demand, on infrastructure we do not control. See `§2a`. |

The boundary that matters most is scanner ↔ worker. Everything else is
conventional web-application security; that one is specific to what we are
building.

---

## 2a. Deployed agent — the trust direction is reversed

Every other zone in the table above assumes untrusted input arriving on
QAVACH-controlled infrastructure. The deployed agent (`ARCH.md §3a`) is the
mirror image: **our** code, running persistently or on demand with real
filesystem and key-material access, on infrastructure **we do not control**.
The scan-target threat model in §1 and the sandbox in §3 do not transfer to
this zone; it needs its own.

**What is different:**

- The thing we must contain is not a hostile scan target — it is the blast
  radius of our own agent being compromised, misconfigured, or run on a host
  that is itself already compromised.
- There is no sandbox to put the agent in: it must read real `0600`
  keystores, real PKCS#11 configuration and real deployed artefacts, on the
  customer's own filesystem. Containment has to come from what the agent is
  *allowed to do*, not from what it is walled off from.
- The agent is reachable at all only because it initiates the connection.
  Reversing that — accepting an inbound connection — would turn every
  enrolled host into a service exposed on the customer's network, a strictly
  worse position than not having an agent at all.

**Non-negotiable controls, in order of how much damage their absence would
cause:**

1. **Outbound-poll-only.** The agent never listens on a socket. It polls the
   backend for work and posts results back over the connection it opened.
2. **Typed scan spec, never a command.** The only thing the backend can ask
   the agent to do is run a named collector module against a named path.
   There is no execution primitive in the protocol — not a shell, not an
   eval, not a generic payload field. A compromised backend can make the
   agent re-run its own collectors against paths it is already permitted to
   read; it cannot make the agent run anything else.
3. **mTLS, both directions verified.** The agent presents the client
   certificate issued at enrollment; it verifies the backend's certificate
   against a pinned CA rather than accepting whatever certificate is offered.
4. **Least privilege.** The agent process runs as a low-privilege service
   account. Access to a specific sensitive path (a keystore, a PKCS#11
   config) is granted by a scoped ACL or sudo rule for that path — never
   blanket root and never a standing elevated account. Every fetched file is
   parsed in a further resource-limited, further-restricted worker process,
   not inline in the agent's main process (`ARCH.md §3a`) — least privilege
   plus a scoped ACL alone is not enough to contain a parser bug once there is
   no container around it.
5. **Signed, provenance-attested binary that verifies its own updates.**
   Extends `§7`'s supply-chain controls to a binary that runs outside our
   infrastructure, where we cannot inspect the host it runs on.
6. **Redaction stays on the backend.** `§5.1`'s secret-detection pass is not
   something the agent can be trusted to perform on itself — a compromised
   agent could be made to skip it. The agent may truncate an oversized
   payload to a size cap before sending it; it never decides what counts as a
   secret.
7. **One egress target.** The agent is configured with exactly one backend
   URL and nothing else — no telemetry endpoint, no update mirror, no
   fallback. Ties to `§5`'s no-telemetry rule and `PRD.md NFR-05`'s air-gap
   requirement.

**Enrollment is the identity boundary.** An operator generates a short-lived,
single-use, host-scoped token from the dashboard; the agent exchanges it once
for a rotatable long-lived credential and registers itself. The identity
issued at that exchange — not an operator-typed hostname — is what evidence
is attributed to (`ARCH.md §6.2`, `HostLocus`), specifically because an
operator-supplied string can be wrong or spoofed and a backend-issued identity
cannot.

**What this does not defend against:** a host that is compromised *before* or
*independent of* the agent. See `§11`.

---

## 3. Sandbox — mandatory, no exceptions

Every collector with `requires_sandbox = True` runs in a fresh container per
job. There is no bypass flag and no "trusted target" mode.

```
docker run --rm
  --network=none                       # unless collector.requires_network
  --read-only
  --tmpfs /work:rw,size=2g,noexec,nosuid,nodev
  --tmpfs /tmp:rw,size=512m,noexec,nosuid,nodev
  --user 65534:65534
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --security-opt seccomp=config/seccomp/scanner.json
  --pids-limit 512
  --memory 4g --memory-swap 4g
  --cpus 2
  -v <target>:/target:ro
  <image@sha256:...>                   # pinned by digest, never by tag
```

**Rules:**

- **Pinned by digest.** `config/scanners.yaml` holds digests, not tags. A tag
  is a mutable pointer to code we will execute with a filesystem mounted.
- **`--network=none` by default.** A collector that needs network declares
  `requires_network = True` and gets an explicit egress allowlist. Nothing gets
  unrestricted egress.
- **Output crosses the boundary as the container's stdout** — one JSON blob,
  captured with `docker logs` after the container exits, before it is
  removed. `/work` (and `/tmp` — added after T-032 found a real scanner,
  cdxgen's `cbom`, hardcodes `/tmp/cdxgen-temp` for its own scratch cache
  regardless of `TMPDIR`) are scratch space for anything the scanner needs
  to write along the way, still `noexec,nosuid,nodev`; neither is the
  retrieval channel. (Verified live, T-031: a `--tmpfs` mount is torn down
  the moment
  its container *stops*, not when it is `rm`'d — `docker cp
  <container>:/work/result.json` 404s against an already-exited container
  even with the container object still present. `docker logs` has no such
  gap, because the log driver captures the stream continuously while the
  process runs, independent of the filesystem. A collector that produces a
  file needs a command that ends by printing it, e.g. `scanner -o
  /work/bom.json && cat /work/bom.json`.) The worker never reads arbitrary
  paths the scanner wrote — stdout is the only channel data crosses on.
- **The collector's command always overrides the image's own `ENTRYPOINT`**
  (`--entrypoint <command[0]>`), never relies on it. A real bug, T-032: the
  pinned cdxgen image bakes `ENTRYPOINT ["cdxgen"]`; a config that sent
  `("sh", "-c", "...")` as plain CMD without this override got it *appended*
  to that entrypoint — the actual process became the nonsensical `cdxgen sh
  -c "..."`, with cdxgen receiving "sh"/"-c"/the script text as its own
  confused CLI arguments. Invisible in T-031's own tests because `busybox`
  has no conflicting `ENTRYPOINT` to collide with.
- **Timeout enforced by the orchestrator**, not by the container. Default 900s.
  A hung scanner is a failed collector (`partial=True`), not a hung scan.
- **Failure is isolated.** A crashed, OOM-killed or timed-out collector
  degrades the scan; it never fails it and never propagates an exception out of
  the worker.

### 3.1 Build resolution is off by default

`cdxgen` resolves dependencies by running the target's build. This gives much
better results and is also the single largest risk in the system: a malicious
`pom.xml`, `package.json` `postinstall`, or `build.gradle` executes on our
infrastructure.

```
--allow-build-resolution           # off by default
```

When enabled:
- Egress is allowlisted to package registry hosts only, enforced at the proxy,
  not by the container's own configuration.
- A warning naming the specific risk is printed to the operator and written to
  the audit log.
- The setting is recorded in `scan_runs.policy_snapshot_json` so a later reader
  knows how the result was produced.

Never make this the default. Never enable it silently because results are
better with it on.

---

## 4. Network targets and SSRF

The TLS collector (FR-130) accepts operator-supplied host:port targets and CIDR
ranges. That is an SSRF primitive by construction.

**Denied by default, in `config/security/network_policy.yaml`:**

- `169.254.169.254/32` and `fd00:ec2::254` — cloud instance metadata
- `169.254.0.0/16`, `::1/128`, `127.0.0.0/8` — link-local and loopback
- `metadata.google.internal`, `metadata.goog`
- Kubernetes service CIDRs and the API server, when detected
- Any address resolving into the QAVACH deployment's own network segment

**Additional controls:**

- **Resolve then pin.** Resolve the hostname, validate the resulting IP against
  the policy, then connect to that IP with SNI set — never resolve twice.
  Re-resolution between validation and connection is a classic DNS-rebinding
  bypass.
- Redirects are not followed. The TLS collector does not speak HTTP.
- Rate limit per target host; a scan must not become a DoS against the
  operator's own estate.
- CIDR expansion is capped (default `/22`) and requires explicit confirmation
  above the cap.
- Every target scanned is written to the audit log.

---

## 5. The CBOM is confidential

Treat QAVACH output as classified material for the organisation being scanned.

- **At rest:** database encryption; object storage encrypted; raw scanner output
  in MinIO/S3 with server-side encryption and no public access.
- **Access control:** RBAC with at minimum Viewer / Analyst / Admin. Viewers see
  posture and aggregates; asset-level detail with file paths and host names
  requires Analyst.
- **Audit log:** every read of a full inventory export, every suppression, every
  adjudication, every policy change. Immutable, append-only.
- **No telemetry.** QAVACH phones home to nothing. There is no usage analytics,
  no crash reporting to a third party, no "anonymised" statistics. This is
  non-negotiable for the deployment context. **This is also why LLM-assisted
  narrative is out of scope for v1** — any such prose necessarily carries
  hostnames, file paths and which systems are weak. See `NOTE.md §4.6`.
- **Air-gap capable.** NFR-05 is a security requirement, not just an operational
  one.
- **Export watermarking:** every export carries the scan ID, the policy version,
  the generating user and a timestamp.
- **Retention:** configurable automatic purge of raw scanner output, which
  contains the most sensitive detail (source snippets, config fragments).

### 5.1 Redaction

Occurrences can carry source snippets. Those snippets can contain hardcoded
keys, passwords and tokens — because that is exactly the kind of code a crypto
scanner finds.

- Snippets are truncated to the matched construct plus minimal context.
- Run a secret-detection pass over any snippet before storing it; redact hits
  to `[REDACTED:<type>]` and record that redaction occurred.
- A hardcoded private key discovered during a scan is a **critical finding in
  its own right**, reported as `related-crypto-material` with the material
  itself never stored — fingerprint and locus only.

---

## 6. Credentials

QAVACH handles Git PATs, cloud access keys, registry credentials and optionally
PKCS#11 PINs.

- Never logged. Not at debug level. Add a log filter and test it.
- Never persisted in plaintext. Encrypted at rest with a key from the
  environment or a KMS; never in the same store as the ciphertext.
- Never written to `scan_runs.policy_snapshot_json` or any export.
- Passed to a sandboxed collector through an environment variable or a tmpfs
  file with `0400`, and destroyed with the container.
- **Cloud collectors are read-only by contract.** Ship the exact minimum IAM
  policy in `docs/iam/` and document that QAVACH requires nothing more. Refuse
  to run if handed credentials with write permissions to KMS — that is a
  misconfiguration worth failing loudly on.
- Git clones use short-lived, scoped tokens; the clone is deleted after the
  scan regardless of outcome, in a `finally`.

---

## 6a. Assurance target — NQM L3

India's roadmap directs that the national list of cryptography-dependent product
categories add *"automated cryptographic discovery and inventory solutions"*,
and that inclusion "constitutes a future compliance requirement for vendors."
QAVACH is that category. Design for it now rather than retrofitting.

Under the TEC/STQC/BIS framework, a tool serving BFSI, telecom or healthcare
sits at **L3 — Enterprise Infrastructure Security** (certification validity:
3 years L1, 5 years L2, **7 years L3**, 10 years L4). L3 requires everything at
L1–L2A/2B plus crypto-agility validation, TRNG/QRNG entropy validation where
applicable, CI/CD integration and automation testing, automated vulnerability
discovery, supply-chain security verification, and secure integration with
centralised cryptographic management systems.

Most of that is already required elsewhere in this document. The gaps to close
deliberately:

- **Crypto-agility validation of QAVACH itself** — we must be able to swap our
  own signing and transport algorithms by configuration, and demonstrate it.
- **VA/PT by a CERT-In empanelled auditor**, not a self-assessment.
- **Supply-chain verification** at the level §7 describes, with evidence.

Note the useful corollary for customers: CERT-In's guidance allows that where
OEM design documentation is unavailable, review may proceed on the basis of the
**cryptographic bill of materials and self-test reports** as an interim measure.
A CBOM substituting for unavailable vendor design documentation is a real,
sellable workflow.

---

## 7. Supply chain — ours

QAVACH is a security tool. It will be scrutinised.

- All Python and JS dependencies pinned with hashes (`uv.lock`, `pnpm-lock.yaml`).
- All scanner images pinned by digest.
- Generate and publish QAVACH's own SBOM **and its own CBOM**, on every release.
  Dogfooding here is both good practice and an excellent demo moment.
- Sign releases. Attach provenance attestation. This includes the deployed
  agent binary (`ARCH.md §3a`): it is signed, provenance-attested, and
  verifies its own update signature before applying — the one release
  artefact that runs on infrastructure we do not control.
- Dependabot or equivalent, with review — never auto-merge into a security tool.
- `docs/THIRD_PARTY.md` lists every scanner, its licence and its invocation
  mode. Opengrep is LGPL-2.1 and is invoked as a **separate process only** —
  never linked, never vendored into the codebase.

---

## 8. QAVACH's own cryptography

A PQC migration tool that signs its own exports with RSA-2048 is a punchline.
Expect this to be checked.

- **Export signing:** ML-DSA-65 (FIPS 204) where the available library supports
  it. If it does not, Ed25519 — **and the output states that limitation
  explicitly.** Silently falling back is worse than the limitation itself.
- **TLS:** prefer a configuration offering `X25519MLKEM768` where the stack
  allows. Document what is actually offered.
- **At rest:** AES-256-GCM. Not AES-128 — not because AES-128 is broken, but
  because we recommend 256-bit for long-lived data and must follow our own
  advice.
- **Password hashing:** Argon2id.
- **Tokens:** EdDSA or ML-DSA, never `RS256`.
- **QAVACH's own CBOM is generated and published**, so anyone can check the
  above rather than take our word for it.

---

## 9. Input parsing

Every parser processes hostile input.

- X.509 parsing via `cryptography` (pyca) only. Never hand-roll ASN.1.
- Archive extraction (container layers, JKS, PKCS#12) must guard against zip
  slip, symlink escape and decompression bombs. Enforce an uncompressed-size
  cap and an entry-count cap.
- XML anywhere: `defusedxml`, entity expansion disabled.
- YAML: `yaml.safe_load`, always.
- Scanner JSON output is size-capped before parsing; a 4 GB SARIF file is a DoS.
- Prefer deterministic parsing over large regexes. For filenames, purls, refs
  and manifests, use `split`, `startswith`, `indexOf` and small anchored
  validators. Avoid nested quantifiers and broad `.*` chains — they are
  ReDoS vectors and they are harder to review.

---

## 10. Multi-tenancy

If QAVACH is deployed shared across business units:

- Every query is scoped by tenant at the repository layer, not the route
  handler. A missing filter in one endpoint should not be able to leak another
  tenant's inventory.
- Object-storage prefixes are per tenant, with policy enforcement.
- Sandbox containers are never reused across tenants.
- Cross-tenant aggregate views are opt-in and show counts only, never asset
  detail.

---

## 11. What is explicitly not defended

Stating limits honestly is part of a threat model.

- **A malicious operator.** Someone with Admin can exfiltrate the inventory.
  Mitigated by audit logging and RBAC, not prevented.
- **Container escape via a runtime CVE.** We harden the container; we do not
  defend against a Docker or kernel vulnerability. Keep hosts patched; consider
  gVisor or Kata for high-assurance deployments.
- **Scanner correctness.** If cdxgen reports a wrong algorithm, QAVACH reports
  a wrong algorithm. The confidence tiers and dispute mechanism reduce the
  blast radius; they do not eliminate it.
- **Physical and HSM security.** Out of scope.
- **Denial of service via a very large scan target.** A 50 GB monorepo will
  consume resources. Resource caps and timeouts bound it; they do not make it
  free.
- **A host the agent runs on being compromised, independent of the agent.**
  The agent's own least-privilege design (`§2a`) limits what an attacker who
  has *already* fully compromised the host gains beyond what that compromise
  already gave them. The agent does not detect host compromise, does not scan
  for rootkits or lateral movement, and is not an EDR product. Endpoint
  security on the host is the operator's responsibility, not QAVACH's.

---

## 12. Reporting a vulnerability

Do not open a public issue. Contact the maintainers privately. Include a
reproduction and a proof of impact.

Out of scope: automated-scanner output with no demonstrated exploit path;
resource exhaustion from an operator deliberately supplying a pathological
target; findings requiring pre-existing privileged access to the deployment.
