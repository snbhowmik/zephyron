# CycloneDX 1.7 schema + Cryptography Registry (vendored)

T-011. Source: [CycloneDX/specification](https://github.com/CycloneDX/specification),
Apache-2.0, tag **`1.7.2`** (commit `349314a9d7671d7d2ca5b711a725f49a73979da6`),
verified 2026-09-18.

| File | Role |
|---|---|
| `bom-1.7.schema.json` | The canonical BOM JSON Schema — `ARCH.md §5.1` |
| `cryptography-defs.schema.json` | Shapes referenced by `bom-1.7.schema.json` for `algorithmFamiliesEnum`/`ellipticCurvesEnum` |
| `cryptography-defs.json` | **The Cryptography Registry itself** — `ARCH.md §5.2`: 98 algorithm families (with standards citations and naming patterns) + `ellipticCurves` groupings. This is the authority `normalize/registry.py` (T-012) resolves against. |
| `jsf-0.82.schema.json` | JSON Schema Faker extension `bom-1.7.schema.json` depends on |
| `spdx.schema.json` | SPDX licence-expression validation `bom-1.7.schema.json` depends on |

All five files are needed together — `bom-1.7.schema.json` `$ref`s the other
four by relative filename. Do not rename any of them; do not vendor
`bom-1.7.schema.json` alone and assume it validates anything (it will fail
to resolve its own refs, or worse, silently reach out to
`cyclonedx.org`/GitHub over the network at validation time, which breaks
the air-gap requirement, invariant I7).

**Verified offline** (2026-09-18): loaded all five as a local
`jsonschema` registry with the process's own `socket.socket` replaced by a
function that raises on any call, then validated a real `ML-KEM-768`
cryptographic-asset component successfully and confirmed a deliberately
invalid document was rejected — not just "no code happened to call the
network," but "a network call would have raised."

## What the Cryptography Registry does *not* give you

`cryptography-defs.json` has **no OID-to-family mapping** — it defines
canonical names, standards references and naming *patterns*
(e.g. `ML-KEM-(512|768|1024)`), not a lookup table from an OID like
`2.16.840.1.101.3.4.4.2` to `ML-KEM-768`. OID resolution (`ARCH.md §5.2`'s
resolution order, step 1) needs a separate NIST-sourced table — this
vendored registry is steps 2–3 (registry exact match, alias table basis),
not step 1. Do not assume vendoring this file alone solves OID resolution;
that is T-012/T-013's job, verified against NIST CSRC directly (`CLAUDE.md §8`).

## How to refresh

1. Check the latest tag: `gh api repos/CycloneDX/specification/tags -q '.[].name' | head`
2. Fetch each file at the new tag, e.g.:
   ```bash
   gh api "repos/CycloneDX/specification/contents/schema/<file>?ref=<tag>" \
     -q .content | base64 -d > config/knowledge/cdx-crypto-registry/<file>
   ```
   for each of the five files above (same filenames upstream).
3. Re-run the offline validation check (see `NOTE.md §7`, 2026-09-18 entry,
   for the exact script) against a few known-good and known-bad sample
   BOMs before committing the refresh.
4. Update the tag/commit/date in this README's header.
5. Check `NOTE.md §6` (MODEL-01/MODEL-02 and any OID-resolution open
   questions) for anything the new version might resolve or invalidate.
