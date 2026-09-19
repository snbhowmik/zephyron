# CycloneDX 1.6 schema (vendored)

T-093. Source: [CycloneDX/specification](https://github.com/CycloneDX/specification),
Apache-2.0, tag **`1.6.2`** (commit `e833d732337dd33aceb45ff1991f896796f1e5e7`),
fetched 2026-09-20. Used only to validate the 1.6 *downgrade* export offline (I7);
1.7 (`../cdx-crypto-registry/`) remains the canonical target.

`bom-1.6.schema.json` `$ref`s `spdx.schema.json` and `jsf-0.82.schema.json` by
relative filename, so all three are needed. Note `spdx.schema.json` differs from
the 1.7 copy (a newer SPDX licence list), so the two directories must not share it.
