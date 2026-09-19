# `qavach:` custom properties

The CycloneDX 1.7 CBOM QAVACH exports is a standards artefact other tools
consume. **Risk scores, Mosca inputs and outputs, CARAF outcomes,
recommendations and roadmap position never appear in it** (invariant I5) — they
live in the Crypto Risk Register (`docs/schema/risk-register-1.0.json`), which
references CBOM components by `bom-ref`.

The only QAVACH data allowed inside the CBOM is the closed set below: properties
that describe the *inventory's own quality*, not an opinion about it. The list
is enforced in both directions by `make schema-check` (CI): a `qavach:` property
in an export that is not listed here fails the build, and a property listed here
that the exporter cannot emit also fails it.

| Property | Where | Value | Meaning |
|---|---|---|---|
| `qavach:disputed` | component | `true` (present only when true) | Two tools disagreed about this asset's usage attribute (mode/padding) and no operator has adjudicated it. Both claims are retained in the register; the CBOM only flags that the asset is contested. |
| `qavach:concluded-confidence` | component | `runtime`, `artefact`, `attested`, `dependency`, `ast`, `pattern` or `heuristic` | The confidence tier of the strongest evidence behind the asset (`ARCH.md §6.4`). A provenance fact, not a risk score. |
| `qavach:downgraded-from` | metadata | `1.7` | Present only on the CycloneDX 1.6 compatibility export: the document was rendered from a 1.7 CBOM and lost the 1.7-only fields the exporter lists (`algorithmFamily`, the `key-wrap` primitive). |
| `qavach:scope` | metadata | `component`, `system` or `root` | The BOM scope this export was produced for (`ARCH.md §10.1`, FR-501). |

## What is deliberately *not* here

`finding_class`, `migration_authority`, the Mosca gap, `Z_effective`, expected
value, the CARAF outcome and the roadmap wave are all conclusions QAVACH draws,
so they are in the register. Additionally, `make schema-check` rejects any
property in the CBOM — under any namespace — whose name carries risk vocabulary
(`risk`, `mosca`, `urgency`, `caraf`, `roadmap`, `outcome`, `score`, `priority`,
`criticality`, `recommend`, …), and any `purl` on a `cryptographic-asset`.

To add a property: document it in the table above, add it to
`DOCUMENTED_PROPERTIES` in `packages/core/src/qavach_core/export/cbom.py`, and
justify why it describes the inventory rather than judging it.
