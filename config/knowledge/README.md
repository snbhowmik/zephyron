# config/knowledge

The CycloneDX Cryptography Registry vendor copy, the algorithm alias table,
the crypto-library capability database, the host known-paths manifest, PQC
alternatives and the performance benchmark table. This is curated knowledge
work, not config stubs — see `NOTE.md §3.5` and `ARCH.md §5.2`, `§5.3`,
`§3a`, `§8.1`, `§8.3`.

| File | Task | Populated by |
|---|---|---|
| `cdx-crypto-registry/` | T-011 | Vendored CycloneDX 1.7 schema + Cryptography Registry |
| `aliases.yaml` | T-013 | Algorithm spelling → canonical name |
| `crypto_libraries.yaml` | T-034 | purl → cryptographic capability |
| `host_known_paths.yaml` | T-034a | Per-OS/platform agent auto-scan manifest |
| `pqc_alternatives.yaml` | T-080 | PQC replacement recommendations, with `status`/`verified_on` |
| `performance.yaml` | T-083 | Cited benchmark figures — `null`, never fabricated |

Not yet populated.
