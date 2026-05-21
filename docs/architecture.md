**English** | [日本語](architecture.ja.md)

# Architecture

`rs-ioc-vault` is split into several crates within a Cargo workspace, so consumers can depend only on what they need. Dependencies flow in a single direction, from higher to lower layers, and lower-layer I/O is hidden behind traits.

## Crate layout

| Crate | Layer | Role |
|----------|---------|------|
| `ioc-vault-core` | Domain | I/O-free domain model (IoC types, normalization, dedup hash, search query, decay model) |
| `ioc-vault-store` | Infrastructure | SQLite (sqlx) persistence, search engine, confidence aggregation, time decay |
| `ioc-vault-collect` | Domain | Collector trait and collection context (incremental fetch / 304) |
| `ioc-vault-adapters` | Adapter | Per-feed adapters (URLhaus / ThreatFox / CISA KEV); feature-gated |
| `ioc-vault-export` | Adapter | Export to CSV / JSONL / STIX 2.1 / MISP |
| `rs-ioc-vault` | Application | The public facade `IocVault` that ties the above together |
| `ioc-vault-cli` | UI | The single binary `ioc-vault` |

## Data flow

```
OSINT feeds → Collector → normalize / dedup → SQLite (WAL + FTS5) → Query / Export → CLI · STIX · MISP
```

1. **Collection**: `Collector` fetches feeds while honoring ETag / Last-Modified and returns a stream of `RawIoc`.
2. **Normalization and deduplication**: Values are normalized by per-IoC-type rules and consolidated into a single record using `SHA-256(type || ":" || value)` as the dedup key.
3. **Persistence**: Stored in a single SQLite file (WAL mode, FTS5 full-text search).
4. **Aggregation**: Observations from multiple sources are treated as independent evidence and the confidence is aggregated in a Bayesian-style manner, while time-decay scores are computed using per-IoC-type half-lives.
5. **Search / Export**: Provides compound-condition search (type, period, confidence, CIDR, regex, FTS5) and standard-format export (STIX 2.1 / MISP / CSV / JSONL).

## Persistence approach

- It is self-contained in a single SQLite file and requires no external DB server.
- WAL mode plus batch commits speed up bulk ingestion.
- Full-text search uses an FTS5 virtual table kept in sync with the main table via triggers.
- The schema is version-controlled via migrations in `migrations/`.

## Design choices

- The domain layer (`ioc-vault-core`) has no I/O dependencies, preserving testability.
- Adapters can be enabled individually via feature flags, eliminating the compile cost of unused sources.
- Errors use a two-layer structure: `anyhow` at the application layer and `thiserror` at the library layer.
- IoC types follow the STIX 2.1 Cyber-observable naming, simplifying the mapping at export time.
