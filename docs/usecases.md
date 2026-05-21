**English** | [日本語](usecases.ja.md)

# Use Cases

`rs-ioc-vault` is an IoC store that consolidates OSINT-derived IoCs into a single SQLite file and lets you work with them from both the CLI and the library. Below are representative usage scenarios.

## 1. Instant local lookups by SOC analysts

Instantly check whether an IP / domain / hash under investigation is a known threat, locally and without relying on external APIs.

```bash
# Initialize and ingest (first time only)
ioc-vault init
ioc-vault update --all --since 7d

# Single-value lookup
ioc-vault lookup 203.0.113.42
ioc-vault lookup evil.example.com --format json

# Bulk lookup from standard input
cat suspicious_hosts.txt | while read v; do ioc-vault lookup "$v"; done
```

Lookup results include the aggregated confidence, observation sources, threat type, related CVEs, and the time-decay score.

## 2. Embedding the library into a detection pipeline

Embed `rs-ioc-vault` as a library into detection engines or batch jobs to perform high-frequency lookups and searches. The store can be opened and closed statelessly, and an in-memory mode is also available.

```rust
use rs_ioc_vault::{IocVault, SearchQuery, IocType};

let vault = IocVault::builder().database("vault.db").build().await?;

let q = SearchQuery::builder()
    .ioc_type(IocType::Ipv4)
    .min_confidence(70)
    .last_seen_within(chrono::Duration::days(30))
    .build();
let hits = vault.search(&q).await?;
```

See [library.md](library.md) for details.

## 3. Scheduled exports for TIP / SIEM integration

Periodically write out accumulated IoCs as STIX 2.1 bundles or MISP events and ingest them into TIP, SIEM, or SOAR systems.

```bash
# Export the last 7 days as a STIX 2.1 bundle
ioc-vault export --format stix --since 7d --out feed.json

# Export only phishing-related entries as a MISP event
ioc-vault export --format misp --threat-type phishing --out phishing.misp.json

# Export high-confidence IPv4 entries as CSV
ioc-vault export --format csv --type ipv4 --min-confidence 80 --out ipv4.csv
```

Because `export` accepts the same filters as `search`, your search conditions carry over directly to what gets distributed.

## 4. Incremental updates and an auditable collection log

Feeds are fetched incrementally, honoring ETag / Last-Modified, and skipped when nothing has changed. Each collection run is recorded, so you can later trace when, from which source, and how many entries were ingested.

```bash
# Incrementally update a specific source with a date range
ioc-vault update --source threatfox --since 2026-04-01

# Check ingestion status and counts
ioc-vault stats
ioc-vault source list
```

## 5. Noise reduction via confidence aggregation and time decay

When the same IoC is observed from multiple sources, the observations are treated as independent evidence and the confidence is aggregated. The time-decay score is also recomputed based on a per-IoC-type half-life, lowering the weight of stale indicators.

```bash
# Recompute time-decay scores
ioc-vault decay

# Extract indicators with high decay scores (i.e., recent and high-confidence)
ioc-vault search --type url --min-decay 0.5 --order decay-desc --limit 100
```

## 6. Operating as the bottom layer (Bronze layer) of a data lake

Operate it as a normalized, deduplicated raw IoC store and feed downstream analysis pipelines (enrichment, correlation analysis, scoring) with JSONL / CSV.

```bash
ioc-vault export --format jsonl --since 1d > bronze/iocs-$(date +%F).jsonl
```

---

Related documents: [CLI Reference](cli.md) · [Library Usage](library.md) · [Architecture](architecture.md)
