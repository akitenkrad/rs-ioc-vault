**English** | [日本語](library.ja.md)

# Library Usage (`rs-ioc-vault`)

`rs-ioc-vault` exposes the same core logic as the CLI through the public facade `IocVault`. Adapters and exporters with heavy dependency stacks can be enabled individually via feature flags.

## Adding the dependency

```toml
[dependencies]
rs-ioc-vault = { git = "https://github.com/akitenkrad/rs-ioc-vault" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

## Quick start

```rust
use rs_ioc_vault::{ExportFormat, IocVault, SearchQuery};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // register the default adapters (URLhaus / ThreatFox / CISA KEV) and build
    let vault = IocVault::builder()
        .database("vault.db")
        .with_default_collectors()
        .build()
        .await?;

    // ingest feeds
    vault.update_all(rs_ioc_vault::UpdateOptions::since_days(7)).await?;

    // look up a single value
    if let Some(rec) = vault.lookup("203.0.113.42").await? {
        println!("{} (confidence {})", rec.value, rec.confidence);
    }

    // composite search and export
    let q = SearchQuery::builder().min_confidence(70).limit(100).build();
    let stdout = std::io::stdout();
    let n = vault.export(ExportFormat::Stix, &q, stdout.lock()).await?;
    eprintln!("exported {n} records");
    Ok(())
}
```

## Main API

| Item | Description |
|------|------|
| `IocVault::builder()` | `.database(path)` / `.in_memory()` / `.with_collector(..)` / `.with_default_collectors()` / `.build().await` |
| `update_source(name, &opts)` / `update_all(opts)` | Ingestion from feeds |
| `lookup(value)` | Single-value lookup (`Option<IocRecord>`) |
| `search(&SearchQuery)` | Compound-condition search (`Vec<IocRecord>`) |
| `export(format, &SearchQuery, writer)` | Write out search results in the specified format |
| `apply_decay(&DecayModel)` | Recompute time-decay scores |
| `store()` | Reference to the low-level `IocStore` |

`SearchQuery::builder()` lets you fluently assemble filters (type, source, threat type, period, confidence, CIDR, regex, FTS, and so on). `DecayModel::default()` carries default half-lives per IoC type.

## Using in-memory

For tests or transient processing, `.in_memory()` is handy.

```rust
let vault = IocVault::builder().in_memory().build().await?;
vault.store().bulk_upsert(records, "manual").await?;
```

## feature flags

Each adapter can be toggled by a feature (all enabled by default). Removing unneeded sources reduces build time and binary size.

```toml
rs-ioc-vault = { git = "https://github.com/akitenkrad/rs-ioc-vault", default-features = false, features = ["urlhaus"] }
```
