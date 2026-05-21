//! Quickstart: build an in-memory vault, ingest a few indicators, search, and
//! export the matches as a STIX 2.1 bundle to stdout.
//!
//! Run with: `cargo run -p rs-ioc-vault --example quickstart`

use rs_ioc_vault::{ExportFormat, IocType, IocVault, RawIoc, SearchQuery, Tlp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Open an ephemeral in-memory vault (no collectors, no network).
    let vault = IocVault::builder().in_memory().build().await?;

    // 2. Register a source row, then upsert a few raw indicators directly.
    vault
        .store()
        .register_source("demo", "https://example/demo", "csv", 80, Tlp::Green)
        .await?;

    let raws = vec![
        RawIoc::new("203.0.113.7", IocType::Ipv4),
        RawIoc::new("evil.example.com", IocType::Domain),
        RawIoc::new("d41d8cd98f00b204e9800998ecf8427e", IocType::Md5),
    ];
    let stats = vault.store().bulk_upsert(raws, "demo").await?;
    eprintln!("ingested {} indicators", stats.total());

    // 3. Search: all indicators, newest first (default ordering).
    let query = SearchQuery::builder().limit(100).build();
    let results = vault.search(&query).await?;
    eprintln!("search matched {} records", results.len());

    // 4. Export the same query as a STIX 2.1 bundle to stdout.
    let stdout = std::io::stdout();
    let count = vault
        .export(ExportFormat::Stix, &query, stdout.lock())
        .await?;
    eprintln!("\nexported {count} records as STIX 2.1");

    Ok(())
}
