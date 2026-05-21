//! `rs-ioc-vault` — the public facade tying the store and collectors together.
//!
//! Construct an [`IocVault`] via [`IocVault::builder`], register collectors,
//! then drive updates with [`IocVault::update_source`] / [`IocVault::update_all`]
//! and read with [`IocVault::lookup`].

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use futures::StreamExt;
use ioc_vault_collect::{Collector, CollectionContext};
use ioc_vault_store::IocStore;

// Re-exports for downstream consumers (includes `RawIoc`, `IocRecord`, ...).
pub use ioc_vault_core::*;
pub use ioc_vault_collect::{Collector as CollectorTrait, FeedType, SourceMetadata};
pub use ioc_vault_export::ExportFormat;
pub use ioc_vault_store::{IocStore as Store, SourceInfo};

const USER_AGENT: &str = "ioc-vault/0.1";

/// The top-level IoC vault: a store plus a registry of collectors.
pub struct IocVault {
    store: IocStore,
    collectors: HashMap<String, Box<dyn Collector>>,
    http: reqwest::Client,
}

/// Options controlling an update run.
#[derive(Debug, Clone, Default)]
pub struct UpdateOptions {
    /// Only fetch indicators updated since this instant (incremental).
    pub since: Option<DateTime<Utc>>,
}

impl UpdateOptions {
    /// Build options requesting the last `n` days.
    pub fn since_days(n: i64) -> Self {
        Self {
            since: Some(Utc::now() - Duration::days(n)),
        }
    }
}

/// Per-source outcome of an update run.
#[derive(Debug, Clone)]
pub struct SourceReport {
    pub source: String,
    pub added: u64,
    pub updated: u64,
    pub skipped: bool,
}

/// Aggregate outcome of [`IocVault::update_all`].
#[derive(Debug, Clone)]
pub struct UpdateReport {
    pub per_source: Vec<SourceReport>,
}

/// Builder for [`IocVault`].
#[derive(Default)]
pub struct IocVaultBuilder {
    db_path: Option<PathBuf>,
    in_memory: bool,
    collectors: Vec<Box<dyn Collector>>,
}

impl IocVaultBuilder {
    /// Use a file-backed database at `path`.
    pub fn database(mut self, path: impl Into<PathBuf>) -> Self {
        self.db_path = Some(path.into());
        self.in_memory = false;
        self
    }

    /// Use an ephemeral in-memory database.
    pub fn in_memory(mut self) -> Self {
        self.in_memory = true;
        self
    }

    /// Register a collector (keyed by its `metadata().name`).
    pub fn with_collector(mut self, collector: Box<dyn Collector>) -> Self {
        self.collectors.push(collector);
        self
    }

    /// Register the default adapters enabled at compile time.
    pub fn with_default_collectors(mut self) -> Self {
        #[cfg(feature = "default-adapters")]
        {
            #[cfg(feature = "urlhaus")]
            {
                self.collectors
                    .push(Box::new(ioc_vault_adapters::UrlhausCollector::new()));
            }
            #[cfg(feature = "threatfox")]
            {
                self.collectors
                    .push(Box::new(ioc_vault_adapters::ThreatFoxCollector::new()));
            }
            #[cfg(feature = "cisa-kev")]
            {
                self.collectors
                    .push(Box::new(ioc_vault_adapters::CisaKevCollector::new()));
            }
        }
        self
    }

    /// Open the store, run migrations, and assemble the vault.
    pub async fn build(self) -> anyhow::Result<IocVault> {
        let store = if self.in_memory {
            IocStore::open_in_memory().await?
        } else {
            let path = self
                .db_path
                .ok_or_else(|| anyhow::anyhow!("no database path set (call .database or .in_memory)"))?;
            IocStore::open(path).await?
        };
        store.migrate().await?;

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .build()?;

        let mut collectors = HashMap::new();
        for c in self.collectors {
            let name = c.metadata().name.to_string();
            collectors.insert(name, c);
        }

        // Persist a source row for each registered collector.
        for c in collectors.values() {
            let m = c.metadata();
            store
                .register_source(m.name, m.url, m.feed_type.as_str(), m.default_confidence, m.default_tlp)
                .await?;
        }

        Ok(IocVault { store, collectors, http })
    }
}

impl IocVault {
    /// Begin building a vault.
    pub fn builder() -> IocVaultBuilder {
        IocVaultBuilder::default()
    }

    /// Borrow the underlying store.
    pub fn store(&self) -> &IocStore {
        &self.store
    }

    /// Names of all registered collectors.
    pub fn collector_names(&self) -> Vec<String> {
        self.collectors.keys().cloned().collect()
    }

    /// Look up a single indicator by value.
    pub async fn lookup(&self, value: &str) -> anyhow::Result<Option<IocRecord>> {
        Ok(self.store.lookup(value).await?)
    }

    /// Execute a composable search query.
    pub async fn search(&self, q: &SearchQuery) -> anyhow::Result<Vec<IocRecord>> {
        Ok(self.store.search(q).await?)
    }

    /// Run `q`, serialize the matching records in `format` to `w`, and return
    /// the number of records written.
    pub async fn export<W: std::io::Write>(
        &self,
        format: ExportFormat,
        q: &SearchQuery,
        w: W,
    ) -> anyhow::Result<usize> {
        let records = self.search(q).await?;
        ioc_vault_export::write(format, &records, w)?;
        Ok(records.len())
    }

    /// Recompute time-decay scores for every stored IoC; returns rows updated.
    pub async fn apply_decay(&self, model: &DecayModel) -> anyhow::Result<usize> {
        Ok(self.store.apply_decay(model).await?)
    }

    /// Update a single source by name.
    pub async fn update_source(
        &self,
        name: &str,
        opts: &UpdateOptions,
    ) -> anyhow::Result<SourceReport> {
        let collector = self
            .collectors
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown collector: {name}"))?;

        // KEV is special-cased: ingest the catalog into the `cves` table.
        #[cfg(feature = "cisa-kev")]
        if name == "cisa-kev" {
            return self.update_kev(name, opts).await;
        }

        let started = Utc::now();
        let result = self.run_collect(name, collector.as_ref(), opts).await;
        match result {
            Ok(report) => Ok(report),
            Err(e) => {
                let finished = Utc::now();
                let _ = self
                    .store
                    .record_run(name, started, finished, "failed", 0, 0, Some(&e.to_string()))
                    .await;
                Err(e)
            }
        }
    }

    async fn run_collect(
        &self,
        name: &str,
        collector: &dyn Collector,
        opts: &UpdateOptions,
    ) -> anyhow::Result<SourceReport> {
        let started = Utc::now();
        let cache = self.store.get_source_cache(name).await?.unwrap_or((None, None));
        let ctx = CollectionContext {
            since: opts.since,
            etag: cache.0.as_deref(),
            last_modified: cache.1.as_deref(),
            http_client: &self.http,
        };
        let result = collector.collect(ctx).await?;

        if result.not_modified {
            let finished = Utc::now();
            self.store
                .record_run(name, started, finished, "skipped", 0, 0, None)
                .await?;
            return Ok(SourceReport {
                source: name.to_string(),
                added: 0,
                updated: 0,
                skipped: true,
            });
        }

        let mut stream = result.stream;
        let mut raws: Vec<RawIoc> = Vec::new();
        while let Some(item) = stream.next().await {
            raws.push(item?);
        }

        let stats = self.store.bulk_upsert(raws, name).await?;
        self.store
            .update_source_cache(name, result.new_etag.as_deref(), result.new_last_modified.as_deref())
            .await?;
        let finished = Utc::now();
        self.store
            .record_run(name, started, finished, "success", stats.added, stats.updated, None)
            .await?;

        Ok(SourceReport {
            source: name.to_string(),
            added: stats.added,
            updated: stats.updated,
            skipped: false,
        })
    }

    /// Fetch and ingest the CISA KEV catalog into the `cves` table.
    #[cfg(feature = "cisa-kev")]
    async fn update_kev(&self, name: &str, _opts: &UpdateOptions) -> anyhow::Result<SourceReport> {
        let started = Utc::now();
        let res: anyhow::Result<u64> = async {
            let resp = self
                .http
                .get(ioc_vault_adapters::cisa_kev::FEED_URL)
                .send()
                .await?
                .error_for_status()?;
            let bytes = resp.bytes().await?;
            let entries = ioc_vault_adapters::parse_kev(&bytes)?;
            let mut count = 0u64;
            for e in &entries {
                let date = if e.date_added.is_empty() {
                    None
                } else {
                    Some(e.date_added.as_str())
                };
                self.store.upsert_cve(&e.cve_id, date, true).await?;
                count += 1;
            }
            Ok(count)
        }
        .await;

        let finished = Utc::now();
        match res {
            Ok(count) => {
                self.store
                    .update_source_cache(name, None, None)
                    .await?;
                self.store
                    .record_run(name, started, finished, "success", count, 0, None)
                    .await?;
                Ok(SourceReport {
                    source: name.to_string(),
                    added: count,
                    updated: 0,
                    skipped: false,
                })
            }
            Err(e) => {
                let _ = self
                    .store
                    .record_run(name, started, finished, "failed", 0, 0, Some(&e.to_string()))
                    .await;
                Err(e)
            }
        }
    }

    /// Update every registered collector.
    pub async fn update_all(&self, opts: &UpdateOptions) -> anyhow::Result<UpdateReport> {
        let mut per_source = Vec::new();
        let mut names: Vec<String> = self.collectors.keys().cloned().collect();
        names.sort();
        for name in names {
            match self.update_source(&name, opts).await {
                Ok(report) => per_source.push(report),
                Err(e) => {
                    tracing::warn!(source = %name, error = %e, "source update failed");
                    per_source.push(SourceReport {
                        source: name,
                        added: 0,
                        updated: 0,
                        skipped: true,
                    });
                }
            }
        }
        Ok(UpdateReport { per_source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioc_vault_collect::{CollectionResult, FeedType, SourceMetadata};
    use ioc_vault_core::{IocType, Tlp};

    struct FakeCollector;

    #[async_trait]
    impl Collector for FakeCollector {
        fn metadata(&self) -> SourceMetadata {
            SourceMetadata {
                name: "fake",
                display_name: "Fake",
                url: "https://example/fake",
                feed_type: FeedType::Csv,
                license: None,
                default_tlp: Tlp::Clear,
                default_confidence: 50,
                supports_incremental: false,
            }
        }

        async fn collect(
            &self,
            _ctx: CollectionContext<'_>,
        ) -> anyhow::Result<CollectionResult> {
            let items = vec![
                RawIoc::new("203.0.113.7", IocType::Ipv4),
                RawIoc::new("evil.example.com", IocType::Domain),
            ];
            let stream = futures::stream::iter(items).map(Ok).boxed();
            Ok(CollectionResult::from_stream(stream, Some("etag-x".into()), None))
        }
    }

    #[tokio::test]
    async fn update_source_adds_and_lookup_finds() {
        let vault = IocVault::builder()
            .in_memory()
            .with_collector(Box::new(FakeCollector))
            .build()
            .await
            .unwrap();

        let report = vault.update_source("fake", &UpdateOptions::default()).await.unwrap();
        assert_eq!(report.added, 2);
        assert!(!report.skipped);

        let found = vault.lookup("203.0.113.7").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().ioc_type, IocType::Ipv4);

        // Cache validator was persisted.
        let cache = vault.store().get_source_cache("fake").await.unwrap().unwrap();
        assert_eq!(cache.0.as_deref(), Some("etag-x"));
    }

    #[tokio::test]
    async fn update_all_reports_each_source() {
        let vault = IocVault::builder()
            .in_memory()
            .with_collector(Box::new(FakeCollector))
            .build()
            .await
            .unwrap();
        let report = vault.update_all(&UpdateOptions::default()).await.unwrap();
        assert_eq!(report.per_source.len(), 1);
        assert_eq!(report.per_source[0].source, "fake");
        assert_eq!(report.per_source[0].added, 2);
    }
}
