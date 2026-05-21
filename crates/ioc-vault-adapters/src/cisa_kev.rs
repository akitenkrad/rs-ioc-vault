//! CISA Known Exploited Vulnerabilities (KEV) catalog adapter.
//!
//! KEV entries are CVEs, not core [`ioc_vault_core::IocType`] values, so the
//! [`Collector::collect`] impl yields an **empty** IoC stream (it never fails
//! the contract) while the catalog itself is handled out-of-band: the facade
//! fetches the JSON and parses it with the public [`parse_kev`] function, then
//! upserts each [`KevEntry`] into the `cves` table directly.

use async_trait::async_trait;
use ioc_vault_collect::{
    Collector, CollectionContext, CollectionResult, FeedType, SourceMetadata,
};
use ioc_vault_core::Tlp;
use serde::Deserialize;

/// Public KEV catalog feed URL.
pub const FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Collector descriptor for the CISA KEV catalog.
///
/// `collect` returns an empty stream by design; use [`parse_kev`] to obtain
/// the catalog entries for CVE-table ingestion.
#[derive(Debug, Clone, Default)]
pub struct CisaKevCollector;

impl CisaKevCollector {
    pub fn new() -> Self {
        Self
    }
}

/// A single parsed KEV catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevEntry {
    pub cve_id: String,
    pub date_added: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct KevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<KevVuln>,
}

#[derive(Debug, Deserialize)]
struct KevVuln {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "dateAdded", default)]
    date_added: String,
    #[serde(rename = "vulnerabilityName", default)]
    vulnerability_name: String,
}

#[async_trait]
impl Collector for CisaKevCollector {
    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: "cisa-kev",
            display_name: "CISA Known Exploited Vulnerabilities",
            url: FEED_URL,
            feed_type: FeedType::Json,
            license: None,
            default_tlp: Tlp::Clear,
            default_confidence: 100,
            supports_incremental: false,
        }
    }

    async fn collect(&self, _ctx: CollectionContext<'_>) -> anyhow::Result<CollectionResult> {
        // KEV entries are CVEs, not IoC values: yield nothing here. The facade
        // ingests the catalog into the `cves` table via `parse_kev`.
        let stream = Box::pin(futures::stream::empty());
        Ok(CollectionResult::from_stream(stream, None, None))
    }
}

/// Parse a CISA KEV catalog JSON body into [`KevEntry`]s.
pub fn parse_kev(bytes: &[u8]) -> anyhow::Result<Vec<KevEntry>> {
    let catalog: KevCatalog = serde_json::from_slice(bytes)?;
    Ok(catalog
        .vulnerabilities
        .into_iter()
        .map(|v| KevEntry {
            cve_id: v.cve_id,
            date_added: v.date_added,
            name: v.vulnerability_name,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
             "vulnerabilityName": "Apache Log4j2 RCE", "dateAdded": "2021-12-10"},
            {"cveID": "CVE-2021-26855", "vendorProject": "Microsoft", "product": "Exchange",
             "vulnerabilityName": "Microsoft Exchange SSRF", "dateAdded": "2021-11-03"},
            {"cveID": "CVE-2017-0144", "vendorProject": "Microsoft", "product": "SMBv1",
             "vulnerabilityName": "EternalBlue", "dateAdded": "2022-03-25"}
        ]
    }"#;

    #[test]
    fn parses_catalog() {
        let entries = parse_kev(SAMPLE.as_bytes()).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].cve_id, "CVE-2021-44228");
        assert_eq!(entries[0].date_added, "2021-12-10");
        assert_eq!(entries[0].name, "Apache Log4j2 RCE");
    }
}
