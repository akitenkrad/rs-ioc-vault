//! URLhaus recent-URLs CSV adapter (abuse.ch, CC0-1.0).

use async_trait::async_trait;
use futures::StreamExt;
use ioc_vault_collect::{
    Collector, CollectionContext, CollectionResult, FeedType, SourceMetadata,
};
use ioc_vault_core::{IocType, RawIoc, Tlp};

const FEED_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";

/// Collector for the URLhaus recent-URLs CSV feed.
#[derive(Debug, Clone, Default)]
pub struct UrlhausCollector;

impl UrlhausCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for UrlhausCollector {
    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: "urlhaus",
            display_name: "URLhaus (abuse.ch)",
            url: FEED_URL,
            feed_type: FeedType::Csv,
            license: Some("CC0-1.0"),
            default_tlp: Tlp::Clear,
            default_confidence: 90,
            supports_incremental: true,
        }
    }

    async fn collect(&self, ctx: CollectionContext<'_>) -> anyhow::Result<CollectionResult> {
        let mut req = ctx.http_client.get(FEED_URL);
        if let Some(etag) = ctx.etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(lm) = ctx.last_modified {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm);
        }
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(CollectionResult::not_modified());
        }
        let resp = resp.error_for_status()?;
        let new_etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let new_last_modified = resp
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.text().await?;
        let items: Vec<RawIoc> = parse_urlhaus_csv(&body);
        let stream = futures::stream::iter(items).map(Ok).boxed();
        Ok(CollectionResult::from_stream(stream, new_etag, new_last_modified))
    }
}

/// Parse a URLhaus recent-URLs CSV body into [`RawIoc`]s.
///
/// The feed has commented header lines starting with `#`; data columns are
/// `id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`.
pub fn parse_urlhaus_csv(body: &str) -> Vec<RawIoc> {
    // Strip the leading `#`-commented lines so the csv reader sees clean rows.
    let data: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(data.as_bytes());

    let mut out = Vec::new();
    for result in rdr.records() {
        let Ok(rec) = result else { continue };
        // id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        let url = rec.get(2).map(str::trim).unwrap_or("");
        if url.is_empty() {
            continue;
        }
        let mut raw = RawIoc::new(url, IocType::Url);
        if let Some(seen) = rec.get(1).and_then(crate::parse_naive_utc) {
            raw.first_seen = Some(seen);
            raw.last_seen = Some(seen);
        }
        if let Some(threat) = rec.get(5).map(str::trim).filter(|s| !s.is_empty()) {
            raw.threat_type = Some(threat.to_string());
        }
        if let Some(tags) = rec.get(6).map(str::trim).filter(|s| !s.is_empty()) {
            raw.tags = tags
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect();
        }
        raw.confidence = Some(90);
        out.push(raw);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# URLhaus Database Dump (CSV - recent URLs only)
# Last updated: 2020-01-01 12:05:00 (UTC)
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2020-01-01 12:00:00","http://evil.example.com/a.exe","online","2020-01-01 12:00:00","malware_download","exe,emotet","https://urlhaus.abuse.ch/url/1/","reporterA"
"2","2020-01-02 08:30:00","http://bad.example.org/b.bin","offline","","malware_download","","https://urlhaus.abuse.ch/url/2/","reporterB"
"3","2020-01-03 00:00:00","https://phish.example.net/login","online","2020-01-03 00:00:00","phishing","phish","https://urlhaus.abuse.ch/url/3/","reporterC"
"#;

    #[test]
    fn parses_rows_skipping_comments() {
        let items = parse_urlhaus_csv(SAMPLE);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, "http://evil.example.com/a.exe");
        assert_eq!(items[0].ioc_type, IocType::Url);
        assert_eq!(items[0].threat_type.as_deref(), Some("malware_download"));
        assert_eq!(items[0].tags, vec!["exe".to_string(), "emotet".to_string()]);
        assert_eq!(items[0].confidence, Some(90));
        assert!(items[0].first_seen.is_some());
    }

    #[test]
    fn empty_tags_yield_no_tags() {
        let items = parse_urlhaus_csv(SAMPLE);
        assert!(items[1].tags.is_empty());
    }
}
