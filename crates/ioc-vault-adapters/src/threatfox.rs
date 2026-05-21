//! ThreatFox API adapter (abuse.ch).

use async_trait::async_trait;
use futures::StreamExt;
use ioc_vault_collect::{
    Collector, CollectionContext, CollectionResult, FeedType, SourceMetadata,
};
use ioc_vault_core::{IocType, RawIoc, Tlp};
use serde::Deserialize;

const API_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

/// Collector for the ThreatFox `get_iocs` API.
#[derive(Debug, Clone, Default)]
pub struct ThreatFoxCollector;

impl ThreatFoxCollector {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Deserialize)]
struct ThreatFoxResponse {
    #[serde(default)]
    query_status: String,
    #[serde(default)]
    data: Vec<ThreatFoxEntry>,
}

#[derive(Debug, Deserialize)]
struct ThreatFoxEntry {
    ioc: String,
    ioc_type: String,
    #[serde(default)]
    threat_type: Option<String>,
    #[serde(default)]
    malware: Option<String>,
    #[serde(default)]
    confidence_level: Option<u8>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[async_trait]
impl Collector for ThreatFoxCollector {
    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: "threatfox",
            display_name: "ThreatFox (abuse.ch)",
            url: API_URL,
            feed_type: FeedType::Json,
            license: Some("CC0-1.0"),
            default_tlp: Tlp::Clear,
            default_confidence: 75,
            supports_incremental: true,
        }
    }

    async fn collect(&self, ctx: CollectionContext<'_>) -> anyhow::Result<CollectionResult> {
        // Derive a day window from `since`; default to the last day.
        let days = match ctx.since {
            Some(since) => {
                let delta = (chrono::Utc::now() - since).num_days();
                delta.clamp(1, 7) as u64
            }
            None => 1,
        };
        let payload = serde_json::json!({ "query": "get_iocs", "days": days });
        let resp = ctx
            .http_client
            .post(API_URL)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        let body = resp.bytes().await?;
        let items = parse_threatfox_json(&body)?;
        let stream = futures::stream::iter(items).map(Ok).boxed();
        Ok(CollectionResult::from_stream(stream, None, None))
    }
}

/// Parse a ThreatFox `get_iocs` JSON response body into [`RawIoc`]s.
///
/// Unknown `ioc_type` values are skipped. `ip:port` values are stripped of
/// their port and treated as IPv4.
pub fn parse_threatfox_json(body: &[u8]) -> anyhow::Result<Vec<RawIoc>> {
    let resp: ThreatFoxResponse = serde_json::from_slice(body)?;
    if !resp.query_status.is_empty() && resp.query_status != "ok" {
        anyhow::bail!("threatfox query_status: {}", resp.query_status);
    }
    let mut out = Vec::with_capacity(resp.data.len());
    for entry in resp.data {
        let (value, ioc_type) = match entry.ioc_type.as_str() {
            "ip:port" => {
                let ip = entry.ioc.split(':').next().unwrap_or(&entry.ioc).to_string();
                (ip, IocType::Ipv4)
            }
            "domain" => (entry.ioc.clone(), IocType::Domain),
            "url" => (entry.ioc.clone(), IocType::Url),
            "md5_hash" => (entry.ioc.clone(), IocType::Md5),
            "sha256_hash" => (entry.ioc.clone(), IocType::Sha256),
            _ => continue,
        };
        let mut raw = RawIoc::new(value, ioc_type);
        raw.threat_type = entry.threat_type;
        raw.malware_family = entry.malware.filter(|s| !s.is_empty());
        raw.confidence = entry.confidence_level.or(Some(75));
        raw.tags = entry.tags.unwrap_or_default();
        if let Some(seen) = entry.first_seen.as_deref().and_then(crate::parse_naive_utc) {
            raw.first_seen = Some(seen);
            raw.last_seen = Some(seen);
        }
        out.push(raw);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "query_status": "ok",
        "data": [
            {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware": "Cobalt Strike", "confidence_level": 100,
             "first_seen": "2021-05-01 10:00:00 UTC", "tags": ["cobaltstrike"]},
            {"ioc": "evil.example.com", "ioc_type": "domain", "threat_type": "payload_delivery",
             "malware": "Emotet", "confidence_level": 75, "first_seen": "2021-05-02 11:00:00 UTC",
             "tags": []},
            {"ioc": "44d88612fea8a8f36de82e1278abb02f", "ioc_type": "md5_hash",
             "malware": "", "confidence_level": 50, "first_seen": "2021-05-03 12:00:00 UTC"},
            {"ioc": "something", "ioc_type": "unknown_type", "malware": "x"}
        ]
    }"#;

    #[test]
    fn maps_types_and_strips_port() {
        let items = parse_threatfox_json(SAMPLE.as_bytes()).unwrap();
        // 4th entry (unknown_type) is skipped.
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, "1.2.3.4");
        assert_eq!(items[0].ioc_type, IocType::Ipv4);
        assert_eq!(items[0].malware_family.as_deref(), Some("Cobalt Strike"));
        assert_eq!(items[0].confidence, Some(100));
        assert_eq!(items[1].ioc_type, IocType::Domain);
        assert_eq!(items[2].ioc_type, IocType::Md5);
        // empty malware string is dropped.
        assert!(items[2].malware_family.is_none());
    }
}
