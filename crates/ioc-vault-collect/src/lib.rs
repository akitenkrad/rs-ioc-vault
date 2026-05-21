//! Collector plugin abstraction (design §6).
//!
//! A [`Collector`] fetches indicators from one OSINT source and yields a
//! stream of [`RawIoc`]. Differential fetch context (ETag / `since`) is passed
//! in via [`CollectionContext`]; the result carries refreshed cache validators.

use std::pin::Pin;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::Stream;
use ioc_vault_core::{RawIoc, Tlp};

/// A stream of raw indicators produced by a collector.
pub type IocStream = Pin<Box<dyn Stream<Item = anyhow::Result<RawIoc>> + Send>>;

/// The wire format a source delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedType {
    Csv,
    Json,
    Stix,
    Misp,
    Taxii,
    Html,
    PlainText,
    Unknown,
}

impl FeedType {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedType::Csv => "csv",
            FeedType::Json => "json",
            FeedType::Stix => "stix",
            FeedType::Misp => "misp",
            FeedType::Taxii => "taxii",
            FeedType::Html => "html",
            FeedType::PlainText => "text",
            FeedType::Unknown => "unknown",
        }
    }
}

/// Static descriptor of a source, used for registration and reporting.
#[derive(Debug, Clone)]
pub struct SourceMetadata {
    pub name: &'static str,
    pub display_name: &'static str,
    pub url: &'static str,
    pub feed_type: FeedType,
    pub license: Option<&'static str>,
    pub default_tlp: Tlp,
    pub default_confidence: u8,
    /// Whether `since`-based differential fetch is supported.
    pub supports_incremental: bool,
}

/// Per-run fetch context handed to [`Collector::collect`].
#[derive(Debug, Clone)]
pub struct CollectionContext<'a> {
    pub since: Option<DateTime<Utc>>,
    pub etag: Option<&'a str>,
    pub last_modified: Option<&'a str>,
    pub http_client: &'a reqwest::Client,
}

/// Result of a collection run.
pub struct CollectionResult {
    pub stream: IocStream,
    pub new_etag: Option<String>,
    pub new_last_modified: Option<String>,
    /// True when the source replied 304 Not Modified.
    pub not_modified: bool,
}

impl CollectionResult {
    /// Build a 304 result with an empty stream.
    pub fn not_modified() -> Self {
        Self {
            stream: Box::pin(futures::stream::empty()),
            new_etag: None,
            new_last_modified: None,
            not_modified: true,
        }
    }

    /// Build a result from a ready stream with optional cache validators.
    pub fn from_stream(
        stream: IocStream,
        new_etag: Option<String>,
        new_last_modified: Option<String>,
    ) -> Self {
        Self {
            stream,
            new_etag,
            new_last_modified,
            not_modified: false,
        }
    }
}

/// Health of a source endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// A pluggable OSINT source.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Static descriptor (name, url, defaults).
    fn metadata(&self) -> SourceMetadata;

    /// Fetch indicators updated since `ctx.since` (or all if `None`).
    ///
    /// Implementations should honor `If-None-Match` / `If-Modified-Since`
    /// using the validators in `ctx` and return [`CollectionResult::not_modified`]
    /// on HTTP 304.
    async fn collect(&self, ctx: CollectionContext<'_>) -> anyhow::Result<CollectionResult>;

    /// Optional reachability / auth check.
    async fn health(&self, _http: &reqwest::Client) -> anyhow::Result<HealthStatus> {
        Ok(HealthStatus::Unknown)
    }
}
