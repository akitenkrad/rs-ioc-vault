//! Concrete OSINT source collectors for `rs-ioc-vault` (design §7).
//!
//! Each adapter lives in its own feature-gated module and provides:
//! - a pure `parse_*` function over an in-memory body (unit-testable, no I/O),
//! - a [`ioc_vault_collect::Collector`] impl that performs the HTTP fetch
//!   (honoring `If-None-Match` / `If-Modified-Since`) and wraps parsed items
//!   into an [`ioc_vault_collect::IocStream`].

#[cfg(feature = "urlhaus")]
pub mod urlhaus;

#[cfg(feature = "threatfox")]
pub mod threatfox;

#[cfg(feature = "cisa-kev")]
pub mod cisa_kev;

#[cfg(feature = "urlhaus")]
pub use urlhaus::{UrlhausCollector, parse_urlhaus_csv};

#[cfg(feature = "threatfox")]
pub use threatfox::{ThreatFoxCollector, parse_threatfox_json};

#[cfg(feature = "cisa-kev")]
pub use cisa_kev::{CisaKevCollector, KevEntry, parse_kev};

/// Parse a timestamp formatted like `2020-01-01 12:00:00` (assumed UTC).
#[allow(dead_code)]
pub(crate) fn parse_naive_utc(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone, Utc};
    let s = s.trim().trim_end_matches(" UTC").trim();
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| Utc.from_utc_datetime(&ndt))
}
