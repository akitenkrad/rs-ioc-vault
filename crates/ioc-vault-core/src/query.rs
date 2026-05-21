//! Search query model and builder.

use chrono::{DateTime, Duration, Utc};

use crate::types::IocType;

/// How the indicator value column should be matched.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum ValueMatcher {
    /// No value constraint.
    #[default]
    Any,
    Exact(String),
    Prefix(String),
    Contains(String),
    Regex(String),
    Cidr(ipnet::IpNet),
}

/// Result ordering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OrderBy {
    #[default]
    LastSeenDesc,
    LastSeenAsc,
    FirstSeenDesc,
    ConfidenceDesc,
    DecayScoreDesc,
}

/// A composable search request against the store.
#[derive(Debug, Default, Clone)]
pub struct SearchQuery {
    pub ioc_types: Vec<IocType>,
    pub sources: Vec<String>,
    pub threat_types: Vec<String>,
    pub malware_families: Vec<String>,
    pub tags: Vec<String>,
    pub cve_ids: Vec<String>,

    pub first_seen_after: Option<DateTime<Utc>>,
    pub first_seen_before: Option<DateTime<Utc>>,
    pub last_seen_after: Option<DateTime<Utc>>,
    pub last_seen_before: Option<DateTime<Utc>>,

    pub min_confidence: Option<u8>,
    pub min_decay_score: Option<f32>,

    pub value_match: ValueMatcher,
    pub fts_query: Option<String>,

    pub include_allowlisted: bool,

    pub order_by: OrderBy,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl SearchQuery {
    /// Start building a query.
    pub fn builder() -> SearchQueryBuilder {
        SearchQueryBuilder::default()
    }
}

/// Fluent builder for [`SearchQuery`].
#[derive(Debug, Default, Clone)]
pub struct SearchQueryBuilder {
    query: SearchQuery,
}

impl SearchQueryBuilder {
    pub fn ioc_type(mut self, t: IocType) -> Self {
        self.query.ioc_types.push(t);
        self
    }

    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.query.sources.push(s.into());
        self
    }

    pub fn threat_type(mut self, s: impl Into<String>) -> Self {
        self.query.threat_types.push(s.into());
        self
    }

    pub fn malware_family(mut self, s: impl Into<String>) -> Self {
        self.query.malware_families.push(s.into());
        self
    }

    pub fn tag(mut self, s: impl Into<String>) -> Self {
        self.query.tags.push(s.into());
        self
    }

    pub fn cve_id(mut self, s: impl Into<String>) -> Self {
        self.query.cve_ids.push(s.into());
        self
    }

    pub fn first_seen_after(mut self, t: DateTime<Utc>) -> Self {
        self.query.first_seen_after = Some(t);
        self
    }

    pub fn last_seen_after(mut self, t: DateTime<Utc>) -> Self {
        self.query.last_seen_after = Some(t);
        self
    }

    pub fn last_seen_before(mut self, t: DateTime<Utc>) -> Self {
        self.query.last_seen_before = Some(t);
        self
    }

    /// Constrain to indicators seen within the given window before now.
    pub fn last_seen_within(mut self, window: Duration) -> Self {
        self.query.last_seen_after = Some(Utc::now() - window);
        self
    }

    pub fn min_confidence(mut self, c: u8) -> Self {
        self.query.min_confidence = Some(c);
        self
    }

    pub fn min_decay_score(mut self, d: f32) -> Self {
        self.query.min_decay_score = Some(d);
        self
    }

    pub fn value_match(mut self, m: ValueMatcher) -> Self {
        self.query.value_match = m;
        self
    }

    pub fn exact(self, v: impl Into<String>) -> Self {
        self.value_match(ValueMatcher::Exact(v.into()))
    }

    pub fn cidr(self, net: ipnet::IpNet) -> Self {
        self.value_match(ValueMatcher::Cidr(net))
    }

    pub fn fts(mut self, q: impl Into<String>) -> Self {
        self.query.fts_query = Some(q.into());
        self
    }

    pub fn include_allowlisted(mut self, yes: bool) -> Self {
        self.query.include_allowlisted = yes;
        self
    }

    pub fn order_by(mut self, o: OrderBy) -> Self {
        self.query.order_by = o;
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.query.limit = Some(n);
        self
    }

    pub fn offset(mut self, n: usize) -> Self {
        self.query.offset = Some(n);
        self
    }

    pub fn build(self) -> SearchQuery {
        self.query
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_accumulates_filters() {
        let q = SearchQuery::builder()
            .ioc_type(IocType::Ipv4)
            .source("urlhaus")
            .source("threatfox")
            .threat_type("c2")
            .min_confidence(70)
            .limit(1000)
            .build();
        assert_eq!(q.ioc_types, vec![IocType::Ipv4]);
        assert_eq!(q.sources, vec!["urlhaus", "threatfox"]);
        assert_eq!(q.min_confidence, Some(70));
        assert_eq!(q.limit, Some(1000));
        assert_eq!(q.order_by, OrderBy::LastSeenDesc);
    }
}
