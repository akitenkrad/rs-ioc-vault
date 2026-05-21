//! Core data model for IoC records, following STIX 2.1 cyber-observable naming.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// The kind of indicator a value represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Cidr,
    Domain,
    Url,
    EmailAddress,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ja3,
    Ja3s,
    Ssdeep,
    Asn,
    FilePath,
    Mutex,
    RegistryKey,
    YaraRule,
    BitcoinAddress,
    UserAgent,
}

impl IocType {
    /// Stable kebab-case string used in the DB and exports.
    pub fn as_str(self) -> &'static str {
        match self {
            IocType::Ipv4 => "ipv4",
            IocType::Ipv6 => "ipv6",
            IocType::Cidr => "cidr",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::EmailAddress => "email-address",
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Sha512 => "sha512",
            IocType::Ja3 => "ja3",
            IocType::Ja3s => "ja3s",
            IocType::Ssdeep => "ssdeep",
            IocType::Asn => "asn",
            IocType::FilePath => "file-path",
            IocType::Mutex => "mutex",
            IocType::RegistryKey => "registry-key",
            IocType::YaraRule => "yara-rule",
            IocType::BitcoinAddress => "bitcoin-address",
            IocType::UserAgent => "user-agent",
        }
    }
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IocType {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = match s {
            "ipv4" => IocType::Ipv4,
            "ipv6" => IocType::Ipv6,
            "cidr" => IocType::Cidr,
            "domain" => IocType::Domain,
            "url" => IocType::Url,
            "email-address" => IocType::EmailAddress,
            "md5" => IocType::Md5,
            "sha1" => IocType::Sha1,
            "sha256" => IocType::Sha256,
            "sha512" => IocType::Sha512,
            "ja3" => IocType::Ja3,
            "ja3s" => IocType::Ja3s,
            "ssdeep" => IocType::Ssdeep,
            "asn" => IocType::Asn,
            "file-path" => IocType::FilePath,
            "mutex" => IocType::Mutex,
            "registry-key" => IocType::RegistryKey,
            "yara-rule" => IocType::YaraRule,
            "bitcoin-address" => IocType::BitcoinAddress,
            "user-agent" => IocType::UserAgent,
            other => {
                return Err(CoreError::UnknownVariant {
                    kind: "IocType",
                    value: other.to_string(),
                });
            }
        };
        Ok(t)
    }
}

/// Traffic Light Protocol marking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tlp {
    #[default]
    Clear,
    Green,
    Amber,
    AmberStrict,
    Red,
}

impl Tlp {
    pub fn as_str(self) -> &'static str {
        match self {
            Tlp::Clear => "clear",
            Tlp::Green => "green",
            Tlp::Amber => "amber",
            Tlp::AmberStrict => "amber-strict",
            Tlp::Red => "red",
        }
    }
}

impl fmt::Display for Tlp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Tlp {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = match s {
            "clear" | "white" => Tlp::Clear,
            "green" => Tlp::Green,
            "amber" => Tlp::Amber,
            "amber-strict" => Tlp::AmberStrict,
            "red" => Tlp::Red,
            other => {
                return Err(CoreError::UnknownVariant {
                    kind: "Tlp",
                    value: other.to_string(),
                });
            }
        };
        Ok(t)
    }
}

/// A single source's observation of an IoC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSighting {
    pub source_name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: u8,
    pub raw_data: Option<serde_json::Value>,
}

/// A normalized, deduplicated indicator with aggregated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRecord {
    /// DB row id, populated after persistence.
    pub id: Option<i64>,
    /// Normalized indicator value.
    pub value: String,
    pub ioc_type: IocType,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Aggregated confidence, 0-100.
    pub confidence: u8,
    pub tlp: Tlp,
    pub threat_type: Option<String>,
    pub malware_family: Option<String>,
    pub tags: Vec<String>,
    pub sources: Vec<SourceSighting>,
    pub cve_refs: Vec<String>,
    /// Time-decay score in 0.0..=1.0.
    pub decay_score: f32,
    pub is_allowlisted: bool,
    pub metadata: serde_json::Value,
}

/// An indicator as produced by a collector, prior to normalization/aggregation.
#[derive(Debug, Clone)]
pub struct RawIoc {
    pub value: String,
    pub ioc_type: IocType,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub confidence: Option<u8>,
    pub threat_type: Option<String>,
    pub malware_family: Option<String>,
    pub tags: Vec<String>,
    pub cve_refs: Vec<String>,
    pub raw: serde_json::Value,
}

impl RawIoc {
    /// Minimal constructor with empty/None optional fields.
    pub fn new(value: impl Into<String>, ioc_type: IocType) -> Self {
        Self {
            value: value.into(),
            ioc_type,
            first_seen: None,
            last_seen: None,
            confidence: None,
            threat_type: None,
            malware_family: None,
            tags: Vec::new(),
            cve_refs: Vec::new(),
            raw: serde_json::Value::Null,
        }
    }
}

/// A self-observed sighting recorded by the operating organization.
#[derive(Debug, Clone)]
pub struct Sighting {
    pub observed_at: DateTime<Utc>,
    pub observer: Option<String>,
    pub count: u32,
    pub context: Option<String>,
}

/// Relationship between an IoC and a CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Relationship {
    #[default]
    RelatedTo,
    Exploits,
    Indicates,
    Targets,
}

impl Relationship {
    pub fn as_str(self) -> &'static str {
        match self {
            Relationship::RelatedTo => "related-to",
            Relationship::Exploits => "exploits",
            Relationship::Indicates => "indicates",
            Relationship::Targets => "targets",
        }
    }
}

/// Outcome counts from a bulk upsert operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpsertStats {
    pub added: u64,
    pub updated: u64,
}

impl UpsertStats {
    pub fn total(&self) -> u64 {
        self.added + self.updated
    }
}
