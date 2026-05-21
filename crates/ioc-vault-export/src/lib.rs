//! Export IoC records to interchange formats: CSV, JSONL, STIX 2.1, MISP.
//!
//! All writers take a `&[IocRecord]` slice and a `std::io::Write` sink so the
//! caller controls buffering and the destination (file, stdout, in-memory).

use std::io::Write;
use std::str::FromStr;

use ioc_vault_core::{IocRecord, IocType, value_hash};
use serde_json::json;

/// Errors produced while exporting records.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown export format: {0}")]
    UnknownFormat(String),
}

/// Convenience result type for this crate.
pub type Result<T> = std::result::Result<T, ExportError>;

/// Supported export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Jsonl,
    Stix,
    Misp,
}

impl FromStr for ExportFormat {
    type Err = ExportError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "csv" => Ok(ExportFormat::Csv),
            "jsonl" => Ok(ExportFormat::Jsonl),
            "stix" | "stix2" | "stix2.1" => Ok(ExportFormat::Stix),
            "misp" => Ok(ExportFormat::Misp),
            other => Err(ExportError::UnknownFormat(other.to_string())),
        }
    }
}

/// Dispatch to the writer for `format`.
pub fn write<W: Write>(format: ExportFormat, records: &[IocRecord], w: W) -> Result<()> {
    match format {
        ExportFormat::Csv => write_csv(records, w),
        ExportFormat::Jsonl => write_jsonl(records, w),
        ExportFormat::Stix => write_stix(records, w),
        ExportFormat::Misp => write_misp(records, w),
    }
}

/// Write records as CSV with a fixed header row.
///
/// Columns: `value,ioc_type,confidence,tlp,threat_type,malware_family,
/// first_seen,last_seen,decay_score,tags,cve_refs,sources`. List columns
/// (tags, cve_refs, sources) are joined with `;`; timestamps are RFC3339.
pub fn write_csv<W: Write>(records: &[IocRecord], w: W) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(w);
    wtr.write_record([
        "value",
        "ioc_type",
        "confidence",
        "tlp",
        "threat_type",
        "malware_family",
        "first_seen",
        "last_seen",
        "decay_score",
        "tags",
        "cve_refs",
        "sources",
    ])?;
    for r in records {
        let sources = r
            .sources
            .iter()
            .map(|s| s.source_name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        wtr.write_record([
            r.value.as_str(),
            r.ioc_type.as_str(),
            &r.confidence.to_string(),
            r.tlp.as_str(),
            r.threat_type.as_deref().unwrap_or(""),
            r.malware_family.as_deref().unwrap_or(""),
            &r.first_seen.to_rfc3339(),
            &r.last_seen.to_rfc3339(),
            &r.decay_score.to_string(),
            &r.tags.join(";"),
            &r.cve_refs.join(";"),
            &sources,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Write one JSON object per line (newline-delimited JSON).
pub fn write_jsonl<W: Write>(records: &[IocRecord], mut w: W) -> Result<()> {
    for r in records {
        let line = serde_json::to_string(r)?;
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

/// Derive a UUID-shaped (8-4-4-4-12) string from a record's value hash.
///
/// Avoids a `uuid` dependency: we slice the 64-char SHA-256 hex of
/// `(type, value)` into the canonical UUID layout. Deterministic per IoC.
fn deterministic_uuid(record: &IocRecord) -> String {
    let h = value_hash(record.ioc_type, &record.value);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32],
    )
}

/// Escape single quotes for embedding inside a STIX pattern string literal.
fn stix_escape(v: &str) -> String {
    v.replace('\'', "\\'")
}

/// Build the STIX 2.1 comparison-expression pattern for a record.
fn stix_pattern(ioc_type: IocType, value: &str) -> String {
    let v = stix_escape(value);
    match ioc_type {
        IocType::Ipv4 => format!("[ipv4-addr:value = '{v}']"),
        IocType::Ipv6 => format!("[ipv6-addr:value = '{v}']"),
        IocType::Cidr => format!("[ipv4-addr:value = '{v}']"),
        IocType::Domain => format!("[domain-name:value = '{v}']"),
        IocType::Url => format!("[url:value = '{v}']"),
        IocType::EmailAddress => format!("[email-addr:value = '{v}']"),
        IocType::Md5 => format!("[file:hashes.'MD5' = '{v}']"),
        IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{v}']"),
        IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{v}']"),
        IocType::Sha512 => format!("[file:hashes.'SHA-512' = '{v}']"),
        _ => format!("[x-ioc:value = '{v}']"),
    }
}

/// STIX `indicator_types` open-vocabulary label (MVP: all malicious-activity).
const STIX_INDICATOR_TYPE: &str = "malicious-activity";

/// Write a STIX 2.1 bundle: one `indicator` SDO per record.
pub fn write_stix<W: Write>(records: &[IocRecord], w: W) -> Result<()> {
    let mut objects = Vec::with_capacity(records.len());
    for r in records {
        let id = format!("indicator--{}", deterministic_uuid(r));
        let mut labels: Vec<String> = Vec::new();
        if let Some(t) = &r.threat_type {
            labels.push(t.clone());
        }
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": id,
            "created": r.first_seen.to_rfc3339(),
            "modified": r.last_seen.to_rfc3339(),
            "valid_from": r.first_seen.to_rfc3339(),
            "name": r.value,
            "confidence": r.confidence,
            "pattern_type": "stix",
            "pattern": stix_pattern(r.ioc_type, &r.value),
            "labels": labels,
            "indicator_types": [STIX_INDICATOR_TYPE],
        }));
    }

    // Deterministic bundle id derived from the set of object ids.
    let bundle_id = {
        let joined: String = objects
            .iter()
            .filter_map(|o| o.get("id").and_then(|v| v.as_str()))
            .collect::<Vec<_>>()
            .join("|");
        let h = value_hash(IocType::Url, &joined);
        format!(
            "bundle--{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32],
        )
    };

    let bundle = json!({
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    });
    serde_json::to_writer(w, &bundle)?;
    Ok(())
}

/// Map an IoC type to a MISP attribute type.
fn misp_type(ioc_type: IocType) -> &'static str {
    match ioc_type {
        IocType::Ipv4 | IocType::Ipv6 => "ip-dst",
        IocType::Domain => "domain",
        IocType::Url => "url",
        IocType::Md5 => "md5",
        IocType::Sha1 => "sha1",
        IocType::Sha256 => "sha256",
        IocType::Sha512 => "sha512",
        IocType::EmailAddress => "email-src",
        _ => "other",
    }
}

/// Map an IoC type to a MISP attribute category.
fn misp_category(ioc_type: IocType) -> &'static str {
    match ioc_type {
        IocType::Ipv4 | IocType::Ipv6 | IocType::Cidr | IocType::Domain | IocType::Url => {
            "Network activity"
        }
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Sha512 => "Payload delivery",
        _ => "External analysis",
    }
}

/// Write a single MISP event JSON containing one attribute per record.
pub fn write_misp<W: Write>(records: &[IocRecord], w: W) -> Result<()> {
    let attributes: Vec<_> = records
        .iter()
        .map(|r| {
            json!({
                "type": misp_type(r.ioc_type),
                "category": misp_category(r.ioc_type),
                "value": r.value,
                "to_ids": true,
                "comment": r.threat_type.clone().unwrap_or_default(),
            })
        })
        .collect();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let event = json!({
        "Event": {
            "info": "rs-ioc-vault export",
            "date": today,
            "Attribute": attributes,
        }
    });
    serde_json::to_writer(w, &event)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ioc_vault_core::{SourceSighting, Tlp};

    fn sample_records() -> Vec<IocRecord> {
        let t = Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap();
        let sighting = SourceSighting {
            source_name: "urlhaus".into(),
            first_seen: t,
            last_seen: t,
            confidence: 80,
            raw_data: None,
        };
        vec![
            IocRecord {
                id: Some(1),
                value: "203.0.113.7".into(),
                ioc_type: IocType::Ipv4,
                first_seen: t,
                last_seen: t,
                confidence: 80,
                tlp: Tlp::Green,
                threat_type: Some("c2".into()),
                malware_family: None,
                tags: vec!["botnet".into(), "active".into()],
                sources: vec![sighting.clone()],
                cve_refs: vec![],
                decay_score: 0.9,
                is_allowlisted: false,
                metadata: serde_json::Value::Null,
            },
            IocRecord {
                id: Some(2),
                value: "evil.example.com".into(),
                ioc_type: IocType::Domain,
                first_seen: t,
                last_seen: t,
                confidence: 70,
                tlp: Tlp::Amber,
                threat_type: Some("phishing".into()),
                malware_family: Some("agenttesla".into()),
                tags: vec!["phish".into()],
                sources: vec![sighting.clone()],
                cve_refs: vec!["CVE-2024-1234".into()],
                decay_score: 0.5,
                is_allowlisted: false,
                metadata: serde_json::Value::Null,
            },
            IocRecord {
                id: Some(3),
                value: "d41d8cd98f00b204e9800998ecf8427e".into(),
                ioc_type: IocType::Md5,
                first_seen: t,
                last_seen: t,
                confidence: 60,
                tlp: Tlp::Clear,
                threat_type: None,
                malware_family: None,
                tags: vec![],
                sources: vec![sighting],
                cve_refs: vec![],
                decay_score: 0.3,
                is_allowlisted: false,
                metadata: serde_json::Value::Null,
            },
        ]
    }

    #[test]
    fn csv_has_header_and_rows() {
        let recs = sample_records();
        let mut buf = Vec::new();
        write_csv(&recs, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), recs.len() + 1);
        assert!(lines[0].starts_with("value,ioc_type,confidence"));
        assert!(lines[1].contains("203.0.113.7"));
        // tags joined with ';'
        assert!(lines[1].contains("botnet;active"));
    }

    #[test]
    fn jsonl_line_count_and_roundtrip() {
        let recs = sample_records();
        let mut buf = Vec::new();
        write_jsonl(&recs, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), recs.len());
        for (i, line) in lines.iter().enumerate() {
            let parsed: IocRecord = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.value, recs[i].value);
            assert_eq!(parsed.ioc_type, recs[i].ioc_type);
        }
    }

    #[test]
    fn stix_is_valid_bundle() {
        let recs = sample_records();
        let mut buf = Vec::new();
        write_stix(&recs, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["type"], "bundle");
        assert!(v["id"].as_str().unwrap().starts_with("bundle--"));
        let objects = v["objects"].as_array().unwrap();
        assert_eq!(objects.len(), recs.len());
        assert_eq!(objects[0]["type"], "indicator");
        assert_eq!(objects[0]["spec_version"], "2.1");
        assert!(
            objects[0]["pattern"]
                .as_str()
                .unwrap()
                .contains("203.0.113.7")
        );
        assert!(objects[0]["pattern"].as_str().unwrap().contains("ipv4-addr"));
        assert!(objects[2]["pattern"].as_str().unwrap().contains("MD5"));
    }

    #[test]
    fn misp_has_attributes() {
        let recs = sample_records();
        let mut buf = Vec::new();
        write_misp(&recs, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let attrs = v["Event"]["Attribute"].as_array().unwrap();
        assert_eq!(attrs.len(), recs.len());
        assert_eq!(attrs[0]["type"], "ip-dst");
        assert_eq!(attrs[0]["category"], "Network activity");
        assert_eq!(attrs[1]["type"], "domain");
        assert_eq!(attrs[2]["type"], "md5");
        assert_eq!(attrs[2]["category"], "Payload delivery");
    }

    #[test]
    fn dispatcher_routes_by_format() {
        let recs = sample_records();
        let mut buf = Vec::new();
        write(ExportFormat::Csv, &recs, &mut buf).unwrap();
        assert!(!buf.is_empty());
        assert_eq!(ExportFormat::from_str("stix2.1").unwrap(), ExportFormat::Stix);
        assert_eq!(ExportFormat::from_str("MISP").unwrap(), ExportFormat::Misp);
        assert!(ExportFormat::from_str("xml").is_err());
    }
}
