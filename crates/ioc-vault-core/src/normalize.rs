//! Value normalization and dedup-hash computation.
//!
//! Normalization rules follow §4.2 of the design document. The normalized
//! value plus its [`IocType`] are hashed into a `value_hash` that serves as
//! the dedup key across sources.

use std::net::{Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::types::IocType;

/// Normalize a raw indicator value for the given type.
///
/// Returns a canonical string suitable for storage and comparison.
pub fn normalize(ioc_type: IocType, raw: &str) -> Result<String, CoreError> {
    let trimmed = raw.trim();
    let err = |reason: &str| CoreError::Normalize {
        ioc_type,
        value: raw.to_string(),
        reason: reason.to_string(),
    };

    match ioc_type {
        IocType::Ipv4 => {
            // Parse each octet as decimal so leading zeros are stripped
            // ("192.168.001.001" -> "192.168.1.1"); std's parser rejects them.
            let octets: Vec<&str> = trimmed.split('.').collect();
            if octets.len() != 4 {
                return Err(err("invalid IPv4 address"));
            }
            let mut parsed = [0u8; 4];
            for (slot, part) in parsed.iter_mut().zip(octets) {
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(err("invalid IPv4 address"));
                }
                *slot = part.parse().map_err(|_| err("octet out of range"))?;
            }
            Ok(Ipv4Addr::from(parsed).to_string())
        }
        IocType::Ipv6 => {
            // RFC 5952 compressed form is what `Ipv6Addr::to_string` produces.
            let ip: Ipv6Addr = trimmed.parse().map_err(|_| err("invalid IPv6 address"))?;
            Ok(ip.to_string())
        }
        IocType::Cidr => {
            let net: ipnet::IpNet = trimmed.parse().map_err(|_| err("invalid CIDR"))?;
            // `IpNet::to_string` emits the canonical network/prefix form.
            Ok(net.trunc().to_string())
        }
        IocType::Domain => normalize_domain(trimmed).ok_or_else(|| err("invalid domain")),
        IocType::Url => normalize_url(trimmed).ok_or_else(|| err("invalid URL")),
        IocType::EmailAddress => {
            let (local, domain) = trimmed
                .rsplit_once('@')
                .ok_or_else(|| err("missing '@' in email address"))?;
            if local.is_empty() {
                return Err(err("empty local part"));
            }
            let domain = normalize_domain(domain).ok_or_else(|| err("invalid email domain"))?;
            Ok(format!("{local}@{domain}"))
        }
        IocType::Md5 => normalize_hex(trimmed, 32).ok_or_else(|| err("invalid MD5")),
        IocType::Sha1 => normalize_hex(trimmed, 40).ok_or_else(|| err("invalid SHA-1")),
        IocType::Sha256 => normalize_hex(trimmed, 64).ok_or_else(|| err("invalid SHA-256")),
        IocType::Sha512 => normalize_hex(trimmed, 128).ok_or_else(|| err("invalid SHA-512")),
        IocType::Asn => {
            let digits = trimmed.trim_start_matches(['A', 'S', 'a', 's']);
            let n: u32 = digits.parse().map_err(|_| err("invalid ASN"))?;
            Ok(n.to_string())
        }
        // Types without a strict canonical form: trim only.
        IocType::Ja3
        | IocType::Ja3s
        | IocType::Ssdeep
        | IocType::FilePath
        | IocType::Mutex
        | IocType::RegistryKey
        | IocType::YaraRule
        | IocType::BitcoinAddress
        | IocType::UserAgent => {
            if trimmed.is_empty() {
                Err(err("empty value"))
            } else {
                Ok(trimmed.to_string())
            }
        }
    }
}

/// Punycode + lowercase + strip a single trailing dot.
fn normalize_domain(input: &str) -> Option<String> {
    let host = input.trim_end_matches('.').trim();
    if host.is_empty() {
        return None;
    }
    let ascii = idna::domain_to_ascii(host).ok()?;
    if ascii.is_empty() { None } else { Some(ascii) }
}

/// Lowercase scheme, punycode host, drop fragment.
fn normalize_url(input: &str) -> Option<String> {
    let mut url = url::Url::parse(input).ok()?;
    url.set_fragment(None);
    // `url` already lowercases the scheme and IDNA-encodes the host on parse.
    Some(url.to_string())
}

/// Validate a fixed-length hex string and return its lowercase form.
fn normalize_hex(input: &str, expected_len: usize) -> Option<String> {
    if input.len() != expected_len || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(input.to_ascii_lowercase())
}

/// Compute the dedup hash `SHA-256(type || ":" || value)` as lowercase hex.
///
/// `value` must already be normalized via [`normalize`].
pub fn value_hash(ioc_type: IocType, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ioc_type.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_strips_leading_zeros() {
        assert_eq!(normalize(IocType::Ipv4, "192.168.001.001").unwrap(), "192.168.1.1");
    }

    #[test]
    fn ipv6_is_compressed() {
        assert_eq!(
            normalize(IocType::Ipv6, "2001:0db8:0000:0000:0000:0000:0000:0001").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn domain_lowercased_and_trailing_dot_removed() {
        assert_eq!(normalize(IocType::Domain, "Evil.Example.COM.").unwrap(), "evil.example.com");
    }

    #[test]
    fn domain_punycode() {
        assert_eq!(normalize(IocType::Domain, "müller.example").unwrap(), "xn--mller-kva.example");
    }

    #[test]
    fn hashes_lowercased() {
        assert_eq!(
            normalize(IocType::Sha256, &"A".repeat(64)).unwrap(),
            "a".repeat(64)
        );
    }

    #[test]
    fn bad_hash_rejected() {
        assert!(normalize(IocType::Md5, "deadbeef").is_err());
    }

    #[test]
    fn asn_strips_prefix() {
        assert_eq!(normalize(IocType::Asn, "AS15169").unwrap(), "15169");
    }

    #[test]
    fn email_domain_normalized() {
        assert_eq!(
            normalize(IocType::EmailAddress, "User@Example.COM").unwrap(),
            "User@example.com"
        );
    }

    #[test]
    fn value_hash_is_stable_and_type_scoped() {
        let a = value_hash(IocType::Domain, "evil.example.com");
        let b = value_hash(IocType::Domain, "evil.example.com");
        let c = value_hash(IocType::Url, "evil.example.com");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
