//! Time-decay model for indicator confidence (design §11.2).
//!
//! Each [`IocType`] is assigned a *half-life* in days. The decay score is
//! computed with proper half-life semantics: `score(age) = 0.5 ^ (age / τ)`,
//! so at `age == τ` the score is exactly `0.5`. Scores are clamped to
//! `0.0..=1.0`.

use crate::types::IocType;

/// Per-type half-lives (in days) used to compute time-decay scores.
///
/// `Default` matches design §11.2:
/// - IPv4/IPv6: 14 days (dynamic allocation / fast flux)
/// - Domain: 30 days
/// - URL: 7 days
/// - Hashes (MD5/SHA1/SHA256/SHA512): 365 days (sample hashes are long-lived)
/// - JA3/JA3S: 90 days
/// - everything else: `default_half_life_days` (30)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecayModel {
    pub ipv4_half_life_days: f64,
    pub ipv6_half_life_days: f64,
    pub domain_half_life_days: f64,
    pub url_half_life_days: f64,
    pub hash_half_life_days: f64,
    pub ja3_half_life_days: f64,
    pub default_half_life_days: f64,
}

impl Default for DecayModel {
    fn default() -> Self {
        Self {
            ipv4_half_life_days: 14.0,
            ipv6_half_life_days: 14.0,
            domain_half_life_days: 30.0,
            url_half_life_days: 7.0,
            hash_half_life_days: 365.0,
            ja3_half_life_days: 90.0,
            default_half_life_days: 30.0,
        }
    }
}

impl DecayModel {
    /// Half-life (days) for `t`, or `None` for types that must never decay.
    ///
    /// All current [`IocType`] variants decay (there is no infinite-lifetime
    /// type), so this currently always returns `Some`.
    pub fn half_life_days(&self, t: IocType) -> Option<f64> {
        let days = match t {
            IocType::Ipv4 => self.ipv4_half_life_days,
            IocType::Ipv6 => self.ipv6_half_life_days,
            IocType::Domain => self.domain_half_life_days,
            IocType::Url => self.url_half_life_days,
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Sha512 => {
                self.hash_half_life_days
            }
            IocType::Ja3 | IocType::Ja3s => self.ja3_half_life_days,
            // CIDR, email, ssdeep, asn, file-path, mutex, registry-key,
            // yara-rule, bitcoin-address, user-agent → default.
            _ => self.default_half_life_days,
        };
        Some(days)
    }

    /// Decay score for `t` at `age_days`, in `0.0..=1.0`.
    ///
    /// Uses half-life semantics: `0.5 ^ (age / τ)` (score is `0.5` at `age == τ`).
    /// Types with no half-life (`half_life_days` returns `None`) never decay and
    /// score `1.0`.
    pub fn score(&self, t: IocType, age_days: f64) -> f32 {
        let half_life = match self.half_life_days(t) {
            Some(h) if h > 0.0 => h,
            // No decay (or non-positive half-life): treat as fully fresh.
            _ => return 1.0,
        };
        let age = age_days.max(0.0);
        let score = 0.5_f64.powf(age / half_life);
        score.clamp(0.0, 1.0) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_half_at_half_life() {
        let m = DecayModel::default();
        let hl = m.half_life_days(IocType::Ipv4).unwrap();
        let s = m.score(IocType::Ipv4, hl);
        assert!((s - 0.5).abs() < 1e-6, "expected ~0.5, got {s}");
    }

    #[test]
    fn score_is_one_at_zero_age() {
        let m = DecayModel::default();
        assert!((m.score(IocType::Domain, 0.0) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn score_quarters_at_two_half_lives() {
        let m = DecayModel::default();
        let hl = m.half_life_days(IocType::Url).unwrap();
        let s = m.score(IocType::Url, hl * 2.0);
        assert!((s - 0.25).abs() < 1e-6, "expected ~0.25, got {s}");
    }
}
