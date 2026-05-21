//! Display-safety ("defanging") for IoC values.
//!
//! Threat indicators are, by definition, hostile. Rendering a live URL, IP
//! address, domain, or email address into a terminal, log file, ticket, or chat
//! window is a hazard: many of those surfaces auto-linkify such text, and a
//! single misclick or copy-paste can route an analyst straight to malware or a
//! phishing page.
//!
//! This module neutralizes that risk by *defanging* — rewriting the structural
//! characters that make a value actionable into inert, human-readable
//! placeholders, following the de-facto community convention (as used by tools
//! such as CyberChef):
//!
//! | original  | defanged |
//! |-----------|----------|
//! | `http`    | `hxxp`   |
//! | `https`   | `hxxps`  |
//! | `://`     | `[://]`  |
//! | `.`       | `[.]`    |
//! | `@`       | `[at]`   |
//! | `:` (IPv6)| `[:]`    |
//!
//! The transformation removes *clickability only*: the value stays legible and
//! could be re-fanged by reversing the substitutions, but it can no longer be
//! followed as a link. As a defense-in-depth measure every actionable type is
//! verified with [`is_defanged`], a strict checker that fails closed if any
//! live-link pattern survives the rewrite.

use crate::types::IocType;

/// Placeholder for a literal `.` in hostnames and addresses.
const DOT: &str = "[.]";
/// Placeholder for the `@` separator in email addresses and URL userinfo.
const AT: &str = "[at]";
/// Placeholder for the `://` scheme separator in URLs.
const SCHEME_SEP: &str = "[://]";
/// Placeholder for a literal `:` in IPv6 addresses.
const COLON: &str = "[:]";

/// Known URL schemes mapped to their conventional defanged spelling. Unlisted
/// schemes are left as-is and rely on [`SCHEME_SEP`] alone to break the link.
const SCHEME_MAP: &[(&str, &str)] = &[
    ("https", "hxxps"),
    ("http", "hxxp"),
    ("ftps", "fxps"),
    ("ftp", "fxp"),
];

/// Defang an IoC value for safe display, choosing the strategy from its type.
///
/// Actionable types (URLs, domains, IPv4/IPv6/CIDR, email addresses) are
/// rewritten so they can no longer be followed as a link. Non-actionable types
/// (hashes, ASNs, file paths, mutexes, …) contain nothing a terminal would
/// linkify and are returned unchanged.
///
/// The output for every actionable type is guaranteed to satisfy
/// [`is_defanged`] (enforced by a `debug_assert!` and the test suite).
pub fn defang(ioc_type: IocType, value: &str) -> String {
    let out = match ioc_type {
        IocType::Url => defang_url(value),
        IocType::Domain => value.replace('.', DOT),
        IocType::Ipv4 | IocType::Cidr => value.replace('.', DOT),
        IocType::Ipv6 => value.replace(':', COLON),
        IocType::EmailAddress => neutralize(value),
        // Hashes, ASNs, file paths, registry keys, … are not clickable links.
        _ => return value.to_string(),
    };
    debug_assert!(
        is_defanged(&out),
        "defang produced a value that still looks live: {out:?}"
    );
    out
}

/// Defang arbitrary text when the indicator type is not known.
///
/// Every transformation is applied unconditionally except dot-neutralization,
/// which is restricted to dots flanked by alphanumerics so that ordinary prose
/// and file paths stay legible while hostnames are still broken apart.
pub fn defang_auto(value: &str) -> String {
    // Break scheme separators first so the scheme names can be matched against
    // their defanged-separator form below.
    let mut out = value.replace("://", SCHEME_SEP);
    // Longest scheme first: `https` must win over its `http` prefix.
    for (live, safe) in SCHEME_MAP {
        out = out.replace(&format!("{live}{SCHEME_SEP}"), &format!("{safe}{SCHEME_SEP}"));
    }
    out = out.replace('@', AT);
    neutralize_inner_dots(&out)
}

/// Recursively defang every JSON *string* in place, leaving object keys,
/// numbers, booleans, and nulls untouched.
///
/// Intended for sanitizing machine-readable output (`json` / `jsonl`) so that
/// no live link survives anywhere in the document — not only the top-level
/// indicator value, but also nested feed payloads (`raw_data`) and `metadata`.
/// Each string is run through [`defang_auto`], which only neutralizes
/// host-like dots, so timestamps and ordinary text remain legible.
pub fn defang_json(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::String(s) => *s = defang_auto(s),
        Value::Array(items) => items.iter_mut().for_each(defang_json),
        Value::Object(map) => map.values_mut().for_each(defang_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Strict verifier: returns `true` only when `s` contains no pattern that a
/// terminal, browser, or reader is likely to treat as a live, clickable link.
///
/// A value is considered *live* if it contains any of:
/// - a raw `@` (email / URL userinfo separator),
/// - a scheme separator `://` immediately preceded by an alphanumeric, or
/// - a `.` flanked on both sides by alphanumerics (a bare `host.tld`).
///
/// Defanged placeholders (`[at]`, `[://]`, `[.]`, `[:]`) deliberately wrap the
/// dangerous characters in brackets, so they never trip these checks.
pub fn is_defanged(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len() {
        match chars[i] {
            '@' => return false,
            ':' => {
                // Live scheme separator: `<alnum>://`.
                if chars.get(i + 1) == Some(&'/')
                    && chars.get(i + 2) == Some(&'/')
                    && i > 0
                    && chars[i - 1].is_alphanumeric()
                {
                    return false;
                }
            }
            '.' => {
                let prev = i > 0 && chars[i - 1].is_alphanumeric();
                let next = chars.get(i + 1).is_some_and(|c| c.is_alphanumeric());
                if prev && next {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Defang a full URL: break the scheme separator, rename a known scheme, then
/// neutralize the remainder.
fn defang_url(value: &str) -> String {
    let rewritten = match value.find("://") {
        Some(idx) => {
            let (scheme, rest) = value.split_at(idx);
            format!("{}{SCHEME_SEP}{}", defang_scheme(scheme), &rest["://".len()..])
        }
        None => value.to_string(),
    };
    neutralize(&rewritten)
}

/// Map a known scheme to its defanged spelling; pass others through unchanged.
fn defang_scheme(scheme: &str) -> String {
    let lower = scheme.to_ascii_lowercase();
    for (live, safe) in SCHEME_MAP {
        if lower == *live {
            return (*safe).to_string();
        }
    }
    scheme.to_string()
}

/// Replace every `@` and `.` with their defanged placeholders.
fn neutralize(s: &str) -> String {
    s.replace('@', AT).replace('.', DOT)
}

/// Replace only the dots flanked by alphanumerics, leaving leading/trailing or
/// space-adjacent dots (prose, file extensions in paths) intact.
fn neutralize_inner_dots(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 8);
    for i in 0..chars.len() {
        if chars[i] == '.' {
            let prev = i > 0 && chars[i - 1].is_alphanumeric();
            let next = i + 1 < chars.len() && chars[i + 1].is_alphanumeric();
            if prev && next {
                out.push_str(DOT);
                continue;
            }
        }
        out.push(chars[i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_scheme_and_dots_are_neutralized() {
        assert_eq!(
            defang(IocType::Url, "http://evil.example.com/a.php"),
            "hxxp[://]evil[.]example[.]com/a[.]php"
        );
        assert_eq!(
            defang(IocType::Url, "https://bad.test/x"),
            "hxxps[://]bad[.]test/x"
        );
    }

    #[test]
    fn url_userinfo_at_is_defanged() {
        assert_eq!(
            defang(IocType::Url, "http://user@evil.test/"),
            "hxxp[://]user[at]evil[.]test/"
        );
    }

    #[test]
    fn unknown_scheme_still_broken_by_separator() {
        let out = defang(IocType::Url, "telnet://10.0.0.1");
        assert_eq!(out, "telnet[://]10[.]0[.]0[.]1");
        assert!(is_defanged(&out));
    }

    #[test]
    fn domain_dots_are_neutralized() {
        assert_eq!(defang(IocType::Domain, "evil.example.com"), "evil[.]example[.]com");
    }

    #[test]
    fn ipv4_and_cidr_dots_are_neutralized() {
        assert_eq!(defang(IocType::Ipv4, "203.0.113.7"), "203[.]0[.]113[.]7");
        assert_eq!(defang(IocType::Cidr, "10.0.0.0/8"), "10[.]0[.]0[.]0/8");
    }

    #[test]
    fn ipv6_colons_are_neutralized() {
        let out = defang(IocType::Ipv6, "2001:db8::1");
        assert_eq!(out, "2001[:]db8[:][:]1");
        assert!(is_defanged(&out));
    }

    #[test]
    fn email_at_and_dots_are_neutralized() {
        assert_eq!(
            defang(IocType::EmailAddress, "attacker@evil.example.com"),
            "attacker[at]evil[.]example[.]com"
        );
    }

    #[test]
    fn non_actionable_types_pass_through() {
        let hash = "a".repeat(64);
        assert_eq!(defang(IocType::Sha256, &hash), hash);
        assert_eq!(defang(IocType::Asn, "15169"), "15169");
        assert_eq!(defang(IocType::FilePath, r"C:\Temp\evil.exe"), r"C:\Temp\evil.exe");
    }

    #[test]
    fn is_defanged_flags_live_values() {
        assert!(!is_defanged("http://evil.com"));
        assert!(!is_defanged("evil.com"));
        assert!(!is_defanged("a@b"));
        assert!(!is_defanged("203.0.113.7"));
    }

    #[test]
    fn is_defanged_accepts_safe_values() {
        assert!(is_defanged("hxxp[://]evil[.]com"));
        assert!(is_defanged("attacker[at]evil[.]com"));
        assert!(is_defanged(&"a".repeat(64)));
        assert!(is_defanged("plain text with a period."));
    }

    #[test]
    fn every_actionable_type_yields_a_defanged_value() {
        let cases = [
            (IocType::Url, "https://a.b.c/d?e=f.g"),
            (IocType::Domain, "sub.evil.example"),
            (IocType::Ipv4, "1.2.3.4"),
            (IocType::Cidr, "192.168.0.0/16"),
            (IocType::Ipv6, "fe80::1"),
            (IocType::EmailAddress, "x@y.z"),
        ];
        for (t, v) in cases {
            assert!(is_defanged(&defang(t, v)), "type {t} value {v} not defanged");
        }
    }

    #[test]
    fn defang_auto_keeps_prose_dots_but_breaks_hosts() {
        assert_eq!(
            defang_auto("see http://evil.example.com now."),
            "see hxxp[://]evil[.]example[.]com now."
        );
        // Trailing sentence dot (space-adjacent) is preserved.
        assert!(defang_auto("done.").ends_with("done."));
    }

    #[test]
    fn defang_json_recurses_into_nested_strings() {
        let mut v = serde_json::json!({
            "value": "http://evil.example.com",
            "ioc_type": "url",
            "confidence": 80,
            "last_seen": "2026-05-22T12:34:56Z",
            "raw_data": {
                "url": "http://evil.example.com/x",
                "host": "evil.example.com",
                "tags": ["c2", "drop@evil.example.com"]
            }
        });
        defang_json(&mut v);
        assert_eq!(v["value"], "hxxp[://]evil[.]example[.]com");
        assert_eq!(v["raw_data"]["url"], "hxxp[://]evil[.]example[.]com/x");
        assert_eq!(v["raw_data"]["host"], "evil[.]example[.]com");
        assert_eq!(v["raw_data"]["tags"][1], "drop[at]evil[.]example[.]com");
        // Non-string scalars and timestamps are untouched.
        assert_eq!(v["confidence"], 80);
        assert_eq!(v["last_seen"], "2026-05-22T12:34:56Z");
        // Object keys are preserved.
        assert!(v["raw_data"].get("host").is_some());
    }
}
