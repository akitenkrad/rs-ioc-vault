//! User configuration loaded from `~/.ioc-vault/config.toml`.
//!
//! The file is optional; a missing file yields the default (empty) config.
//! Per-source secrets such as the ThreatFox Auth-Key may be set here instead
//! of via environment variables. Environment variables take precedence.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// On-disk configuration. Every field is optional.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub threatfox: ThreatFoxConfig,
}

/// ThreatFox-specific settings.
#[derive(Debug, Default, Deserialize)]
pub struct ThreatFoxConfig {
    /// abuse.ch Auth-Key for the ThreatFox API (<https://auth.abuse.ch/>).
    pub auth_key: Option<String>,
}

impl Config {
    /// Load config from `path`, returning the default (empty) config when the
    /// file does not exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s)
                .with_context(|| format!("failed to parse config at {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => {
                Err(e).with_context(|| format!("failed to read config at {}", path.display()))
            }
        }
    }

    /// Resolve the ThreatFox Auth-Key. The `THREATFOX_AUTH_KEY` environment
    /// variable takes precedence over the config file; blank values are ignored.
    pub fn threatfox_auth_key(&self) -> Option<String> {
        std::env::var("THREATFOX_AUTH_KEY")
            .ok()
            .or_else(|| self.threatfox.auth_key.clone())
            .filter(|k| !k.trim().is_empty())
    }
}

/// Default config path: `~/.ioc-vault/config.toml`.
pub fn default_config_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".ioc-vault").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_threatfox_auth_key() {
        let cfg: Config = toml::from_str(
            r#"
            [threatfox]
            auth_key = "abc123"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.threatfox.auth_key.as_deref(), Some("abc123"));
    }

    #[test]
    fn empty_config_is_default() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.threatfox.auth_key.is_none());
    }

    #[test]
    fn missing_file_yields_default() {
        let cfg = Config::load(Path::new("/nonexistent/ioc-vault/config.toml")).unwrap();
        assert!(cfg.threatfox.auth_key.is_none());
    }
}
