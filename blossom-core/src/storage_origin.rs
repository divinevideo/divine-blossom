//! Storage identity and rollout policy, independent of any provider SDK.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageProvider {
    Gcs,
    B2,
}

impl StorageProvider {
    pub fn name(self) -> &'static str {
        match self {
            Self::Gcs => "gcs",
            Self::B2 => "b2",
        }
    }

    pub fn b2_host(region: &str) -> Result<String, &'static str> {
        if region.is_empty()
            || region.len() > 63
            || region.starts_with('-')
            || region.ends_with('-')
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("invalid B2 region");
        }
        Ok(format!("s3.{region}.backblazeb2.com"))
    }
}

/// Version is the provider's opaque object generation/version, never an ETag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    pub provider: StorageProvider,
    pub bucket: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaReadPolicy {
    pub primary: StorageProvider,
    pub gcs_fallback_enabled: bool,
}

impl MediaReadPolicy {
    pub fn parse(primary: Option<&str>, fallback: Option<&str>) -> Result<Self, &'static str> {
        let primary = match primary.unwrap_or("gcs") {
            "gcs" => StorageProvider::Gcs,
            "b2" => StorageProvider::B2,
            _ => return Err("media_read_primary must be gcs or b2"),
        };
        let gcs_fallback_enabled = match fallback.unwrap_or("true") {
            "true" => true,
            "false" => false,
            _ => return Err("gcs_fallback_enabled must be true or false"),
        };
        Ok(Self {
            primary,
            gcs_fallback_enabled,
        })
    }

    pub fn should_fallback(self, status: u16) -> bool {
        self.primary == StorageProvider::B2
            && self.gcs_fallback_enabled
            && (status == 404 || (500..=599).contains(&status))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErasurePolicy {
    pub gcs_enabled: bool,
    pub fos_enabled: bool,
}

impl ErasurePolicy {
    pub fn parse(
        gcs_erasure: Option<&str>,
        fos_erasure: Option<&str>,
        b2_replica_enabled: bool,
        fos_active: bool,
    ) -> Result<Self, &'static str> {
        let gcs_enabled = match gcs_erasure.unwrap_or("true") {
            "true" => true,
            "false" => false,
            _ => return Err("gcs_erasure_enabled must be true or false"),
        };
        if !gcs_enabled && !b2_replica_enabled {
            return Err("gcs_erasure_enabled=false requires b2_replica_enabled=true");
        }
        let fos_enabled = match fos_erasure.unwrap_or("true") {
            "true" => true,
            "false" => false,
            _ => return Err("fos_erasure_enabled must be true or false"),
        };
        if !fos_enabled && fos_active {
            return Err("fos_erasure_enabled=false requires FOS read and write-back to be disabled");
        }
        Ok(Self {
            gcs_enabled,
            fos_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erasure_policy_defaults_on_and_fails_closed_on_unsafe_combinations() {
        assert_eq!(
            ErasurePolicy::parse(None, None, false, false).unwrap(),
            ErasurePolicy {
                gcs_enabled: true,
                fos_enabled: true,
            }
        );
        assert_eq!(
            ErasurePolicy::parse(Some("false"), Some("false"), true, false).unwrap(),
            ErasurePolicy {
                gcs_enabled: false,
                fos_enabled: false,
            }
        );
        assert!(ErasurePolicy::parse(Some("false"), None, false, false).is_err());
        assert!(ErasurePolicy::parse(None, Some("false"), true, true).is_err());
        assert!(ErasurePolicy::parse(Some("invalid"), None, true, false).is_err());
        assert!(ErasurePolicy::parse(None, Some("invalid"), true, false).is_err());
    }
}
