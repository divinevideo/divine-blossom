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
