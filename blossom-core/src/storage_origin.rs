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

#[derive(Clone, Copy, Debug, Default)]
pub struct ErasurePolicyInputs<'a> {
    pub gcs_erasure: Option<&'a str>,
    pub fos_erasure: Option<&'a str>,
    pub b2_replica_enabled: Option<&'a str>,
    pub media_read_primary: Option<&'a str>,
    pub gcs_fallback_enabled: Option<&'a str>,
    pub derived_media_read_primary: Option<&'a str>,
    pub derived_media_gcs_fallback_enabled: Option<&'a str>,
    pub upload_service_all_uploads: Option<&'a str>,
    pub b2_demand_mirror_enabled: Option<&'a str>,
    pub fos_read_enabled: Option<&'a str>,
    pub fos_write_back_enabled: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErasurePolicy {
    pub gcs_enabled: bool,
    pub fos_enabled: bool,
}

impl ErasurePolicy {
    pub fn parse(inputs: ErasurePolicyInputs<'_>) -> Result<Self, &'static str> {
        let gcs_enabled = match inputs.gcs_erasure.unwrap_or("true") {
            "true" => true,
            "false" => false,
            _ => return Err("gcs_erasure_enabled must be true or false"),
        };
        if !gcs_enabled {
            let originals =
                MediaReadPolicy::parse(inputs.media_read_primary, inputs.gcs_fallback_enabled)?;
            let derived = MediaReadPolicy::parse(
                inputs.derived_media_read_primary,
                inputs.derived_media_gcs_fallback_enabled,
            )?;
            if inputs.b2_replica_enabled != Some("true") {
                return Err("gcs_erasure_enabled=false requires b2_replica_enabled=true");
            }
            if originals.primary != StorageProvider::B2 || originals.gcs_fallback_enabled {
                return Err(
                    "gcs_erasure_enabled=false requires media_read_primary=b2 and gcs_fallback_enabled=false",
                );
            }
            if derived.primary != StorageProvider::B2 || derived.gcs_fallback_enabled {
                return Err(
                    "gcs_erasure_enabled=false requires derived_media_read_primary=b2 and derived_media_gcs_fallback_enabled=false",
                );
            }
            if inputs.upload_service_all_uploads != Some("true") {
                return Err("gcs_erasure_enabled=false requires upload_service_all_uploads=true");
            }
            if inputs.b2_demand_mirror_enabled == Some("true") {
                return Err("gcs_erasure_enabled=false requires b2_demand_mirror_enabled to be off");
            }
        }
        let fos_enabled = match inputs.fos_erasure.unwrap_or("true") {
            "true" => true,
            "false" => false,
            _ => return Err("fos_erasure_enabled must be true or false"),
        };
        if !fos_enabled
            && (inputs.fos_read_enabled == Some("true")
                || inputs.fos_write_back_enabled == Some("true"))
        {
            return Err(
                "fos_erasure_enabled=false requires FOS read and write-back to be disabled",
            );
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

    fn b2_only_inputs() -> ErasurePolicyInputs<'static> {
        ErasurePolicyInputs {
            gcs_erasure: Some("false"),
            fos_erasure: Some("false"),
            b2_replica_enabled: Some("true"),
            media_read_primary: Some("b2"),
            gcs_fallback_enabled: Some("false"),
            derived_media_read_primary: Some("b2"),
            derived_media_gcs_fallback_enabled: Some("false"),
            upload_service_all_uploads: Some("true"),
            b2_demand_mirror_enabled: None,
            fos_read_enabled: None,
            fos_write_back_enabled: None,
        }
    }

    #[test]
    fn erasure_policy_defaults_on_and_fails_closed_on_unsafe_combinations() {
        assert_eq!(
            ErasurePolicy::parse(ErasurePolicyInputs::default()).unwrap(),
            ErasurePolicy {
                gcs_enabled: true,
                fos_enabled: true,
            }
        );
        assert_eq!(
            ErasurePolicy::parse(b2_only_inputs()).unwrap(),
            ErasurePolicy {
                gcs_enabled: false,
                fos_enabled: false,
            }
        );
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            b2_replica_enabled: None,
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            gcs_fallback_enabled: Some("true"),
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            derived_media_read_primary: Some("gcs"),
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            upload_service_all_uploads: None,
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            b2_demand_mirror_enabled: Some("true"),
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            fos_read_enabled: Some("true"),
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            fos_write_back_enabled: Some("true"),
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            gcs_erasure: Some("invalid"),
            ..b2_only_inputs()
        })
        .is_err());
        assert!(ErasurePolicy::parse(ErasurePolicyInputs {
            fos_erasure: Some("invalid"),
            ..b2_only_inputs()
        })
        .is_err());
    }
}
