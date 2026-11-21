//! Fixed, authenticated Compute-to-upload-service publication protocol.
use crate::bunny_pilot::{digest, Asset, HLS_PATHS};
use crate::storage_origin::{ObjectRef, StorageProvider};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub path: String,
    pub source_sha256: String,
    pub delivery_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub version: u8,
    pub parent: String,
    pub assets: Vec<Pin>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verified {
    pub asset: Pin,
    pub source: ObjectRef,
    pub destination_version: String,
    pub delivery_size: usize,
}

pub fn complete<'a>(parent: &str, pins: impl Iterator<Item = &'a Pin>) -> bool {
    let mut suffixes = BTreeSet::new();
    for pin in pins {
        let Some(asset) = Asset::parse(&pin.path) else {
            return false;
        };
        if asset.hash() != parent
            || !digest(&pin.source_sha256)
            || !digest(&pin.delivery_sha256)
            || (asset.is_original() && pin.source_sha256 != parent)
            || (!asset.is_playlist() && pin.source_sha256 != pin.delivery_sha256)
            || !suffixes.insert(asset.suffix())
        {
            return false;
        }
    }
    !suffixes.is_empty()
        && suffixes.len() <= 8
        && (!suffixes.iter().any(|s| s.starts_with("hls/"))
            || HLS_PATHS.iter().all(|s| suffixes.contains(s)))
}

pub fn version_valid(provider: StorageProvider, value: &str) -> bool {
    match provider {
        StorageProvider::Gcs => value
            .parse::<u64>()
            .is_ok_and(|n| n > 0 && n.to_string() == value),
        StorageProvider::B2 => {
            (1..=1024).contains(&value.len())
                && value != "null"
                && !value.contains("://")
                && value.bytes().all(|b| b.is_ascii_graphic())
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub path: String,
    pub sha256: String,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
}

impl Publication {
    pub fn asset(&self) -> Option<Asset<'_>> {
        let asset = Asset::parse(&self.path)?;
        let children = asset.child_names();
        (digest(&self.sha256)
            && (!asset.is_original() || self.sha256 == asset.hash())
            && self.dependencies.len() == children.len()
            && children.iter().all(|child| {
                self.dependencies.iter().any(|d| {
                    d.path == format!("/{}/hls/{child}", asset.hash()) && digest(&d.sha256)
                })
            }))
        .then_some(asset)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub original: StorageProvider,
    pub derivative: StorageProvider,
    pub gcs_bucket: Option<String>,
    pub b2_bucket: String,
    pub b2_bucket_id: String,
    pub b2_region: String,
}

impl Scope {
    pub fn source(&self, asset: &Asset<'_>) -> (StorageProvider, &str) {
        let provider = if asset.is_original() {
            self.original
        } else {
            self.derivative
        };
        (
            provider,
            match provider {
                StorageProvider::Gcs => self.gcs_bucket.as_deref().unwrap_or(""),
                StorageProvider::B2 => &self.b2_bucket,
            },
        )
    }
    pub fn matches(&self, verified: &Verified) -> bool {
        let Some(asset) = Asset::parse(&verified.asset.path) else {
            return false;
        };
        let (provider, bucket) = self.source(&asset);
        !bucket.is_empty()
            && verified.source.provider == provider
            && verified.source.bucket == bucket
            && verified.source.key == asset.source_key()
            && verified
                .source
                .version
                .as_deref()
                .is_some_and(|v| version_valid(provider, v))
            && version_valid(StorageProvider::B2, &verified.destination_version)
            && (1..=asset.max_size()).contains(&verified.delivery_size)
            && digest(&verified.asset.source_sha256)
            && digest(&verified.asset.delivery_sha256)
            && (!asset.is_original() || verified.asset.source_sha256 == asset.hash())
            && (asset.is_playlist()
                || verified.asset.source_sha256 == verified.asset.delivery_sha256)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Publish {
        publication: Publication,
        original_size: Option<u64>,
    },
    Finalize {
        inventory: Inventory,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub scope: Scope,
    pub operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Published {
        verified: Verified,
    },
    AlreadyPublished {
        verified: Verified,
    },
    Verified {
        assets: Vec<Verified>,
    },
    /// Every outcome below except the final two guarantees no PUT was accepted.
    SourceMissing,
    SourceChanged,
    DeliveryConflict,
    Rejected,
    Unavailable,
    /// Acknowledged PUT followed by failed verification; cleanup can take over.
    ReadbackFailed,
    /// Transport failed or could still deliver a write; do not release the fence.
    Uncertain,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub scope: Scope,
    pub result: Outcome,
}
