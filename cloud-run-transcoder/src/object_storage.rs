//! Private, version-pinned media I/O. Locks, jobs and readiness use other APIs.

use crate::hls_claim::{gcs_status, Claim, OwnershipLost, PublishLease, WriteTarget, WRITE_ID};
use anyhow::{anyhow, bail, Context, Result};
use blossom_core::storage_origin::{ObjectRef, StorageProvider};
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt};
use google_cloud_storage::{
    client::Client as GcsClient,
    http::objects::{
        download::Range,
        get::GetObjectRequest,
        upload::{UploadObjectRequest, UploadType},
        Object,
    },
};
use reqwest::{header::HeaderMap, Method, StatusCode};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{io::AsyncWriteExt, time::Instant};

pub(crate) const REQUIRED_HLS_FILES: [&str; 5] = [
    "master.m3u8",
    "stream_720p.m3u8",
    "stream_480p.m3u8",
    "stream_720p.ts",
    "stream_480p.ts",
];
pub(crate) const OPTIONAL_HLS_FILES: [&str; 2] = ["stream_720p.mp4", "stream_480p.mp4"];

const CONTROL_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_STALL_TIMEOUT: Duration = Duration::from_secs(30);
const B2_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const B2_RETRY_BACKOFFS: [Duration; 2] = [Duration::from_millis(200), Duration::from_millis(500)];
const MIN_B2_RETRY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct HlsUploadItem {
    pub tier: u8,
    pub key: String,
    pub body: Bytes,
    pub mime: String,
    pub custom: HashMap<String, String>,
    pub cache_control: Option<String>,
}

struct BatchWriteError {
    error: anyhow::Error,
    unconfirmed: bool,
}

impl BatchWriteError {
    fn settled(error: anyhow::Error) -> Self {
        Self {
            error,
            unconfirmed: false,
        }
    }

    fn unconfirmed(error: anyhow::Error) -> Self {
        Self {
            error,
            unconfirmed: true,
        }
    }
}

enum B2SendError {
    Connect(anyhow::Error),
    Transport(anyhow::Error),
    Timeout(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("GCS object MIME missing")]
pub(crate) struct MissingGcsMime;

// No Debug: credentials must never enter diagnostics.
#[derive(Clone)]
pub enum StorageConfiguration {
    Gcs,
    B2 {
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
    },
    B2Primary {
        gcs_backup_enabled: bool,
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
    },
}
impl StorageConfiguration {
    pub fn parse(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let provider = lookup("MEDIA_STORAGE_PROVIDER");
        match provider.as_deref().unwrap_or("gcs") {
            "gcs" => Ok(Self::Gcs),
            "b2" | "b2_primary" => {
                let mut required = |name| {
                    lookup(name)
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| anyhow!("Missing {name}"))
                };
                let bucket = required("B2_MEDIA_BUCKET")?;
                let region = required("B2_REGION")?;
                let access_key = required("B2_ACCESS_KEY_ID")?;
                let secret_key = required("B2_SECRET_ACCESS_KEY")?;
                Ok(if provider.as_deref() == Some("b2_primary") {
                    let gcs_backup_enabled = match lookup("MEDIA_GCS_BACKUP_ENABLED").as_deref() {
                        None | Some("true") => true,
                        Some("false") => false,
                        _ => bail!("MEDIA_GCS_BACKUP_ENABLED must be true or false"),
                    };
                    Self::B2Primary {
                        gcs_backup_enabled,
                        bucket,
                        region,
                        access_key,
                        secret_key,
                    }
                } else {
                    Self::B2 {
                        bucket,
                        region,
                        access_key,
                        secret_key,
                    }
                })
            }
            _ => bail!("MEDIA_STORAGE_PROVIDER must be gcs, b2 or b2_primary"),
        }
    }
}

#[derive(Clone)]
pub struct MediaStorage {
    backend: Backend,
    required_backup: Option<Box<MediaStorage>>,
    // Legacy inputs and already-journaled writes remain readable when replication is off.
    legacy_gcs: Option<Box<MediaStorage>>,
}
#[derive(Clone)]
enum Backend {
    Gcs {
        client: GcsClient,
        bucket: String,
    },
    B2 {
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
        endpoint: String,
        client: reqwest::Client,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub reference: ObjectRef,
    pub size: u64,
    pub content_type: String,
    pub custom: HashMap<String, String>,
    pub cache_control: Option<String>,
}
#[derive(Clone, Debug)]
pub struct VerifiedObject {
    pub object: ObjectMetadata,
    pub sha256: String,
    /// Present only after the required GCS replica was independently verified.
    pub required_backup: Option<ObjectMetadata>,
}

enum WriteCondition {
    Unconditional,
    BackupGeneration(i64),
}

struct B2Request<'a> {
    method: Method,
    key: &'a str,
    version: Option<&'a str>,
    body: Bytes,
    mime: Option<&'a str>,
    cache: Option<&'a str>,
    custom: &'a HashMap<String, String>,
}

impl MediaStorage {
    pub fn gcs(client: GcsClient, bucket: String) -> Self {
        Self {
            backend: Backend::Gcs { client, bucket },
            required_backup: None,
            legacy_gcs: None,
        }
    }
    pub fn configured(
        config: StorageConfiguration,
        gcs: Option<GcsClient>,
        gcs_bucket: String,
    ) -> Result<Self> {
        let legacy_required = matches!(&config, StorageConfiguration::B2Primary { .. });
        let backup_required = matches!(
            &config,
            StorageConfiguration::B2Primary {
                gcs_backup_enabled: true,
                ..
            }
        );
        match config {
            StorageConfiguration::Gcs => {
                if gcs_bucket.is_empty() {
                    bail!("GCS media bucket required");
                }
                Ok(Self::gcs(
                    gcs.ok_or_else(|| anyhow!("GCS media client required"))?,
                    gcs_bucket,
                ))
            }
            StorageConfiguration::B2 {
                bucket,
                region,
                access_key,
                secret_key,
            }
            | StorageConfiguration::B2Primary {
                bucket,
                region,
                access_key,
                secret_key,
                ..
            } => {
                let legacy_gcs = if legacy_required {
                    if gcs_bucket.is_empty() {
                        bail!("GCS legacy bucket required for B2 primary");
                    }
                    Some(Box::new(Self::gcs(
                        gcs.ok_or_else(|| anyhow!("GCS legacy client required for B2 primary"))?,
                        gcs_bucket,
                    )))
                } else {
                    None
                };
                if bucket.is_empty()
                    || !bucket
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    bail!("Invalid B2 media bucket");
                }
                let host = StorageProvider::b2_host(&region).map_err(anyhow::Error::msg)?;
                blossom_core::s3_signing::authorization(
                    &access_key,
                    &secret_key,
                    &region,
                    "20000101",
                    "20000101T000000Z",
                    "configuration-validation",
                    "host",
                )
                .map_err(anyhow::Error::msg)?;
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(10))
                    .pool_idle_timeout(B2_POOL_IDLE_TIMEOUT)
                    .build()?;
                Ok(Self {
                    backend: Backend::B2 {
                        bucket,
                        region,
                        access_key,
                        secret_key,
                        endpoint: format!("https://{host}"),
                        client,
                    },
                    required_backup: if backup_required {
                        legacy_gcs.clone()
                    } else {
                        None
                    },
                    legacy_gcs,
                })
            }
        }
    }
    fn provider_bucket(&self) -> (StorageProvider, &str) {
        match &self.backend {
            Backend::Gcs { bucket, .. } => (StorageProvider::Gcs, bucket),
            Backend::B2 { bucket, .. } => (StorageProvider::B2, bucket),
        }
    }
    pub fn is_gcs(&self) -> bool {
        matches!(self.backend, Backend::Gcs { .. })
    }
    pub(crate) fn is_b2_primary(&self) -> bool {
        self.legacy_gcs.is_some()
    }
    pub(crate) fn requires_backup(&self) -> bool {
        self.required_backup.is_some()
    }
    fn validate_reference(&self, reference: &ObjectRef) -> Result<()> {
        validate_key(&reference.key)?;
        let (provider, bucket) = self.provider_bucket();
        if reference.provider != provider
            || reference.bucket != bucket
            || reference.version.as_ref().is_none_or(|v| !valid_version(v))
        {
            bail!("Object reference does not match configured media storage");
        }
        Ok(())
    }
    pub async fn stat(&self, key: &str) -> Result<Option<ObjectMetadata>> {
        self.stat_pinned(key, None).await
    }
    pub async fn can_reuse_hls(&self, hash: &str) -> Result<bool> {
        let prefix = format!("{hash}/hls");
        // The encoder emits two single-file TS variants. A master alone cannot
        // prove the set exists. An MP4 is optional, but a present MP4 needs its backup.
        let required = REQUIRED_HLS_FILES.into_iter().map(|name| (name, true));
        let optional = OPTIONAL_HLS_FILES.into_iter().map(|name| (name, false));
        for (filename, required) in required.chain(optional) {
            let key = format!("{prefix}/{filename}");
            let Some(primary) = self.stat(&key).await? else {
                if required {
                    return Ok(false);
                }
                // Progressive remux is best-effort; absent MP4s are not HLS
                // failures, but any MP4 actually written needs its backup.
                continue;
            };
            if !required && primary.size == 0 {
                // Empty historical remux placeholders are absent for HLS;
                // the MP4 endpoint can regenerate them from the TS variant.
                continue;
            }
            if !self.can_reuse_output(&primary).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub async fn can_reuse_output(&self, primary: &ObjectMetadata) -> Result<bool> {
        if primary.size == 0 {
            return Ok(false);
        }
        let Some(backup) = &self.required_backup else {
            return Ok(true);
        };
        let Some(replica) = backup.stat(&primary.reference.key).await? else {
            return Ok(false);
        };
        Ok(backup_metadata_matches(primary, &replica)
            && self.hash_body(primary, None).await? == backup.hash_body(&replica, None).await?)
    }

    /// A committed PUT must expose the unique attempt marker at the exact
    /// backend and key recorded before issuing the request.
    pub async fn hls_write_committed(&self, gcs: bool, key: &str, id: &str) -> Result<bool> {
        let backend = if gcs && !self.is_gcs() {
            self.legacy_gcs
                .as_deref()
                .context("GCS HLS recovery store unavailable")?
        } else {
            self
        };
        if backend.is_gcs() != gcs {
            bail!("HLS storage mode changed during publication");
        }
        Ok(backend
            .stat(key)
            .await?
            .is_some_and(|object| object.custom.get(WRITE_ID).is_some_and(|value| value == id)))
    }
    /// Verify or repair a required backup without rewriting the pinned primary.
    /// Callers that may write the same artifact must hold its existing job lock.
    pub async fn ensure_required_backup(&self, primary: &ObjectMetadata) -> Result<()> {
        let Some(backup) = &self.required_backup else {
            return Ok(());
        };
        // Detect control failures before downloading the primary's full bytes.
        let replica = backup.stat(&primary.reference.key).await?;
        let body = Bytes::from(self.read(primary).await?);
        self.ensure_backup_bytes(primary, body, replica.as_ref())
            .await
    }

    /// Preserve the primary's provenance when an existing output needs a backup.
    pub async fn ensure_existing_backup(
        &self,
        primary: &ObjectMetadata,
        body: Bytes,
    ) -> Result<()> {
        let Some(backup) = &self.required_backup else {
            return Ok(());
        };
        self.validate_reference(&primary.reference)?;
        if primary.size != body.len() as u64 {
            bail!("Existing output size does not match backup bytes");
        }
        let replica = backup.stat(&primary.reference.key).await?;
        self.verify_sha256(primary, &hex::encode(Sha256::digest(&body)))
            .await?;
        self.ensure_backup_bytes(primary, body, replica.as_ref())
            .await
    }

    // `body` came either from our pinned read or from an independently verified
    // existing primary. Never resolve a new latest version during repair.
    async fn ensure_backup_bytes(
        &self,
        primary: &ObjectMetadata,
        body: Bytes,
        replica: Option<&ObjectMetadata>,
    ) -> Result<()> {
        let backup = self
            .required_backup
            .as_ref()
            .ok_or_else(|| anyhow!("Required backup unavailable"))?;
        let sha = hex::encode(Sha256::digest(&body));
        if let Some(replica) = replica {
            if backup_metadata_matches(primary, replica)
                && sha == backup.hash_body(replica, None).await?
            {
                return Ok(());
            }
        }
        let expected = match replica {
            None => 0,
            Some(replica) => replica
                .reference
                .version
                .as_deref()
                .ok_or_else(|| anyhow!("Pinned GCS backup generation required"))?
                .parse::<i64>()
                .context("Invalid GCS backup generation")?,
        };
        backup
            .put_single_verified_if_generation(
                &primary.reference.key,
                body,
                &primary.content_type,
                primary.custom.clone(),
                primary.cache_control.clone(),
                WriteCondition::BackupGeneration(expected),
            )
            .await
            .context("Required GCS backup of existing output was not verified")?;
        Ok(())
    }
    /// Read exactly an event-supplied object version; never resolve latest.
    pub async fn stat_reference(&self, reference: &ObjectRef) -> Result<Option<ObjectMetadata>> {
        self.validate_reference(reference)?;
        self.stat_pinned(&reference.key, reference.version.as_deref())
            .await
    }
    async fn stat_pinned(
        &self,
        key: &str,
        version: Option<&str>,
    ) -> Result<Option<ObjectMetadata>> {
        validate_key(key)?;
        let metadata = match &self.backend {
            Backend::Gcs { client, bucket } => {
                let request = GetObjectRequest {
                    bucket: bucket.clone(),
                    object: key.into(),
                    generation: gcs_generation(version)?,
                    ..Default::default()
                };
                match tokio::time::timeout(CONTROL_TIMEOUT, client.get_object(&request))
                    .await
                    .context("GCS metadata deadline exceeded")?
                {
                    Ok(object) => from_gcs(bucket, key, object)?,
                    Err(google_cloud_storage::http::Error::Response(error))
                        if error.code == 404 =>
                    {
                        return Ok(None)
                    }
                    Err(_) => bail!("GCS media metadata unavailable"),
                }
            }
            Backend::B2 { bucket, .. } => {
                let response = self.b2_read_with_retry(Method::HEAD, key, version).await?;
                if response.status() == StatusCode::NOT_FOUND {
                    return Ok(None);
                }
                if response.status() != StatusCode::OK
                    || response.headers().contains_key("content-range")
                {
                    bail!("B2 full media metadata response required");
                }
                from_b2(bucket, key, response.headers())?
            }
        };
        if version.is_some_and(|v| metadata.reference.version.as_deref() != Some(v)) {
            bail!("Pinned media metadata version mismatch");
        }
        Ok(Some(metadata))
    }
    async fn body<'a>(&'a self, object: &ObjectMetadata) -> Result<BoxStream<'a, Result<Bytes>>> {
        self.validate_reference(&object.reference)?;
        match &self.backend {
            Backend::Gcs { client, bucket } => {
                let mut request = GetObjectRequest {
                    bucket: bucket.clone(),
                    object: object.reference.key.clone(),
                    generation: gcs_generation(object.reference.version.as_deref())?,
                    ..Default::default()
                };
                // GCS metadata can change without a new byte generation. Bind
                // the byte GET to the metadata values actually checked here.
                let metadata = tokio::time::timeout(CONTROL_TIMEOUT, client.get_object(&request))
                    .await
                    .context("GCS pinned metadata deadline exceeded")?
                    .map_err(|_| anyhow!("GCS pinned media metadata unavailable"))?;
                if metadata.metageneration <= 0 {
                    bail!("GCS metadata generation invalid");
                }
                request.if_metageneration_match = Some(metadata.metageneration);
                if from_gcs(bucket, &object.reference.key, metadata)? != *object {
                    bail!("GCS pinned media metadata mismatch");
                }
                let stream = tokio::time::timeout(
                    CONTROL_TIMEOUT,
                    client.download_streamed_object(&request, &Range::default()),
                )
                .await
                .context("GCS media headers timed out")?
                .map_err(|_| anyhow!("GCS pinned media read failed"))?;
                Ok(stream
                    .map(|part| part.map_err(|_| anyhow!("GCS media stream failed")))
                    .boxed())
            }
            Backend::B2 { bucket, .. } => {
                let response = self
                    .b2_read_with_retry(
                        Method::GET,
                        &object.reference.key,
                        object.reference.version.as_deref(),
                    )
                    .await?;
                if response.status() != StatusCode::OK
                    || response.headers().contains_key("content-range")
                {
                    bail!("B2 full media response required");
                }
                if from_b2(bucket, &object.reference.key, response.headers())? != *object {
                    bail!("B2 pinned media metadata mismatch");
                }
                Ok(response
                    .bytes_stream()
                    .map(|part| part.map_err(|_| anyhow!("B2 media stream failed")))
                    .boxed())
            }
        }
    }
    /// Read pinned bytes, rejecting stalled streams and mismatched object lengths.
    pub async fn read(&self, object: &ObjectMetadata) -> Result<Vec<u8>> {
        let mut body = self.body(object).await?;
        let mut bytes = Vec::new();
        let mut length = 0u64;
        while let Some(chunk) = tokio::time::timeout(STREAM_STALL_TIMEOUT, body.next())
            .await
            .context("Media body stalled")?
        {
            let chunk = chunk?;
            length = length
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow!("Media length overflow"))?;
            if length > object.size {
                bail!("Media exceeded pinned object size");
            }
            bytes
                .try_reserve(chunk.len())
                .context("Media allocation failed")?;
            bytes.extend_from_slice(&chunk);
        }
        if length != object.size {
            bail!("Media body does not match pinned size");
        }
        Ok(bytes)
    }
    async fn hash_body(
        &self,
        object: &ObjectMetadata,
        mut writer: Option<&mut tokio::fs::File>,
    ) -> Result<String> {
        let mut body = self.body(object).await?;
        let mut hash = Sha256::new();
        let mut length = 0u64;
        while let Some(chunk) = tokio::time::timeout(STREAM_STALL_TIMEOUT, body.next())
            .await
            .context("Media body stalled")?
        {
            let chunk = chunk?;
            length = length
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow!("Media length overflow"))?;
            if length > object.size {
                bail!("Media exceeded pinned object size");
            }
            hash.update(&chunk);
            if let Some(file) = writer.as_mut() {
                file.write_all(&chunk).await?;
            }
        }
        if length != object.size {
            bail!("Media body does not match pinned size");
        }
        Ok(hex::encode(hash.finalize()))
    }
    /// An absent input may use the legacy store in B2-primary mode. Provider
    /// failures and failed verification must never select another source.
    pub(crate) async fn find_processing_input(
        &self,
        key: &str,
    ) -> Result<Option<(&Self, ObjectMetadata)>> {
        if let Some(object) = self.stat(key).await? {
            return Ok(Some((self, object)));
        }
        match self.legacy_gcs.as_deref() {
            Some(legacy) => Ok(legacy.stat(key).await?.map(|object| (legacy, object))),
            None => Ok(None),
        }
    }

    pub async fn download_processing_segment(&self, key: &str, path: &Path) -> Result<bool> {
        let Some((store, object)) = self.find_processing_input(key).await? else {
            return Ok(false);
        };
        store.download_pinned(&object, None, path).await?;
        Ok(true)
    }

    pub async fn download_processing_original(
        &self,
        expected_sha: &str,
        path: &Path,
    ) -> Result<VerifiedObject> {
        if !is_sha256(expected_sha) {
            bail!("Original SHA-256 identity invalid");
        }
        let (store, object) = self
            .find_processing_input(expected_sha)
            .await?
            .ok_or_else(|| anyhow!("Original not found"))?;
        store.download_original(&object, expected_sha, path).await
    }

    pub async fn download_original(
        &self,
        object: &ObjectMetadata,
        expected_sha: &str,
        path: &Path,
    ) -> Result<VerifiedObject> {
        if !is_sha256(expected_sha) || object.reference.key != expected_sha {
            bail!("Original SHA-256 identity invalid");
        }
        self.download_pinned(object, Some(expected_sha), path).await
    }

    async fn download_pinned(
        &self,
        object: &ObjectMetadata,
        expected_sha: Option<&str>,
        path: &Path,
    ) -> Result<VerifiedObject> {
        let directory = path
            .parent()
            .ok_or_else(|| anyhow!("Media output directory missing"))?;
        let temp = tempfile::NamedTempFile::new_in(directory)?;
        let mut writer = tokio::fs::File::from_std(temp.reopen()?);
        let sha256 = self.hash_body(object, Some(&mut writer)).await?;
        if expected_sha.is_some_and(|expected| sha256 != expected) {
            bail!("Original SHA-256 verification failed");
        }
        writer.flush().await?;
        drop(writer);
        temp.persist(path)
            .map_err(|_| anyhow!("Verified media could not be published"))?;
        Ok(VerifiedObject {
            object: object.clone(),
            sha256,
            required_backup: None,
        })
    }
    pub async fn verify_sha256(&self, object: &ObjectMetadata, expected_sha: &str) -> Result<()> {
        if !is_sha256(expected_sha) || self.hash_body(object, None).await? != expected_sha {
            bail!("Media SHA-256 verification failed");
        }
        Ok(())
    }
    pub async fn put_verified(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        custom: HashMap<String, String>,
        cache_control: Option<String>,
    ) -> Result<VerifiedObject> {
        self.put_with_backup(key, body, mime, custom, cache_control)
            .await
    }

    /// Journal the entire output set in one claim mutation, then publish each
    /// tier in order (parallel within a tier, master last) while holding the
    /// active `Publishing` lease.
    pub async fn put_hls_batch_verified(
        &self,
        mut items: Vec<HlsUploadItem>,
        claim: &mut Claim,
    ) -> Result<Vec<VerifiedObject>> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let mut seen_keys = HashSet::with_capacity(items.len());
        let mut targets =
            Vec::with_capacity(items.len() * if self.required_backup.is_some() { 2 } else { 1 });
        for item in &items {
            validate_key(&item.key)?;
            if !seen_keys.insert(item.key.clone()) {
                bail!("Duplicate media key in publication batch");
            }
            if is_sha256(&item.key) {
                let sha256 = hex::encode(Sha256::digest(&item.body));
                if item.key != sha256 {
                    bail!("Content-addressed output key mismatch");
                }
            }
            targets.push(WriteTarget {
                gcs: self.is_gcs(),
                key: item.key.clone(),
            });
            if self.required_backup.is_some() {
                targets.push(WriteTarget {
                    gcs: true,
                    key: item.key.clone(),
                });
            }
        }

        // Pre-fetch live GCS generations in parallel before the single
        // begin_publication CAS so every GCS write still carries ifGenerationMatch.
        let gcs_generations = if let Some(gcs_store) = if self.is_gcs() {
            Some(self)
        } else {
            self.required_backup.as_deref()
        } {
            let keys: Vec<String> = items.iter().map(|item| item.key.clone()).collect();
            let fetched = claim
                .hold(futures::future::try_join_all(keys.iter().map(
                    |key| async {
                        let generation = match gcs_store.stat(key).await? {
                            Some(object) => gcs_generation_from_metadata(&object)?,
                            None => 0,
                        };
                        Ok::<(String, i64), anyhow::Error>((key.clone(), generation))
                    },
                )))
                .await?;
            fetched.into_iter().collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };

        let write_id = claim.write_id();
        for item in &mut items {
            item.custom.insert(WRITE_ID.to_owned(), write_id.clone());
        }
        claim.begin_publication(targets, &write_id).await?;
        let lease = PublishLease::new(claim.lease_renewed_at());
        let deadline = claim.deadline();
        let mut tiers: BTreeMap<u8, Vec<HlsUploadItem>> = BTreeMap::new();
        for item in items {
            tiers.entry(item.tier).or_default().push(item);
        }

        let (batch_result, heartbeat_error) = claim
            .hold_publishing(lease.clone(), async {
                let mut verified = Vec::new();
                let mut batch_had_ambiguous = false;
                for (_tier, tier_items) in tiers {
                    if Instant::now() >= deadline {
                        let err = anyhow!("Transcode attempt exceeded its preparation deadline");
                        return Err(if batch_had_ambiguous {
                            BatchWriteError::unconfirmed(err)
                        } else {
                            BatchWriteError::settled(err)
                        });
                    }
                    if lease.remaining_after(Duration::ZERO).is_none() {
                        let err =
                            anyhow!("Transcode lease lost or expired before tier publication");
                        return Err(if batch_had_ambiguous {
                            BatchWriteError::unconfirmed(err)
                        } else {
                            BatchWriteError::settled(err)
                        });
                    }
                    // Always await every started PUT in the tier (join_all,
                    // never try_join_all) so we never drop an in-flight PUT
                    // and misclassify an unconfirmed write as settled.
                    let results =
                        futures::future::join_all(
                            tier_items.into_iter().map(|item| {
                                let gcs_gen = gcs_generations.get(&item.key).copied();
                                let lease = lease.clone();
                                async move {
                                    self.put_batch_item_with_backup(item, gcs_gen, &lease).await
                                }
                            }),
                        )
                        .await;
                    let mut first_error: Option<anyhow::Error> = None;
                    let mut any_unconfirmed = batch_had_ambiguous;
                    let mut tier_verified = Vec::with_capacity(results.len());
                    for result in results {
                        match result {
                            Ok((receipt, item_ambiguous)) => {
                                batch_had_ambiguous |= item_ambiguous;
                                any_unconfirmed |= item_ambiguous;
                                tier_verified.push(receipt);
                            }
                            Err(err) => {
                                if first_error.is_none() {
                                    first_error = Some(err.error);
                                }
                                any_unconfirmed |= err.unconfirmed;
                            }
                        }
                    }
                    if let Some(error) = first_error {
                        return Err(BatchWriteError {
                            error,
                            unconfirmed: any_unconfirmed,
                        });
                    }
                    verified.extend(tier_verified);
                }
                Ok(verified)
            })
            .await;

        Self::settle_publication(claim, batch_result, heartbeat_error).await
    }

    async fn settle_publication<T>(
        claim: &mut Claim,
        result: std::result::Result<T, BatchWriteError>,
        heartbeat_error: Option<anyhow::Error>,
    ) -> Result<T> {
        match result {
            Ok(verified) => {
                if let Some(hb_err) = heartbeat_error {
                    return Err(hb_err);
                }
                claim.acknowledge_write();
                Ok(verified)
            }
            Err(err) => {
                if let Some(hb_err) = heartbeat_error {
                    if hb_err.is::<OwnershipLost>() {
                        return Err(hb_err);
                    }
                    return Err(err.error);
                }
                if !err.unconfirmed {
                    claim.reject_write().await?;
                }
                Err(err.error)
            }
        }
    }

    async fn put_batch_item_with_backup(
        &self,
        item: HlsUploadItem,
        gcs_generation: Option<i64>,
        lease: &PublishLease,
    ) -> std::result::Result<(VerifiedObject, bool), BatchWriteError> {
        let (mut primary, mut had_ambiguous) = self
            .put_publication_target(
                &item.key,
                item.body.clone(),
                &item.mime,
                item.custom.clone(),
                item.cache_control.clone(),
                if self.is_gcs() { gcs_generation } else { None },
                Some(lease),
            )
            .await?;
        if let Some(backup) = &self.required_backup {
            if lease.remaining_after(Duration::ZERO).is_none() {
                let err = anyhow!("Transcode lease lost or expired before backup publication");
                return Err(if had_ambiguous {
                    BatchWriteError::unconfirmed(err)
                } else {
                    BatchWriteError::settled(err)
                });
            }
            let (replica, backup_ambiguous) = backup
                .put_publication_target(
                    &item.key,
                    item.body,
                    &item.mime,
                    item.custom,
                    item.cache_control,
                    gcs_generation,
                    Some(lease),
                )
                .await
                .map_err(|mut err| {
                    err.error = err.error.context(
                        "Required GCS backup was not verified; primary must not be acknowledged",
                    );
                    err.unconfirmed |= had_ambiguous;
                    err
                })?;
            had_ambiguous |= backup_ambiguous;
            if replica.sha256 != primary.sha256 {
                let err = anyhow!("Required GCS backup identity mismatch");
                return Err(if had_ambiguous {
                    BatchWriteError::unconfirmed(err)
                } else {
                    BatchWriteError::settled(err)
                });
            }
            primary.required_backup = Some(replica.object);
        }
        Ok((primary, had_ambiguous))
    }

    pub(crate) async fn put_claimed_verified(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        mut custom: HashMap<String, String>,
        cache_control: Option<String>,
        claim: &mut Claim,
    ) -> Result<VerifiedObject> {
        validate_key(key)?;
        if is_sha256(key) && key != hex::encode(Sha256::digest(&body)) {
            bail!("Content-addressed output key mismatch");
        }
        custom.insert(WRITE_ID.to_owned(), claim.write_id());

        // Journal one provider at a time. If a primary PUT is unconfirmed,
        // the backup has not started and cannot provide a recovery marker.
        let mut primary = self
            .put_claimed_target(
                key,
                body.clone(),
                mime,
                custom.clone(),
                cache_control.clone(),
                claim,
            )
            .await?;
        if let Some(backup) = &self.required_backup {
            let replica = backup
                .put_claimed_target(key, body, mime, custom, cache_control, claim)
                .await
                .context(
                    "Required GCS backup was not verified; primary must not be acknowledged",
                )?;
            if replica.sha256 != primary.sha256 {
                bail!("Required GCS backup identity mismatch");
            }
            primary.required_backup = Some(replica.object);
        }
        Ok(primary)
    }

    async fn put_claimed_target(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        custom: HashMap<String, String>,
        cache_control: Option<String>,
        claim: &mut Claim,
    ) -> Result<VerifiedObject> {
        let gcs_generation = if self.is_gcs() {
            Some(match claim.hold(self.stat(key)).await? {
                Some(object) => gcs_generation_from_metadata(&object)?,
                None => 0,
            })
        } else {
            None
        };
        claim
            .begin_publication(
                vec![WriteTarget {
                    gcs: self.is_gcs(),
                    key: key.to_owned(),
                }],
                &custom[WRITE_ID],
            )
            .await?;
        let lease = PublishLease::new(claim.lease_renewed_at());
        let deadline = claim.deadline();
        let (result, heartbeat_error) = claim
            .hold_publishing(lease.clone(), async {
                if Instant::now() >= deadline {
                    return Err(BatchWriteError::settled(anyhow!(
                        "Transcode attempt exceeded its preparation deadline"
                    )));
                }
                if lease.remaining_after(Duration::ZERO).is_none() {
                    return Err(BatchWriteError::settled(anyhow!(
                        "Transcode lease lost or expired before publication"
                    )));
                }
                // Sound uses a single PUT per provider so its journal covers
                // exactly one mutable write, including when the verdict is forced.
                self.put_publication_target(
                    key,
                    body,
                    mime,
                    custom,
                    cache_control,
                    gcs_generation,
                    None,
                )
                .await
                .map(|(verified, _)| verified)
            })
            .await;
        Self::settle_publication(claim, result, heartbeat_error).await
    }

    async fn put_publication_target(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        custom: HashMap<String, String>,
        cache_control: Option<String>,
        gcs_generation: Option<i64>,
        retry_lease: Option<&PublishLease>,
    ) -> std::result::Result<(VerifiedObject, bool), BatchWriteError> {
        let remaining_retry_time =
            |delay| retry_lease.and_then(|lease| lease.remaining_after(delay));
        let sha256 = hex::encode(Sha256::digest(&body));
        let mut had_ambiguous_attempt = false;
        let classify_settled = |had_ambiguous: bool, err: anyhow::Error| {
            if had_ambiguous {
                BatchWriteError::unconfirmed(err)
            } else {
                BatchWriteError::settled(err)
            }
        };
        let reference = match &self.backend {
            Backend::Gcs { client, bucket } => {
                let metadata = Object {
                    name: key.into(),
                    content_type: Some(mime.into()),
                    metadata: Some(custom.clone()),
                    cache_control: cache_control.clone(),
                    ..Default::default()
                };
                let result = tokio::time::timeout(
                    CONTROL_TIMEOUT,
                    client.upload_object(
                        &UploadObjectRequest {
                            bucket: bucket.clone(),
                            if_generation_match: gcs_generation,
                            ..Default::default()
                        },
                        body.clone(),
                        &UploadType::Multipart(Box::new(metadata)),
                    ),
                )
                .await
                .map_err(|_| {
                    BatchWriteError::unconfirmed(anyhow!(
                        "GCS media write deadline; outcome unconfirmed"
                    ))
                })?;
                match result {
                    Ok(object) => {
                        from_gcs(bucket, key, object)
                            .map_err(BatchWriteError::settled)?
                            .reference
                    }
                    Err(error) => {
                        let rejected = gcs_status(&error).is_some_and(write_rejected);
                        let err = anyhow!("GCS media write failed");
                        return Err(if rejected {
                            BatchWriteError::settled(err)
                        } else {
                            BatchWriteError::unconfirmed(err)
                        });
                    }
                }
            }
            Backend::B2 { .. } => {
                let mut attempt = 0usize;
                let mut timeout = CONTROL_TIMEOUT;
                let write_id = custom.get(WRITE_ID).map(String::as_str);
                loop {
                    let request = self
                        .build_b2_request(B2Request {
                            method: Method::PUT,
                            key,
                            version: None,
                            body: body.clone(),
                            mime: Some(mime),
                            cache: cache_control.as_deref(),
                            custom: &custom,
                        })
                        .map_err(|err| classify_settled(had_ambiguous_attempt, err))?;
                    match send_b2_request_classified(request, timeout).await {
                        Ok(response) => {
                            let status = response.status();
                            if status.is_success() {
                                let (_, bucket) = self.provider_bucket();
                                let version = required(response.headers(), "x-amz-version-id")
                                    .map_err(|err| classify_settled(had_ambiguous_attempt, err))?;
                                break ObjectRef {
                                    provider: StorageProvider::B2,
                                    bucket: bucket.into(),
                                    key: key.into(),
                                    version: Some(version),
                                };
                            }
                            let code = status.as_u16();
                            let transient_5xx = b2_transient_status(status);
                            if transient_5xx {
                                had_ambiguous_attempt = true;
                            }
                            if (transient_5xx || code == 429) && attempt < B2_RETRY_BACKOFFS.len() {
                                let delay = B2_RETRY_BACKOFFS[attempt];
                                if remaining_retry_time(delay)
                                    .is_some_and(|rem| rem >= MIN_B2_RETRY_TIMEOUT)
                                {
                                    attempt += 1;
                                    tokio::time::sleep(delay).await;
                                    // If a 5xx arrived after B2 actually committed
                                    // this attempt, verify the committed object
                                    // directly instead of issuing a duplicate PUT.
                                    if transient_5xx {
                                        if let Ok(Some(existing)) = self.stat(key).await {
                                            if write_id.is_some()
                                                && existing.custom.get(WRITE_ID).map(String::as_str)
                                                    == write_id
                                            {
                                                break existing.reference;
                                            }
                                        }
                                    }
                                    if let Some(rem) = remaining_retry_time(Duration::ZERO)
                                        .filter(|rem| *rem >= MIN_B2_RETRY_TIMEOUT)
                                    {
                                        timeout = rem.min(CONTROL_TIMEOUT);
                                        crate::hls_claim::count("b2_write_retried");
                                        continue;
                                    }
                                }
                            }
                            let err = successful(status).unwrap_err();
                            return Err(if !had_ambiguous_attempt && write_rejected(code) {
                                BatchWriteError::settled(err)
                            } else {
                                BatchWriteError::unconfirmed(err)
                            });
                        }
                        Err(B2SendError::Connect(err)) => {
                            // TCP connect failed before any HTTP bytes left the
                            // client, so this attempt could not have committed.
                            if attempt < B2_RETRY_BACKOFFS.len() {
                                let delay = B2_RETRY_BACKOFFS[attempt];
                                if remaining_retry_time(delay)
                                    .is_some_and(|rem| rem >= MIN_B2_RETRY_TIMEOUT)
                                {
                                    attempt += 1;
                                    tokio::time::sleep(delay).await;
                                    if let Some(rem) = remaining_retry_time(Duration::ZERO)
                                        .filter(|rem| *rem >= MIN_B2_RETRY_TIMEOUT)
                                    {
                                        timeout = rem.min(CONTROL_TIMEOUT);
                                        crate::hls_claim::count("b2_write_retried");
                                        continue;
                                    }
                                }
                            }
                            return Err(classify_settled(had_ambiguous_attempt, err));
                        }
                        Err(B2SendError::Transport(err)) => {
                            had_ambiguous_attempt = true;
                            if attempt < B2_RETRY_BACKOFFS.len() {
                                let delay = B2_RETRY_BACKOFFS[attempt];
                                if remaining_retry_time(delay)
                                    .is_some_and(|rem| rem >= MIN_B2_RETRY_TIMEOUT)
                                {
                                    attempt += 1;
                                    tokio::time::sleep(delay).await;
                                    if let Ok(Some(existing)) = self.stat(key).await {
                                        if write_id.is_some()
                                            && existing.custom.get(WRITE_ID).map(String::as_str)
                                                == write_id
                                        {
                                            break existing.reference;
                                        }
                                    }
                                    if let Some(rem) = remaining_retry_time(Duration::ZERO)
                                        .filter(|rem| *rem >= MIN_B2_RETRY_TIMEOUT)
                                    {
                                        timeout = rem.min(CONTROL_TIMEOUT);
                                        crate::hls_claim::count("b2_write_retried");
                                        continue;
                                    }
                                }
                            }
                            return Err(BatchWriteError::unconfirmed(err));
                        }
                        Err(B2SendError::Timeout(err)) => {
                            return Err(BatchWriteError::unconfirmed(err));
                        }
                    }
                }
            }
        };
        // Read-back verification is settled only if no earlier PUT attempt on
        // this item had an ambiguous outcome.
        self.validate_reference(&reference)
            .map_err(|err| classify_settled(had_ambiguous_attempt, err))?;
        let object = self
            .stat_reference(&reference)
            .await
            .map_err(|err| classify_settled(had_ambiguous_attempt, err))?
            .ok_or_else(|| {
                classify_settled(
                    had_ambiguous_attempt,
                    anyhow!("Written media version missing"),
                )
            })?;
        if object.reference != reference
            || object.size != body.len() as u64
            || object.content_type != mime
            || object.custom != custom
            || object.cache_control != cache_control
        {
            return Err(classify_settled(
                had_ambiguous_attempt,
                anyhow!("Written media metadata verification failed"),
            ));
        }
        self.verify_sha256(&object, &sha256)
            .await
            .map_err(|err| classify_settled(had_ambiguous_attempt, err))?;
        Ok((
            VerifiedObject {
                object,
                sha256,
                required_backup: None,
            },
            had_ambiguous_attempt,
        ))
    }

    async fn put_with_backup(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        custom: HashMap<String, String>,
        cache_control: Option<String>,
    ) -> Result<VerifiedObject> {
        let mut primary = self
            .put_single_verified_if_generation(
                key,
                body.clone(),
                mime,
                custom.clone(),
                cache_control.clone(),
                WriteCondition::Unconditional,
            )
            .await?;
        if let Some(backup) = &self.required_backup {
            let replica = backup
                .put_single_verified_if_generation(
                    key,
                    body,
                    mime,
                    custom,
                    cache_control,
                    WriteCondition::Unconditional,
                )
                .await
                .context(
                    "Required GCS backup was not verified; primary must not be acknowledged",
                )?;
            if replica.sha256 != primary.sha256 {
                bail!("Required GCS backup identity mismatch");
            }
            primary.required_backup = Some(replica.object);
        }
        Ok(primary)
    }

    async fn put_single_verified_if_generation(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        custom: HashMap<String, String>,
        cache_control: Option<String>,
        condition: WriteCondition,
    ) -> Result<VerifiedObject> {
        let gcs_generation = match condition {
            WriteCondition::Unconditional => None,
            WriteCondition::BackupGeneration(generation) => Some(generation),
        };
        validate_key(key)?;
        let sha256 = hex::encode(Sha256::digest(&body));
        if is_sha256(key) && key != sha256 {
            bail!("Content-addressed output key mismatch");
        }
        let reference = match &self.backend {
            Backend::Gcs { client, bucket } => {
                let metadata = Object {
                    name: key.into(),
                    content_type: Some(mime.into()),
                    metadata: Some(custom.clone()),
                    cache_control: cache_control.clone(),
                    ..Default::default()
                };
                let result = tokio::time::timeout(
                    CONTROL_TIMEOUT,
                    client.upload_object(
                        &UploadObjectRequest {
                            bucket: bucket.clone(),
                            if_generation_match: gcs_generation,
                            ..Default::default()
                        },
                        body.clone(),
                        &UploadType::Multipart(Box::new(metadata)),
                    ),
                )
                .await
                .context("GCS media write deadline; outcome unconfirmed")?;
                let object = result.map_err(|_| anyhow!("GCS media write failed"))?;
                from_gcs(bucket, key, object)?.reference
            }
            Backend::B2 { .. } => {
                if gcs_generation.is_some() {
                    bail!("GCS generation precondition requires a GCS backup");
                }
                let request = self.build_b2_request(B2Request {
                    method: Method::PUT,
                    key,
                    version: None,
                    body: body.clone(),
                    mime: Some(mime),
                    cache: cache_control.as_deref(),
                    custom: &custom,
                })?;
                let response = send_b2_request(request).await?;
                successful(response.status())?;
                let (_, bucket) = self.provider_bucket();
                ObjectRef {
                    provider: StorageProvider::B2,
                    bucket: bucket.into(),
                    key: key.into(),
                    version: Some(required(response.headers(), "x-amz-version-id")?),
                }
            }
        };
        self.validate_reference(&reference)?;
        let object = self
            .stat_reference(&reference)
            .await?
            .ok_or_else(|| anyhow!("Written media version missing"))?;
        if object.reference != reference
            || object.size != body.len() as u64
            || object.content_type != mime
            || object.custom != custom
            || object.cache_control != cache_control
        {
            bail!("Written media metadata verification failed");
        }
        self.verify_sha256(&object, &sha256).await?;
        Ok(VerifiedObject {
            object,
            sha256,
            required_backup: None,
        })
    }
    async fn b2_read_with_retry(
        &self,
        method: Method,
        key: &str,
        version: Option<&str>,
    ) -> Result<reqwest::Response> {
        let mut attempt = 0usize;
        loop {
            let request = self.build_b2_request(B2Request {
                method: method.clone(),
                key,
                version,
                body: Bytes::new(),
                mime: None,
                cache: None,
                custom: &HashMap::new(),
            })?;
            match send_b2_request_classified(request, CONTROL_TIMEOUT).await {
                Ok(response) => {
                    if (b2_transient_status(response.status())
                        || response.status() == StatusCode::TOO_MANY_REQUESTS)
                        && attempt < B2_RETRY_BACKOFFS.len()
                    {
                        let delay = B2_RETRY_BACKOFFS[attempt];
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(response);
                }
                Err(B2SendError::Connect(err) | B2SendError::Transport(err)) => {
                    if attempt < B2_RETRY_BACKOFFS.len() {
                        let delay = B2_RETRY_BACKOFFS[attempt];
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(err);
                }
                Err(B2SendError::Timeout(err)) => return Err(err),
            }
        }
    }

    fn build_b2_request(&self, request: B2Request<'_>) -> Result<reqwest::RequestBuilder> {
        let B2Request {
            method,
            key,
            version,
            body,
            mime,
            cache,
            custom,
        } = request;
        validate_key(key)?;
        let Backend::B2 {
            bucket,
            region,
            access_key,
            secret_key,
            endpoint,
            client,
        } = &self.backend
        else {
            bail!("B2 backend not selected");
        };
        let path = format!(
            "/{}/{}",
            encode(bucket),
            key.split('/').map(encode).collect::<Vec<_>>().join("/")
        );
        let query = version
            .map(|v| format!("versionId={}", encode(v)))
            .unwrap_or_default();
        let url = format!(
            "{endpoint}{path}{}",
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        );
        let now = OffsetDateTime::now_utc();
        let date = format!(
            "{:04}{:02}{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        );
        let timestamp = format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );
        let hash = hex::encode(Sha256::digest(&body));
        let mut headers = BTreeMap::from([
            (
                "host".to_string(),
                reqwest::Url::parse(endpoint)?.authority().into(),
            ),
            ("x-amz-date".to_string(), timestamp.clone()),
            ("x-amz-content-sha256".to_string(), hash.clone()),
        ]);
        if let Some(mime) = mime {
            headers.insert("content-type".into(), mime.into());
        }
        if let Some(cache) = cache {
            headers.insert("cache-control".into(), cache.into());
        }
        for (name, value) in custom {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
                || value.trim() != value
                || !value.is_ascii()
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                bail!("Metadata cannot be represented without alteration");
            }
            headers.insert(format!("x-amz-meta-{name}"), value.clone());
        }
        for value in headers.values() {
            if value.is_empty()
                || value.trim() != value
                || !value.is_ascii()
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                bail!("Media header cannot be represented without alteration");
            }
        }
        // Reuse the verified upload-server B2 adapter's canonical wire layout;
        // the signing core is shared with the existing edge wrappers.
        let signed = headers.keys().cloned().collect::<Vec<_>>().join(";");
        let mut canonical_headers = String::new();
        for (name, value) in &headers {
            canonical_headers.push_str(name);
            canonical_headers.push(':');
            canonical_headers
                .push_str(&value.split_ascii_whitespace().collect::<Vec<_>>().join(" "));
            canonical_headers.push('\n');
        }
        let canonical = format!(
            "{}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{hash}",
            method.as_str()
        );
        let auth = blossom_core::s3_signing::authorization(
            access_key, secret_key, region, &date, &timestamp, &canonical, &signed,
        )
        .map_err(anyhow::Error::msg)?;
        let mut request = client.request(method, url).header("authorization", auth);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request.body(body))
    }
    #[cfg(test)]
    fn b2_for_test(endpoint: &str, bucket: &str) -> Result<Self> {
        let url = reqwest::Url::parse(endpoint)?;
        if url.scheme() != "http" || url.host_str() != Some("127.0.0.1") {
            bail!("Test endpoint must be loopback");
        }
        let mut store = Self::configured(
            StorageConfiguration::B2 {
                bucket: bucket.into(),
                region: "us-west-004".into(),
                access_key: "synthetic-access".into(),
                secret_key: "synthetic-secret".into(),
            },
            None,
            String::new(),
        )?;
        if let Backend::B2 {
            endpoint: target, ..
        } = &mut store.backend
        {
            *target = endpoint.into();
        }
        Ok(store)
    }
}

async fn send_b2_request(request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    match send_b2_request_classified(request, CONTROL_TIMEOUT).await {
        Ok(response) => Ok(response),
        Err(
            B2SendError::Connect(err) | B2SendError::Transport(err) | B2SendError::Timeout(err),
        ) => Err(err),
    }
}

async fn send_b2_request_classified(
    request: reqwest::RequestBuilder,
    timeout: Duration,
) -> std::result::Result<reqwest::Response, B2SendError> {
    match tokio::time::timeout(timeout, request.send()).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) if error.is_connect() => Err(B2SendError::Connect(anyhow!(
            "B2 media connection failed before request dispatch"
        ))),
        Ok(Err(_)) => Err(B2SendError::Transport(anyhow!(
            "B2 media transport failed; write outcome may be unconfirmed"
        ))),
        Err(_) => Err(B2SendError::Timeout(anyhow!(
            "B2 media headers timed out; write outcome may be unconfirmed"
        ))),
    }
}

fn b2_transient_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 500 | 502 | 503 | 504)
}

fn write_rejected(status: u16) -> bool {
    // Explicit refusal. A transport error, 408, or server error may follow
    // a committed mutation and must keep the journal in Writing.
    matches!(status, 400 | 401 | 403 | 404 | 409 | 411 | 412 | 413 | 429)
}

fn gcs_generation_from_metadata(object: &ObjectMetadata) -> Result<i64> {
    gcs_generation(object.reference.version.as_deref())?.context("Missing GCS generation")
}

fn from_gcs(bucket: &str, key: &str, object: Object) -> Result<ObjectMetadata> {
    if object.name != key
        || object.generation <= 0
        || object.size < 0
        || (!object.bucket.is_empty() && object.bucket != bucket)
    {
        bail!("GCS object identity invalid");
    }
    Ok(ObjectMetadata {
        reference: ObjectRef {
            provider: StorageProvider::Gcs,
            bucket: bucket.into(),
            key: key.into(),
            version: Some(object.generation.to_string()),
        },
        size: object.size as u64,
        content_type: object.content_type.ok_or(MissingGcsMime)?,
        custom: object.metadata.unwrap_or_default(),
        cache_control: object.cache_control,
    })
}
fn from_b2(bucket: &str, key: &str, headers: &HeaderMap) -> Result<ObjectMetadata> {
    let version = required(headers, "x-amz-version-id")?;
    if !valid_version(&version) {
        bail!("B2 version invalid");
    }
    let mut custom = HashMap::new();
    for name in headers.keys() {
        if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
            custom.insert(key.into(), required(headers, name.as_str())?);
        }
    }
    Ok(ObjectMetadata {
        reference: ObjectRef {
            provider: StorageProvider::B2,
            bucket: bucket.into(),
            key: key.into(),
            version: Some(version),
        },
        size: required(headers, "content-length")?
            .parse()
            .context("B2 object size invalid")?,
        content_type: required(headers, "content-type")?,
        custom,
        cache_control: optional(headers, "cache-control")?,
    })
}
fn optional(headers: &HeaderMap, name: &str) -> Result<Option<String>> {
    if headers.get_all(name).iter().count() > 1 {
        bail!("Ambiguous media response header");
    }
    headers
        .get(name)
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| anyhow!("Invalid media response header"))
        })
        .transpose()
}
fn required(headers: &HeaderMap, name: &str) -> Result<String> {
    optional(headers, name)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("Required media response header missing"))
}
fn successful(status: StatusCode) -> Result<()> {
    if !status.is_success() {
        bail!("Private media request failed ({status})");
    }
    Ok(())
}
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version != "null"
        && version.len() <= 1024
        && version.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}
fn gcs_generation(version: Option<&str>) -> Result<Option<i64>> {
    version
        .map(|v| {
            v.parse::<i64>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| anyhow!("GCS pinned generation invalid"))
        })
        .transpose()
}
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 1024
        || key
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
        || key.bytes().any(|b| b.is_ascii_control() || b == b'\\')
    {
        bail!("Invalid media object key");
    }
    Ok(())
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "object_storage_tests.rs"]
pub(crate) mod tests;

fn backup_metadata_matches(primary: &ObjectMetadata, replica: &ObjectMetadata) -> bool {
    primary.size == replica.size
        && primary.content_type == replica.content_type
        && primary.custom == replica.custom
        && primary.cache_control == replica.cache_control
}
