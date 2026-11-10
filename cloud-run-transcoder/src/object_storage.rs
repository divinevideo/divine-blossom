//! Private, version-pinned media I/O. Locks, jobs and readiness use other APIs.

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
    collections::{BTreeMap, HashMap},
    path::Path,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_STALL_TIMEOUT: Duration = Duration::from_secs(30);

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
                    Self::B2Primary {
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
        }
    }
    pub fn configured(
        config: StorageConfiguration,
        gcs: Option<GcsClient>,
        gcs_bucket: String,
    ) -> Result<Self> {
        let backup_required = matches!(&config, StorageConfiguration::B2Primary { .. });
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
            } => {
                let required_backup = if backup_required {
                    if gcs_bucket.is_empty() {
                        bail!("GCS backup bucket required for B2 primary");
                    }
                    Some(Box::new(Self::gcs(
                        gcs.ok_or_else(|| anyhow!("GCS backup client required for B2 primary"))?,
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
                    required_backup,
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
        let Some(backup) = &self.required_backup else {
            return Ok(self.stat(&format!("{prefix}/master.m3u8")).await?.is_some());
        };
        // The encoder emits two single-file TS variants. A master alone cannot
        // prove their backups succeeded, and regenerating every duplicate job
        // would discard the existing at-least-once dispatch's idempotency.
        for (filename, required) in [
            ("master.m3u8", true),
            ("stream_720p.m3u8", true),
            ("stream_480p.m3u8", true),
            ("stream_720p.ts", true),
            ("stream_480p.ts", true),
            ("stream_720p.mp4", false),
            ("stream_480p.mp4", false),
        ] {
            let key = format!("{prefix}/{filename}");
            let Some(primary) = self.stat(&key).await? else {
                if required {
                    return Ok(false);
                }
                // Progressive remux is best-effort; absent MP4s are not HLS
                // failures, but any MP4 actually written needs its backup.
                continue;
            };
            let Some(replica) = backup.stat(&key).await? else {
                return Ok(false);
            };
            if primary.size != replica.size
                || primary.content_type != replica.content_type
                || primary.custom != replica.custom
                || primary.cache_control != replica.cache_control
                || self.hash_body(&primary, None).await?
                    != backup.hash_body(&replica, None).await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Preserve the primary's provenance when shared audio needs a backup.
    pub async fn ensure_existing_backup(
        &self,
        primary: &ObjectMetadata,
        body: Bytes,
    ) -> Result<()> {
        if let Some(backup) = &self.required_backup {
            self.validate_reference(&primary.reference)?;
            let sha = hex::encode(Sha256::digest(&body));
            if primary.size != body.len() as u64 {
                bail!("Existing output size does not match backup bytes");
            }
            self.verify_sha256(primary, &sha).await?;
            backup
                .put_single_verified(
                    &primary.reference.key,
                    body,
                    &primary.content_type,
                    primary.custom.clone(),
                    primary.cache_control.clone(),
                )
                .await
                .context("Required GCS backup of existing output was not verified")?;
        }
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
                let response = self
                    .b2_request(B2Request {
                        method: Method::HEAD,
                        key,
                        version,
                        body: Bytes::new(),
                        mime: None,
                        cache: None,
                        custom: &HashMap::new(),
                    })
                    .await?;
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
                    .b2_request(B2Request {
                        method: Method::GET,
                        key: &object.reference.key,
                        version: object.reference.version.as_deref(),
                        body: Bytes::new(),
                        mime: None,
                        cache: None,
                        custom: &HashMap::new(),
                    })
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
    /// Prefer the selected provider. During a B2-primary migration, only an
    /// absent original may fall back to its legacy GCS location; provider
    /// failures or failed verification must never select another source.
    pub async fn download_processing_original(
        &self,
        expected_sha: &str,
        path: &Path,
    ) -> Result<VerifiedObject> {
        if !is_sha256(expected_sha) {
            bail!("Original SHA-256 identity invalid");
        }
        if let Some(object) = self.stat(expected_sha).await? {
            return self.download_original(&object, expected_sha, path).await;
        }
        let legacy = self
            .required_backup
            .as_deref()
            .ok_or_else(|| anyhow!("Original not found"))?;
        let object = legacy
            .stat(expected_sha)
            .await?
            .ok_or_else(|| anyhow!("Original not found"))?;
        legacy.download_original(&object, expected_sha, path).await
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
        let directory = path
            .parent()
            .ok_or_else(|| anyhow!("Original output directory missing"))?;
        let temp = tempfile::NamedTempFile::new_in(directory)?;
        let mut writer = tokio::fs::File::from_std(temp.reopen()?);
        let sha256 = self.hash_body(object, Some(&mut writer)).await?;
        if sha256 != expected_sha {
            bail!("Original SHA-256 verification failed");
        }
        writer.flush().await?;
        drop(writer);
        temp.persist(path)
            .map_err(|_| anyhow!("Verified original could not be published"))?;
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
        let mut primary = self
            .put_single_verified(
                key,
                body.clone(),
                mime,
                custom.clone(),
                cache_control.clone(),
            )
            .await?;
        if let Some(backup) = &self.required_backup {
            let replica = backup
                .put_single_verified(key, body, mime, custom, cache_control)
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
    async fn put_single_verified(
        &self,
        key: &str,
        body: Bytes,
        mime: &str,
        custom: HashMap<String, String>,
        cache_control: Option<String>,
    ) -> Result<VerifiedObject> {
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
                let object = tokio::time::timeout(
                    CONTROL_TIMEOUT,
                    client.upload_object(
                        &UploadObjectRequest {
                            bucket: bucket.clone(),
                            ..Default::default()
                        },
                        body.clone(),
                        &UploadType::Multipart(Box::new(metadata)),
                    ),
                )
                .await
                .context("GCS media write deadline; outcome unconfirmed")?
                .map_err(|_| anyhow!("GCS media write failed; outcome unconfirmed"))?;
                from_gcs(bucket, key, object)?.reference
            }
            Backend::B2 { .. } => {
                let response = self
                    .b2_request(B2Request {
                        method: Method::PUT,
                        key,
                        version: None,
                        body: body.clone(),
                        mime: Some(mime),
                        cache: cache_control.as_deref(),
                        custom: &custom,
                    })
                    .await?;
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
    async fn b2_request(&self, request: B2Request<'_>) -> Result<reqwest::Response> {
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
        tokio::time::timeout(CONTROL_TIMEOUT, request.body(body).send())
            .await
            .context("B2 media headers timed out; write outcome may be unconfirmed")?
            .map_err(|_| anyhow!("B2 media transport failed; write outcome may be unconfirmed"))
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
        content_type: object
            .content_type
            .ok_or_else(|| anyhow!("GCS object MIME missing"))?,
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
mod tests;
