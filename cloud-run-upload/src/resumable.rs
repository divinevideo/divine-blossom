use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt};
use google_cloud_storage::{
    client::Client as GcsClient,
    http::{
        objects::{
            copy::CopyObjectRequest,
            delete::DeleteObjectRequest,
            download::Range as DownloadRange,
            get::GetObjectRequest,
            upload::{Media, UploadObjectRequest, UploadType},
            Object,
        },
        resumable_upload_client::{ChunkSize, UploadStatus},
    },
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_RESUMABLE_CHUNK_SIZE: u64 = 8 * 1024 * 1024;
pub const DEFAULT_RESUMABLE_SESSION_TTL_SECS: u64 = 24 * 60 * 60;
pub const SESSION_OFFSET_HEADER: &str = "Upload-Offset";
pub const SESSION_LENGTH_HEADER: &str = "Upload-Length";
pub const SESSION_EXPIRES_HEADER: &str = "Upload-Expires";
pub const SESSION_CHUNK_SIZE_HEADER: &str = "X-Divine-Chunk-Size";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableUploadInitRequest {
    pub sha256: String,
    pub size: u64,
    #[serde(alias = "content_type")]
    pub content_type: String,
    #[serde(alias = "file_name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableUploadInitResponse {
    pub upload_id: String,
    pub upload_url: String,
    pub expires_at: String,
    pub chunk_size: u64,
    pub next_offset: u64,
    #[serde(default)]
    pub required_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteUploadResponse {
    pub sha256: String,
    pub size: u64,
    #[serde(alias = "content_type")]
    pub content_type: String,
    #[serde(alias = "thumbnail_url")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionStatus {
    pub next_offset: u64,
    pub declared_size: u64,
    pub expires_at: String,
    pub chunk_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadSession {
    pub upload_id: String,
    pub owner: String,
    pub final_sha256: String,
    pub declared_size: u64,
    pub content_type: String,
    pub file_name: Option<String>,
    pub expires_at_epoch_secs: u64,
    pub next_offset: u64,
    pub session_url: String,
    pub session_token: String,
    pub temp_object: String,
    pub storage_complete: bool,
    pub finalized_object: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total: u64,
}

impl ContentRange {
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendCreateSession {
    pub session_url: String,
    pub temp_object: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendUploadState {
    InProgress,
    Completed,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ResumableError {
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Gone(String),
    #[error("{0}")]
    RangeNotSatisfiable(String),
    #[error("{0}")]
    UnprocessableEntity(String),
    #[error("{0}")]
    Internal(String),
}

impl ResumableError {
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            ResumableError::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            ResumableError::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            ResumableError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
            ResumableError::Conflict(_) => axum::http::StatusCode::CONFLICT,
            ResumableError::Gone(_) => axum::http::StatusCode::GONE,
            ResumableError::RangeNotSatisfiable(_) => axum::http::StatusCode::RANGE_NOT_SATISFIABLE,
            ResumableError::UnprocessableEntity(_) => axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            ResumableError::Internal(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[async_trait]
pub trait SessionStore: Clone + Send + Sync + 'static {
    async fn load(&self, upload_id: &str) -> Result<Option<UploadSession>>;
    async fn save(&self, session: &UploadSession) -> Result<()>;
    async fn delete(&self, upload_id: &str) -> Result<()>;
}

#[async_trait]
pub trait ResumableBackend: Clone + Send + Sync + 'static {
    async fn create_session(
        &self,
        upload_id: &str,
        owner: &str,
        content_type: &str,
        declared_size: u64,
    ) -> Result<BackendCreateSession>;

    async fn upload_chunk(
        &self,
        session: &UploadSession,
        range: &ContentRange,
        chunk: Bytes,
    ) -> Result<BackendUploadState>;

    async fn cancel_session(&self, session: &UploadSession) -> Result<()>;

    async fn stream_object(&self, object_key: &str) -> Result<BoxStream<'static, Result<Bytes>>>;

    async fn object_exists(&self, object_key: &str) -> Result<bool>;

    async fn copy_to_final(
        &self,
        source_key: &str,
        destination_key: &str,
        content_type: &str,
        owner: &str,
    ) -> Result<()>;

    async fn delete_object(&self, object_key: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct ResumableManager<B, S> {
    backend: B,
    store: S,
    upload_base_url: String,
    chunk_size: u64,
    session_ttl_secs: u64,
}

impl<B, S> ResumableManager<B, S>
where
    B: ResumableBackend,
    S: SessionStore,
{
    pub fn new(
        backend: B,
        store: S,
        upload_base_url: impl Into<String>,
        chunk_size: u64,
        session_ttl_secs: u64,
    ) -> Self {
        Self {
            backend,
            store,
            upload_base_url: upload_base_url.into().trim_end_matches('/').to_string(),
            chunk_size,
            session_ttl_secs,
        }
    }

    pub async fn init_session(
        &self,
        owner: &str,
        request: ResumableUploadInitRequest,
    ) -> std::result::Result<ResumableUploadInitResponse, ResumableError> {
        validate_init_request(&request)?;

        let upload_id = format!("up_{}", random_hex(12));
        let session_token = format!("tok_{}", random_hex(24));
        let backend_session = self
            .backend
            .create_session(&upload_id, owner, &request.content_type, request.size)
            .await
            .map_err(internal_error)?;
        let expires_at_epoch_secs = now_epoch_secs().saturating_add(self.session_ttl_secs);

        let session = UploadSession {
            upload_id: upload_id.clone(),
            owner: owner.to_string(),
            final_sha256: request.sha256.to_lowercase(),
            declared_size: request.size,
            content_type: request.content_type.clone(),
            file_name: request.file_name.clone(),
            expires_at_epoch_secs,
            next_offset: 0,
            session_url: backend_session.session_url,
            session_token: session_token.clone(),
            temp_object: backend_session.temp_object,
            storage_complete: false,
            finalized_object: None,
        };

        self.store.save(&session).await.map_err(internal_error)?;

        let mut required_headers = HashMap::new();
        required_headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", session_token),
        );
        required_headers.insert("Content-Type".to_string(), request.content_type);

        Ok(ResumableUploadInitResponse {
            upload_id: upload_id.clone(),
            upload_url: format!("{}/sessions/{}", self.upload_base_url, upload_id),
            expires_at: expires_at_epoch_secs.to_string(),
            chunk_size: self.chunk_size,
            next_offset: 0,
            required_headers,
        })
    }

    pub async fn head_session(
        &self,
        upload_id: &str,
        authorization: Option<&str>,
    ) -> std::result::Result<UploadSessionStatus, ResumableError> {
        let session = self.authorize_session(upload_id, authorization).await?;

        Ok(UploadSessionStatus {
            next_offset: session.next_offset,
            declared_size: session.declared_size,
            expires_at: session.expires_at_epoch_secs.to_string(),
            chunk_size: self.chunk_size,
        })
    }

    pub async fn upload_chunk(
        &self,
        upload_id: &str,
        authorization: Option<&str>,
        content_range: &str,
        chunk: Bytes,
    ) -> std::result::Result<UploadSessionStatus, ResumableError> {
        let mut session = self.authorize_session(upload_id, authorization).await?;
        if session.finalized_object.is_some() {
            return Err(ResumableError::Conflict(
                "Upload session already finalized".to_string(),
            ));
        }

        let range = parse_content_range(content_range, session.declared_size)?;
        if range.start != session.next_offset {
            return Err(ResumableError::RangeNotSatisfiable(format!(
                "Expected next offset {}, got {}",
                session.next_offset, range.start
            )));
        }

        if range.len() != chunk.len() as u64 {
            return Err(ResumableError::RangeNotSatisfiable(format!(
                "Content-Range length {} does not match body length {}",
                range.len(),
                chunk.len()
            )));
        }

        let is_final_chunk = range.end + 1 == session.declared_size;
        if !is_final_chunk && range.len() % (256 * 1024) != 0 {
            return Err(ResumableError::UnprocessableEntity(
                "Chunk size must be a multiple of 256 KiB unless it completes the upload"
                    .to_string(),
            ));
        }

        let upload_state = self
            .backend
            .upload_chunk(&session, &range, chunk)
            .await
            .map_err(internal_error)?;

        session.next_offset = range.end + 1;
        if matches!(upload_state, BackendUploadState::Completed) {
            session.storage_complete = true;
        }
        self.store.save(&session).await.map_err(internal_error)?;

        Ok(UploadSessionStatus {
            next_offset: session.next_offset,
            declared_size: session.declared_size,
            expires_at: session.expires_at_epoch_secs.to_string(),
            chunk_size: self.chunk_size,
        })
    }

    pub async fn complete_session(
        &self,
        upload_id: &str,
        owner: &str,
    ) -> std::result::Result<CompleteUploadResponse, ResumableError> {
        let mut session = self
            .store
            .load(upload_id)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| ResumableError::NotFound("Upload session not found".to_string()))?;

        if session.owner != owner {
            return Err(ResumableError::Unauthorized(
                "Upload session does not belong to the authenticated user".to_string(),
            ));
        }

        if session.expires_at_epoch_secs <= now_epoch_secs() {
            self.cleanup_expired_session(&session).await;
            return Err(ResumableError::Gone("Upload session expired".to_string()));
        }

        if session.next_offset != session.declared_size {
            return Err(ResumableError::Conflict(format!(
                "Upload incomplete: {} of {} bytes committed",
                session.next_offset, session.declared_size
            )));
        }

        if let Some(finalized_object) = session.finalized_object.as_ref() {
            return Ok(CompleteUploadResponse {
                sha256: finalized_object.clone(),
                size: session.declared_size,
                content_type: session.content_type.clone(),
                thumbnail_url: None,
                dim: None,
            });
        }

        let (computed_hash, computed_size) = self
            .hash_temp_object(&session.temp_object)
            .await
            .map_err(internal_error)?;
        if computed_hash != session.final_sha256 {
            let _ = self.backend.delete_object(&session.temp_object).await;
            let _ = self.store.delete(upload_id).await;
            return Err(ResumableError::UnprocessableEntity(format!(
                "Uploaded bytes hashed to {}, expected {}",
                computed_hash, session.final_sha256
            )));
        }
        if computed_size != session.declared_size {
            return Err(ResumableError::UnprocessableEntity(format!(
                "Uploaded bytes totalled {} bytes, expected {}",
                computed_size, session.declared_size
            )));
        }

        if !self
            .backend
            .object_exists(&session.final_sha256)
            .await
            .map_err(internal_error)?
        {
            self.backend
                .copy_to_final(
                    &session.temp_object,
                    &session.final_sha256,
                    &session.content_type,
                    &session.owner,
                )
                .await
                .map_err(internal_error)?;
        }

        let _ = self.backend.delete_object(&session.temp_object).await;
        session.storage_complete = true;
        session.finalized_object = Some(session.final_sha256.clone());
        self.store.save(&session).await.map_err(internal_error)?;

        Ok(CompleteUploadResponse {
            sha256: session.final_sha256.clone(),
            size: session.declared_size,
            content_type: session.content_type.clone(),
            thumbnail_url: None,
            dim: None,
        })
    }

    pub async fn abort_session(
        &self,
        upload_id: &str,
        authorization: Option<&str>,
    ) -> std::result::Result<(), ResumableError> {
        let session = self.authorize_session(upload_id, authorization).await?;
        if session.finalized_object.is_some() {
            return Err(ResumableError::Conflict(
                "Upload session already finalized".to_string(),
            ));
        }

        self.backend
            .cancel_session(&session)
            .await
            .map_err(internal_error)?;
        let _ = self.backend.delete_object(&session.temp_object).await;
        self.store.delete(upload_id).await.map_err(internal_error)?;
        Ok(())
    }

    async fn authorize_session(
        &self,
        upload_id: &str,
        authorization: Option<&str>,
    ) -> std::result::Result<UploadSession, ResumableError> {
        let session = self
            .store
            .load(upload_id)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| ResumableError::NotFound("Upload session not found".to_string()))?;

        if session.expires_at_epoch_secs <= now_epoch_secs() {
            self.cleanup_expired_session(&session).await;
            return Err(ResumableError::Gone("Upload session expired".to_string()));
        }

        let token = parse_bearer_token(authorization).ok_or_else(|| {
            ResumableError::Unauthorized("Bearer upload token required".to_string())
        })?;
        if token != session.session_token {
            return Err(ResumableError::Unauthorized(
                "Invalid upload session token".to_string(),
            ));
        }

        Ok(session)
    }

    async fn cleanup_expired_session(&self, session: &UploadSession) {
        if session.finalized_object.is_none() {
            let _ = self.backend.cancel_session(session).await;
            let _ = self.backend.delete_object(&session.temp_object).await;
        }
        let _ = self.store.delete(&session.upload_id).await;
    }

    async fn hash_temp_object(&self, object_key: &str) -> Result<(String, u64)> {
        let mut stream = self.backend.stream_object(object_key).await?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size = size.saturating_add(chunk.len() as u64);
            hasher.update(&chunk);
        }

        Ok((hex::encode(hasher.finalize()), size))
    }
}

#[derive(Clone)]
pub struct GcsSessionStore {
    client: GcsClient,
    bucket: String,
}

impl GcsSessionStore {
    pub fn new(client: GcsClient, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    fn session_object_key(upload_id: &str) -> String {
        format!("__resumable/sessions/{}.json", upload_id)
    }
}

#[async_trait]
impl SessionStore for GcsSessionStore {
    async fn load(&self, upload_id: &str) -> Result<Option<UploadSession>> {
        let object = Self::session_object_key(upload_id);
        match self
            .client
            .download_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object,
                    ..Default::default()
                },
                &DownloadRange::default(),
            )
            .await
        {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if is_not_found_error(&error) => Ok(None),
            Err(error) => Err(anyhow!("Failed to load session manifest: {}", error)),
        }
    }

    async fn save(&self, session: &UploadSession) -> Result<()> {
        let object = Self::session_object_key(&session.upload_id);
        let payload = serde_json::to_vec(session)?;
        let mut media = Media::new(object);
        media.content_type = "application/json".into();
        media.content_length = Some(payload.len() as u64);
        let upload_type = UploadType::Simple(media);

        self.client
            .upload_object(
                &UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    ..Default::default()
                },
                payload,
                &upload_type,
            )
            .await
            .map_err(|error| anyhow!("Failed to persist session manifest: {}", error))?;

        Ok(())
    }

    async fn delete(&self, upload_id: &str) -> Result<()> {
        let object = Self::session_object_key(upload_id);
        match self
            .client
            .delete_object(&DeleteObjectRequest {
                bucket: self.bucket.clone(),
                object,
                ..Default::default()
            })
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found_error(&error) => Ok(()),
            Err(error) => Err(anyhow!("Failed to delete session manifest: {}", error)),
        }
    }
}

#[derive(Clone)]
pub struct GcsResumableBackend {
    client: GcsClient,
    bucket: String,
}

impl GcsResumableBackend {
    pub fn new(client: GcsClient, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    fn temp_object_key(upload_id: &str) -> String {
        format!("__resumable/uploads/{}/blob", upload_id)
    }
}

#[async_trait]
impl ResumableBackend for GcsResumableBackend {
    async fn create_session(
        &self,
        upload_id: &str,
        owner: &str,
        content_type: &str,
        _declared_size: u64,
    ) -> Result<BackendCreateSession> {
        let temp_object = Self::temp_object_key(upload_id);
        let mut metadata_map = HashMap::new();
        metadata_map.insert("owner".to_string(), owner.to_string());
        metadata_map.insert("upload_id".to_string(), upload_id.to_string());

        let upload_type = UploadType::Multipart(Box::new(Object {
            name: temp_object.clone(),
            content_type: Some(content_type.to_string()),
            metadata: Some(metadata_map),
            ..Default::default()
        }));
        let uploader = self
            .client
            .prepare_resumable_upload(
                &UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    if_generation_match: Some(0),
                    ..Default::default()
                },
                &upload_type,
            )
            .await
            .map_err(|error| anyhow!("Failed to prepare resumable upload: {}", error))?;

        Ok(BackendCreateSession {
            session_url: uploader.url().to_string(),
            temp_object,
        })
    }

    async fn upload_chunk(
        &self,
        session: &UploadSession,
        range: &ContentRange,
        chunk: Bytes,
    ) -> Result<BackendUploadState> {
        let uploader = self
            .client
            .get_resumable_upload(session.session_url.clone());
        let status = uploader
            .upload_multiple_chunk(
                chunk,
                &ChunkSize::new(range.start, range.end, Some(range.total)),
            )
            .await
            .map_err(|error| anyhow!("Failed to upload resumable chunk: {}", error))?;

        Ok(match status {
            UploadStatus::ResumeIncomplete => BackendUploadState::InProgress,
            UploadStatus::Ok(_) => BackendUploadState::Completed,
        })
    }

    async fn cancel_session(&self, session: &UploadSession) -> Result<()> {
        self.client
            .get_resumable_upload(session.session_url.clone())
            .cancel()
            .await
            .map_err(|error| anyhow!("Failed to cancel resumable upload: {}", error))
    }

    async fn stream_object(&self, object_key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let stream = self
            .client
            .download_streamed_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: object_key.to_string(),
                    ..Default::default()
                },
                &DownloadRange::default(),
            )
            .await
            .map_err(|error| anyhow!("Failed to stream object {}: {}", object_key, error))?;
        Ok(stream
            .map(|chunk| chunk.map_err(anyhow::Error::from))
            .boxed())
    }

    async fn object_exists(&self, object_key: &str) -> Result<bool> {
        match self
            .client
            .get_object(&GetObjectRequest {
                bucket: self.bucket.clone(),
                object: object_key.to_string(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_not_found_error(&error) => Ok(false),
            Err(error) => Err(anyhow!("Failed to check object existence: {}", error)),
        }
    }

    async fn copy_to_final(
        &self,
        source_key: &str,
        destination_key: &str,
        content_type: &str,
        owner: &str,
    ) -> Result<()> {
        let mut metadata_map = HashMap::new();
        metadata_map.insert("owner".to_string(), owner.to_string());

        self.client
            .copy_object(&CopyObjectRequest {
                source_bucket: self.bucket.clone(),
                source_object: source_key.to_string(),
                destination_bucket: self.bucket.clone(),
                destination_object: destination_key.to_string(),
                if_generation_match: Some(0),
                metadata: Some(Object {
                    name: destination_key.to_string(),
                    content_type: Some(content_type.to_string()),
                    metadata: Some(metadata_map),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .map_err(|error| anyhow!("Failed to copy final object: {}", error))?;

        Ok(())
    }

    async fn delete_object(&self, object_key: &str) -> Result<()> {
        match self
            .client
            .delete_object(&DeleteObjectRequest {
                bucket: self.bucket.clone(),
                object: object_key.to_string(),
                ..Default::default()
            })
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found_error(&error) => Ok(()),
            Err(error) => Err(anyhow!("Failed to delete object {}: {}", object_key, error)),
        }
    }
}

pub fn parse_content_range(
    raw: &str,
    expected_total: u64,
) -> std::result::Result<ContentRange, ResumableError> {
    let raw = raw.trim();
    let range = raw.strip_prefix("bytes ").ok_or_else(|| {
        ResumableError::BadRequest("Content-Range must start with 'bytes '".to_string())
    })?;
    let (range_part, total_part) = range.split_once('/').ok_or_else(|| {
        ResumableError::BadRequest("Content-Range must include total size".to_string())
    })?;
    let total: u64 = total_part.parse().map_err(|_| {
        ResumableError::BadRequest("Invalid total size in Content-Range".to_string())
    })?;
    if total != expected_total {
        return Err(ResumableError::RangeNotSatisfiable(format!(
            "Declared total {} does not match session size {}",
            total, expected_total
        )));
    }

    let (start_part, end_part) = range_part.split_once('-').ok_or_else(|| {
        ResumableError::BadRequest("Content-Range must include start and end offsets".to_string())
    })?;
    let start: u64 = start_part.parse().map_err(|_| {
        ResumableError::BadRequest("Invalid start offset in Content-Range".to_string())
    })?;
    let end: u64 = end_part.parse().map_err(|_| {
        ResumableError::BadRequest("Invalid end offset in Content-Range".to_string())
    })?;

    if start > end || end >= total {
        return Err(ResumableError::RangeNotSatisfiable(
            "Content-Range is outside the declared upload size".to_string(),
        ));
    }

    Ok(ContentRange { start, end, total })
}

fn validate_init_request(
    request: &ResumableUploadInitRequest,
) -> std::result::Result<(), ResumableError> {
    if request.size == 0 {
        return Err(ResumableError::BadRequest(
            "Upload size must be greater than zero".to_string(),
        ));
    }
    if request.content_type.trim().is_empty() {
        return Err(ResumableError::BadRequest(
            "Content type is required".to_string(),
        ));
    }
    if request.sha256.len() != 64 || !request.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ResumableError::BadRequest(
            "sha256 must be a 64-character hexadecimal string".to_string(),
        ));
    }

    Ok(())
}

fn random_hex(num_bytes: usize) -> String {
    let mut bytes = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_bearer_token(authorization: Option<&str>) -> Option<&str> {
    authorization.and_then(|value| value.strip_prefix("Bearer "))
}

fn internal_error(error: anyhow::Error) -> ResumableError {
    ResumableError::Internal(error.to_string())
}

fn is_not_found_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("404") || message.contains("Not Found") || message.contains("No such object")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct InMemoryStore {
        sessions: Arc<Mutex<HashMap<String, UploadSession>>>,
    }

    #[async_trait]
    impl SessionStore for InMemoryStore {
        async fn load(&self, upload_id: &str) -> Result<Option<UploadSession>> {
            Ok(self.sessions.lock().await.get(upload_id).cloned())
        }

        async fn save(&self, session: &UploadSession) -> Result<()> {
            self.sessions
                .lock()
                .await
                .insert(session.upload_id.clone(), session.clone());
            Ok(())
        }

        async fn delete(&self, upload_id: &str) -> Result<()> {
            self.sessions.lock().await.remove(upload_id);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeBackend {
        temp_objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        final_objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    #[async_trait]
    impl ResumableBackend for FakeBackend {
        async fn create_session(
            &self,
            upload_id: &str,
            _owner: &str,
            _content_type: &str,
            _declared_size: u64,
        ) -> Result<BackendCreateSession> {
            Ok(BackendCreateSession {
                session_url: format!("https://gcs.example/upload/{}", upload_id),
                temp_object: format!("temp/{}", upload_id),
            })
        }

        async fn upload_chunk(
            &self,
            session: &UploadSession,
            range: &ContentRange,
            chunk: Bytes,
        ) -> Result<BackendUploadState> {
            let mut temp_objects = self.temp_objects.lock().await;
            let buffer = temp_objects
                .entry(session.temp_object.clone())
                .or_insert_with(Vec::new);
            if buffer.len() as u64 != range.start {
                return Err(anyhow!(
                    "fake backend expected start {}, got {}",
                    buffer.len(),
                    range.start
                ));
            }
            buffer.extend_from_slice(&chunk);
            Ok(if range.end + 1 == range.total {
                BackendUploadState::Completed
            } else {
                BackendUploadState::InProgress
            })
        }

        async fn cancel_session(&self, _session: &UploadSession) -> Result<()> {
            Ok(())
        }

        async fn stream_object(
            &self,
            object_key: &str,
        ) -> Result<BoxStream<'static, Result<Bytes>>> {
            let data = self
                .temp_objects
                .lock()
                .await
                .get(object_key)
                .cloned()
                .ok_or_else(|| anyhow!("missing temp object {}", object_key))?;
            Ok(stream::iter(vec![Ok(Bytes::from(data))]).boxed())
        }

        async fn object_exists(&self, object_key: &str) -> Result<bool> {
            Ok(self.final_objects.lock().await.contains_key(object_key))
        }

        async fn copy_to_final(
            &self,
            source_key: &str,
            destination_key: &str,
            _content_type: &str,
            _owner: &str,
        ) -> Result<()> {
            let data = self
                .temp_objects
                .lock()
                .await
                .get(source_key)
                .cloned()
                .ok_or_else(|| anyhow!("missing temp object {}", source_key))?;
            self.final_objects
                .lock()
                .await
                .insert(destination_key.to_string(), data);
            Ok(())
        }

        async fn delete_object(&self, object_key: &str) -> Result<()> {
            self.temp_objects.lock().await.remove(object_key);
            self.final_objects.lock().await.remove(object_key);
            Ok(())
        }
    }

    fn manager() -> ResumableManager<FakeBackend, InMemoryStore> {
        ResumableManager::new(
            FakeBackend::default(),
            InMemoryStore::default(),
            "https://upload.divine.video",
            DEFAULT_RESUMABLE_CHUNK_SIZE,
            DEFAULT_RESUMABLE_SESSION_TTL_SECS,
        )
    }

    #[tokio::test]
    async fn init_creates_session_and_returns_upload_url() {
        let manager = manager();

        let response = manager
            .init_session(
                "owner_pubkey",
                ResumableUploadInitRequest {
                    sha256: "5b48aa1fcf30af61243ac9307eb98b7fa22df1c58573c3ca5d1b14fc30099929"
                        .to_string(),
                    size: 1024,
                    content_type: "video/mp4".to_string(),
                    file_name: Some("video.mp4".to_string()),
                },
            )
            .await
            .expect("init response");

        assert!(response.upload_id.starts_with("up_"));
        assert_eq!(
            response.upload_url,
            format!(
                "https://upload.divine.video/sessions/{}",
                response.upload_id
            )
        );
        assert_eq!(response.next_offset, 0);
        assert_eq!(response.chunk_size, DEFAULT_RESUMABLE_CHUNK_SIZE);
        assert!(response.required_headers.contains_key("Authorization"));
    }

    #[test]
    fn init_request_accepts_camel_case_and_legacy_snake_case_fields() {
        let camel_case: ResumableUploadInitRequest = serde_json::from_value(serde_json::json!({
            "sha256": "5b48aa1fcf30af61243ac9307eb98b7fa22df1c58573c3ca5d1b14fc30099929",
            "size": 1024,
            "contentType": "video/mp4",
            "fileName": "video.mp4"
        }))
        .expect("camelCase init request");
        assert_eq!(camel_case.content_type, "video/mp4");
        assert_eq!(camel_case.file_name.as_deref(), Some("video.mp4"));

        let snake_case: ResumableUploadInitRequest = serde_json::from_value(serde_json::json!({
            "sha256": "5b48aa1fcf30af61243ac9307eb98b7fa22df1c58573c3ca5d1b14fc30099929",
            "size": 1024,
            "content_type": "video/mp4",
            "file_name": "video.mp4"
        }))
        .expect("snake_case init request");
        assert_eq!(snake_case.content_type, "video/mp4");
        assert_eq!(snake_case.file_name.as_deref(), Some("video.mp4"));
    }

    #[test]
    fn init_response_serializes_mobile_contract_field_names() {
        let response = ResumableUploadInitResponse {
            upload_id: "up_123".to_string(),
            upload_url: "https://upload.divine.video/sessions/up_123".to_string(),
            expires_at: "1234567890".to_string(),
            chunk_size: DEFAULT_RESUMABLE_CHUNK_SIZE,
            next_offset: 0,
            required_headers: HashMap::from([(
                "Authorization".to_string(),
                "Bearer token".to_string(),
            )]),
        };

        let json = serde_json::to_value(&response).expect("serialize init response");

        assert_eq!(json["uploadId"], "up_123");
        assert_eq!(
            json["uploadUrl"],
            "https://upload.divine.video/sessions/up_123"
        );
        assert_eq!(json["expiresAt"], "1234567890");
        assert_eq!(json["chunkSize"], DEFAULT_RESUMABLE_CHUNK_SIZE);
        assert_eq!(json["nextOffset"], 0);
        assert_eq!(json["requiredHeaders"]["Authorization"], "Bearer token");
        assert!(json.get("upload_id").is_none());
        assert!(json.get("required_headers").is_none());
    }

    #[tokio::test]
    async fn head_session_returns_committed_offset() {
        let manager = manager();
        let response = manager
            .init_session(
                "owner_pubkey",
                ResumableUploadInitRequest {
                    sha256: "5b48aa1fcf30af61243ac9307eb98b7fa22df1c58573c3ca5d1b14fc30099929"
                        .to_string(),
                    size: 1024 * 1024,
                    content_type: "video/mp4".to_string(),
                    file_name: None,
                },
            )
            .await
            .expect("init response");
        let auth = response
            .required_headers
            .get("Authorization")
            .expect("session auth")
            .to_string();

        let status = manager
            .upload_chunk(
                &response.upload_id,
                Some(&auth),
                "bytes 0-262143/1048576",
                Bytes::from(vec![7u8; 256 * 1024]),
            )
            .await
            .expect("chunk upload");

        assert_eq!(status.next_offset, 256 * 1024);

        let head = manager
            .head_session(&response.upload_id, Some(&auth))
            .await
            .expect("head session");
        assert_eq!(head.next_offset, 256 * 1024);
        assert_eq!(head.declared_size, 1024 * 1024);
    }

    #[tokio::test]
    async fn put_session_chunk_rejects_non_contiguous_ranges() {
        let manager = manager();
        let response = manager
            .init_session(
                "owner_pubkey",
                ResumableUploadInitRequest {
                    sha256: "5b48aa1fcf30af61243ac9307eb98b7fa22df1c58573c3ca5d1b14fc30099929"
                        .to_string(),
                    size: 1024 * 1024,
                    content_type: "video/mp4".to_string(),
                    file_name: None,
                },
            )
            .await
            .expect("init response");
        let auth = response
            .required_headers
            .get("Authorization")
            .expect("session auth")
            .to_string();

        manager
            .upload_chunk(
                &response.upload_id,
                Some(&auth),
                "bytes 0-262143/1048576",
                Bytes::from(vec![1u8; 256 * 1024]),
            )
            .await
            .expect("first chunk");

        let error = manager
            .upload_chunk(
                &response.upload_id,
                Some(&auth),
                "bytes 524288-786431/1048576",
                Bytes::from(vec![2u8; 256 * 1024]),
            )
            .await
            .expect_err("non-contiguous chunk should fail");

        assert!(matches!(error, ResumableError::RangeNotSatisfiable(_)));
    }
}
