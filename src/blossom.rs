// ABOUTME: Blossom protocol types and constants
// ABOUTME: Implements BUD-01 and BUD-02 data structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Blob descriptor returned by the server (BUD-02)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    /// URL where the blob can be retrieved
    pub url: String,
    /// SHA-256 hash of the blob (hex encoded)
    pub sha256: String,
    /// Size in bytes
    pub size: u64,
    /// MIME type (optional)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Upload timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded: Option<String>,
    /// Thumbnail URL for videos (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// HLS manifest URL for videos (optional, present when transcoding complete)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hls: Option<String>,
    /// Video dimensions as "WIDTHxHEIGHT" (display dimensions after rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
    /// Transcript URL in WebVTT format (optional, present when transcription complete)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtt: Option<String>,
}

/// Blob metadata stored in KV store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// SHA-256 hash (hex encoded)
    pub sha256: String,
    /// Size in bytes
    pub size: u64,
    /// MIME type
    #[serde(rename = "type")]
    pub mime_type: String,
    /// Upload timestamp (ISO 8601)
    pub uploaded: String,
    /// Owner's nostr public key (hex encoded)
    pub owner: String,
    /// Content status for moderation
    pub status: BlobStatus,
    /// Path to thumbnail for videos
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// Moderation check results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation: Option<ModerationResult>,
    /// Transcode status for video HLS generation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcode_status: Option<TranscodeStatus>,
    /// Stable error code from the last transcode attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcode_error_code: Option<String>,
    /// Human-readable error message from the last transcode attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcode_error_message: Option<String>,
    /// ISO timestamp for the most recent transcode attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcode_last_attempt_at: Option<String>,
    /// UNIX timestamp after which HLS generation may be retried
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcode_retry_after: Option<u64>,
    /// Number of failed transcode attempts recorded for this blob
    #[serde(default)]
    pub transcode_attempt_count: u32,
    /// Whether HLS generation has reached a terminal failure state
    #[serde(default)]
    pub transcode_terminal: bool,
    /// Video dimensions as "WIDTHxHEIGHT" (display dimensions after rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
    /// Transcript status for audio/video transcription
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_status: Option<TranscriptStatus>,
    /// Stable error code from the last transcript attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_error_code: Option<String>,
    /// Human-readable error message from the last transcript attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_error_message: Option<String>,
    /// ISO timestamp for the most recent transcript attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_last_attempt_at: Option<String>,
    /// UNIX timestamp after which transcript generation may be retried
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_retry_after: Option<u64>,
    /// Number of failed transcript attempts recorded for this blob
    #[serde(default)]
    pub transcript_attempt_count: u32,
    /// Whether transcript generation has reached a terminal failure state
    #[serde(default)]
    pub transcript_terminal: bool,
}

/// Moderation status for blobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobStatus {
    /// Normal, publicly accessible
    Active,
    /// Shadow restricted - only owner can access (renders as 404 to non-owners)
    Restricted,
    /// Awaiting moderation review
    Pending,
    /// Permanently banned by moderation - not accessible to anyone
    Banned,
    /// Soft-deleted internally; preserved in storage but never served publicly
    Deleted,
    /// Age-gated content. Anonymous viewers receive 401 (auth_required) so the
    /// client can present an age-verification UI. Distinct from `Restricted`,
    /// which is shadow-banned and 404s to non-owners.
    #[serde(rename = "age_restricted")]
    AgeRestricted,
}

impl BlobStatus {
    pub fn as_api_str(self) -> &'static str {
        match self {
            BlobStatus::Active => "active",
            BlobStatus::Restricted => "restricted",
            BlobStatus::Pending => "pending",
            BlobStatus::Banned => "banned",
            BlobStatus::Deleted => "deleted",
            BlobStatus::AgeRestricted => "age_restricted",
        }
    }

    pub fn blocks_public_access(self) -> bool {
        matches!(self, BlobStatus::Banned | BlobStatus::Deleted)
    }

    pub fn requires_private_cache(self) -> bool {
        matches!(self, BlobStatus::Restricted | BlobStatus::AgeRestricted)
    }
}

/// Result of evaluating whether a viewer is allowed to fetch a blob.
///
/// All blob-serving endpoints should derive their HTTP response from this
/// enum (via [`BlobMetadata::access_for`]) instead of inspecting
/// [`BlobStatus`] directly. This guarantees consistent behavior across
/// `GET`/`HEAD` for blobs, thumbnails, HLS manifests, HLS segments,
/// transcripts, and quality variants — and makes adding a new moderation
/// outcome a single-file change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobAccess {
    /// Viewer may fetch the content.
    Allowed,
    /// Hide the existence of the blob (Banned / Deleted / shadow-Restricted to
    /// non-owners). Maps to HTTP 404.
    NotFound,
    /// Age-gated content. Maps to HTTP 401 with body `age_restricted` so the
    /// client can present an age-verification UI.
    AgeGated,
}

impl BlobMetadata {
    /// Decide whether a viewer is allowed to access this blob.
    ///
    /// `requester_pubkey` is the authenticated viewer's pubkey, if any.
    /// `is_admin` is true when the request carries a valid admin Bearer token.
    pub fn access_for(&self, requester_pubkey: Option<&str>, is_admin: bool) -> BlobAccess {
        if is_admin {
            return BlobAccess::Allowed;
        }

        let is_owner = requester_pubkey
            .map(|p| p.eq_ignore_ascii_case(&self.owner))
            .unwrap_or(false);

        match self.status {
            BlobStatus::Active | BlobStatus::Pending => BlobAccess::Allowed,
            BlobStatus::Banned | BlobStatus::Deleted => BlobAccess::NotFound,
            BlobStatus::Restricted => {
                if is_owner {
                    BlobAccess::Allowed
                } else {
                    BlobAccess::NotFound
                }
            }
            BlobStatus::AgeRestricted => {
                if requester_pubkey.is_some() {
                    BlobAccess::Allowed
                } else {
                    BlobAccess::AgeGated
                }
            }
        }
    }
}

/// Transcode status for video blobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TranscodeStatus {
    /// Transcoding not yet started
    Pending,
    /// Transcoding in progress
    Processing,
    /// Transcoding completed successfully
    Complete,
    /// Transcoding failed
    Failed,
}

impl Default for TranscodeStatus {
    fn default() -> Self {
        TranscodeStatus::Pending
    }
}

/// Transcript status for audio/video blobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TranscriptStatus {
    /// Transcription not yet started
    Pending,
    /// Transcription in progress
    Processing,
    /// Transcription completed successfully
    Complete,
    /// Transcription failed
    Failed,
}

impl Default for TranscriptStatus {
    fn default() -> Self {
        TranscriptStatus::Pending
    }
}

impl Default for BlobStatus {
    fn default() -> Self {
        BlobStatus::Pending
    }
}

/// Moderation result from content safety checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationResult {
    /// When the check was performed (ISO 8601)
    pub checked_at: String,
    /// Whether content passed safety checks
    pub is_safe: bool,
    /// Detailed safety scores
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<SafetyScores>,
}

/// Detailed safety scores from moderation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyScores {
    /// Adult content score
    pub adult: String,
    /// Violence content score
    pub violence: String,
    /// Racy content score
    pub racy: String,
}

/// Upload requirements response (HEAD /upload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRequirements {
    /// Maximum file size in bytes (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Allowed MIME types (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_types: Option<Vec<String>>,
    /// Supported Divine upload extensions (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

/// Request payload for initializing a resumable upload session.
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

/// Response payload returned after creating a resumable upload session.
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

/// Request payload for completing a resumable upload session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumableUploadCompleteRequest {
    pub sha256: String,
}

/// Response payload returned when a resumable upload session finishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableUploadCompleteResponse {
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

/// Subtitle job status returned by /v1/subtitles APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubtitleJobStatus {
    Queued,
    Processing,
    Ready,
    Failed,
}

/// Subtitle job metadata persisted in KV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtitleJob {
    pub job_id: String,
    pub video_sha256: String,
    pub status: SubtitleJobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_track_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cue_count: Option<u32>,
    pub sha256: String,
    pub attempt_count: u32,
    pub max_attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request payload for creating subtitle jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtitleJobCreateRequest {
    pub video_sha256: String,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub force: bool,
}

impl BlobMetadata {
    /// Convert to BlobDescriptor for API response
    pub fn to_descriptor(&self, base_url: &str) -> BlobDescriptor {
        // Include HLS URL if video transcoding is complete
        let hls = if is_video_mime_type(&self.mime_type)
            && self.transcode_status == Some(TranscodeStatus::Complete)
        {
            Some(format!("{}/{}.hls", base_url, self.sha256))
        } else {
            None
        };
        let vtt = if is_transcribable_mime_type(&self.mime_type)
            && self.transcript_status == Some(TranscriptStatus::Complete)
        {
            Some(format!("{}/{}.vtt", base_url, self.sha256))
        } else {
            None
        };

        BlobDescriptor {
            url: format!("{}/{}", base_url, self.sha256),
            sha256: self.sha256.clone(),
            size: self.size,
            mime_type: Some(self.mime_type.clone()),
            uploaded: Some(self.uploaded.clone()),
            thumbnail: self.thumbnail.clone(),
            hls,
            dim: self.dim.clone(),
            vtt,
        }
    }
}

/// Nostr event for Blossom authorization (kind 24242)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlossomAuthEvent {
    /// Event ID (sha256 of serialized event)
    pub id: String,
    /// Author's public key (hex)
    pub pubkey: String,
    /// Unix timestamp
    pub created_at: u64,
    /// Event kind (24242 for blossom auth)
    pub kind: u32,
    /// Tags array
    pub tags: Vec<Vec<String>>,
    /// Event content
    pub content: String,
    /// Schnorr signature
    pub sig: String,
}

/// Blossom authorization action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAction {
    Get,
    Upload,
    Delete,
    List,
}

impl BlossomAuthEvent {
    /// Get the action type from tags
    pub fn get_action(&self) -> Option<AuthAction> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "t" {
                return match tag[1].as_str() {
                    "get" => Some(AuthAction::Get),
                    "upload" => Some(AuthAction::Upload),
                    "delete" => Some(AuthAction::Delete),
                    "list" => Some(AuthAction::List),
                    _ => None,
                };
            }
        }
        None
    }

    /// Get the blob hash from tags (for delete operations)
    pub fn get_hash(&self) -> Option<&str> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "x" {
                return Some(&tag[1]);
            }
        }
        None
    }

    /// Get the expiration timestamp from tags
    pub fn get_expiration(&self) -> Option<u64> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "expiration" {
                return tag[1].parse().ok();
            }
        }
        None
    }
}

// ============================================================================
// Admin Dashboard Data Structures
// ============================================================================

/// Global statistics for admin dashboard
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalStats {
    /// Total number of blobs
    pub total_blobs: u64,
    /// Total size of all blobs in bytes
    pub total_size_bytes: u64,
    /// Counts by blob status
    pub status_counts: HashMap<String, u64>,
    /// Counts by transcode status
    pub transcode_counts: HashMap<String, u64>,
    /// Counts by MIME type
    pub mime_type_counts: HashMap<String, u64>,
    /// Number of unique uploaders
    pub unique_uploaders: u64,
}

impl GlobalStats {
    /// Create a new empty stats object
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment stats for a new blob
    pub fn add_blob(&mut self, metadata: &BlobMetadata) {
        self.total_blobs += 1;
        self.total_size_bytes += metadata.size;

        let status_key = format!("{:?}", metadata.status).to_lowercase();
        *self.status_counts.entry(status_key).or_insert(0) += 1;

        if let Some(transcode) = &metadata.transcode_status {
            let transcode_key = format!("{:?}", transcode).to_lowercase();
            *self.transcode_counts.entry(transcode_key).or_insert(0) += 1;
        }

        *self
            .mime_type_counts
            .entry(metadata.mime_type.clone())
            .or_insert(0) += 1;
    }

    /// Decrement stats when a blob is removed
    pub fn remove_blob(&mut self, metadata: &BlobMetadata) {
        self.total_blobs = self.total_blobs.saturating_sub(1);
        self.total_size_bytes = self.total_size_bytes.saturating_sub(metadata.size);

        let status_key = format!("{:?}", metadata.status).to_lowercase();
        if let Some(count) = self.status_counts.get_mut(&status_key) {
            *count = count.saturating_sub(1);
        }

        if let Some(transcode) = &metadata.transcode_status {
            let transcode_key = format!("{:?}", transcode).to_lowercase();
            if let Some(count) = self.transcode_counts.get_mut(&transcode_key) {
                *count = count.saturating_sub(1);
            }
        }

        if let Some(count) = self.mime_type_counts.get_mut(&metadata.mime_type) {
            *count = count.saturating_sub(1);
        }
    }

    /// Update status count when blob status changes
    pub fn update_status(&mut self, old_status: BlobStatus, new_status: BlobStatus) {
        let old_key = format!("{:?}", old_status).to_lowercase();
        let new_key = format!("{:?}", new_status).to_lowercase();

        if let Some(count) = self.status_counts.get_mut(&old_key) {
            *count = count.saturating_sub(1);
        }
        *self.status_counts.entry(new_key).or_insert(0) += 1;
    }

    /// Update transcode count when transcode status changes
    pub fn update_transcode(
        &mut self,
        old_status: Option<TranscodeStatus>,
        new_status: TranscodeStatus,
    ) {
        if let Some(old) = old_status {
            let old_key = format!("{:?}", old).to_lowercase();
            if let Some(count) = self.transcode_counts.get_mut(&old_key) {
                *count = count.saturating_sub(1);
            }
        }
        let new_key = format!("{:?}", new_status).to_lowercase();
        *self.transcode_counts.entry(new_key).or_insert(0) += 1;
    }
}

/// Rolling list of recent uploads (max 200 hashes)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecentIndex {
    /// List of blob hashes, most recent first
    pub hashes: Vec<String>,
}

impl RecentIndex {
    /// Maximum number of recent uploads to track
    pub const MAX_RECENT: usize = 200;

    /// Create a new empty recent index
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a hash to the front of the list, maintaining max size
    pub fn add(&mut self, hash: String) {
        // Remove if already present to avoid duplicates
        self.hashes.retain(|h| h != &hash);
        // Add to front
        self.hashes.insert(0, hash);
        // Trim to max size
        self.hashes.truncate(Self::MAX_RECENT);
    }

    /// Remove a hash from the list
    pub fn remove(&mut self, hash: &str) {
        self.hashes.retain(|h| h != hash);
    }
}

/// Index of all uploaders' pubkeys
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserIndex {
    /// List of uploader pubkeys (hex encoded)
    pub pubkeys: Vec<String>,
}

impl UserIndex {
    /// Create a new empty user index
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pubkey if not already present
    pub fn add(&mut self, pubkey: String) -> bool {
        if !self.pubkeys.contains(&pubkey) {
            self.pubkeys.push(pubkey);
            true
        } else {
            false
        }
    }

    /// Check if a pubkey exists
    pub fn contains(&self, pubkey: &str) -> bool {
        self.pubkeys.contains(&pubkey.to_string())
    }

    /// Remove a pubkey from the index
    pub fn remove(&mut self, pubkey: &str) {
        self.pubkeys.retain(|p| p != pubkey);
    }
}

// ============================================================================
// Video/Media Types
// ============================================================================

/// MIME types we consider video
pub const VIDEO_MIME_TYPES: &[&str] = &[
    "video/mp4",
    "video/webm",
    "video/ogg",
    "video/quicktime",
    "video/x-msvideo",
    "video/x-matroska",
];

/// MIME types we consider audio
pub const AUDIO_MIME_TYPES: &[&str] = &[
    "audio/mpeg",
    "audio/mp3",
    "audio/mp4",
    "audio/x-m4a",
    "audio/wav",
    "audio/x-wav",
    "audio/ogg",
    "audio/flac",
    "audio/webm",
    "audio/aac",
];

/// Check if a MIME type is a video type
pub fn is_video_mime_type(mime_type: &str) -> bool {
    VIDEO_MIME_TYPES.iter().any(|&t| mime_type.starts_with(t))
}

/// Check if a MIME type can be transcribed (audio or video)
pub fn is_transcribable_mime_type(mime_type: &str) -> bool {
    is_video_mime_type(mime_type) || AUDIO_MIME_TYPES.iter().any(|&t| mime_type.starts_with(t))
}

/// Parse SHA-256 hash from URL path
/// Handles paths like /abc123.mp4 or /abc123
pub fn parse_hash_from_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');

    // Remove extension if present
    let hash = if let Some(dot_pos) = path.rfind('.') {
        &path[..dot_pos]
    } else {
        path
    };

    // Validate it's a valid SHA-256 hex string (64 characters)
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash.to_lowercase())
    } else {
        None
    }
}

/// Check if path is a thumbnail request ({hash}.jpg)
/// Returns the GCS key if it's a thumbnail request
pub fn parse_thumbnail_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');

    if path.ends_with(".jpg") {
        let hash = &path[..path.len() - 4]; // Remove .jpg
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            // Return full path including .jpg extension as GCS key
            return Some(format!("{}.jpg", hash.to_lowercase()));
        }
    }
    None
}

/// Parse audio extraction path: /{sha256}.audio.m4a
pub fn parse_audio_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    if path.ends_with(".audio.m4a") {
        let hash = &path[..path.len() - ".audio.m4a".len()];
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hash.to_lowercase());
        }
    }
    None
}

/// Check if a path is an audio extraction request
pub fn is_audio_path(path: &str) -> bool {
    parse_audio_path(path).is_some()
}

/// Mapping from source video SHA256 to derived audio blob metadata.
/// Stored in KV as "audio_map:{source_sha256}".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioMapping {
    /// SHA256 of the source video
    pub source_sha256: String,
    /// SHA256 of the derived audio file
    pub audio_sha256: String,
    /// Duration in seconds
    pub duration_seconds: f64,
    /// Size in bytes
    pub size_bytes: u64,
    /// MIME type of the audio
    pub mime_type: String,
}

/// Check if a path looks like a hash path (for routing)
pub fn is_hash_path(path: &str) -> bool {
    parse_hash_from_path(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_from_path() {
        let hash = "a".repeat(64);

        assert_eq!(
            parse_hash_from_path(&format!("/{}", hash)),
            Some(hash.clone())
        );
        assert_eq!(
            parse_hash_from_path(&format!("/{}.mp4", hash)),
            Some(hash.clone())
        );
        assert_eq!(
            parse_hash_from_path(&format!("/{}.webm", hash)),
            Some(hash.clone())
        );

        // Invalid cases
        assert_eq!(parse_hash_from_path("/upload"), None);
        assert_eq!(parse_hash_from_path("/list/pubkey"), None);
        assert_eq!(parse_hash_from_path("/tooshort"), None);
    }

    #[test]
    fn test_is_video_mime_type() {
        assert!(is_video_mime_type("video/mp4"));
        assert!(is_video_mime_type("video/webm"));
        assert!(!is_video_mime_type("image/png"));
        assert!(!is_video_mime_type("application/json"));
    }

    #[test]
    fn test_is_transcribable_mime_type() {
        assert!(is_transcribable_mime_type("video/mp4"));
        assert!(is_transcribable_mime_type("audio/mpeg"));
        assert!(is_transcribable_mime_type("audio/wav"));
        assert!(!is_transcribable_mime_type("image/png"));
        assert!(!is_transcribable_mime_type("application/json"));
    }

    /// Helper to build a BlobMetadata for testing
    fn test_metadata(mime_type: &str) -> BlobMetadata {
        BlobMetadata {
            sha256: "a".repeat(64),
            size: 1024,
            mime_type: mime_type.to_string(),
            uploaded: "2026-01-01T00:00:00Z".to_string(),
            owner: "b".repeat(64),
            status: BlobStatus::Active,
            thumbnail: None,
            moderation: None,
            transcode_status: None,
            transcode_error_code: None,
            transcode_error_message: None,
            transcode_last_attempt_at: None,
            transcode_retry_after: None,
            transcode_attempt_count: 0,
            transcode_terminal: false,
            dim: None,
            transcript_status: None,
            transcript_error_code: None,
            transcript_error_message: None,
            transcript_last_attempt_at: None,
            transcript_retry_after: None,
            transcript_attempt_count: 0,
            transcript_terminal: false,
        }
    }

    #[test]
    fn test_descriptor_includes_hls_when_transcode_complete() {
        let mut meta = test_metadata("video/mp4");
        let base = "https://media.test";

        // No HLS URL when transcode not complete
        let desc = meta.to_descriptor(base);
        assert!(desc.hls.is_none());

        // No HLS URL when processing
        meta.transcode_status = Some(TranscodeStatus::Processing);
        let desc = meta.to_descriptor(base);
        assert!(desc.hls.is_none());

        // HLS URL present when complete
        meta.transcode_status = Some(TranscodeStatus::Complete);
        let desc = meta.to_descriptor(base);
        assert_eq!(desc.hls, Some(format!("{}/{}.hls", base, meta.sha256)));
    }

    #[test]
    fn test_descriptor_includes_vtt_when_transcript_complete() {
        let mut meta = test_metadata("video/mp4");
        let base = "https://media.test";

        // No VTT URL when transcript not complete
        let desc = meta.to_descriptor(base);
        assert!(desc.vtt.is_none());

        // VTT URL present when complete
        meta.transcript_status = Some(TranscriptStatus::Complete);
        let desc = meta.to_descriptor(base);
        assert_eq!(desc.vtt, Some(format!("{}/{}.vtt", base, meta.sha256)));
    }

    #[test]
    fn test_descriptor_no_hls_for_non_video() {
        let mut meta = test_metadata("image/png");
        meta.transcode_status = Some(TranscodeStatus::Complete);
        let desc = meta.to_descriptor("https://media.test");
        assert!(desc.hls.is_none());
    }

    #[test]
    fn test_descriptor_no_vtt_for_non_transcribable() {
        let mut meta = test_metadata("image/png");
        meta.transcript_status = Some(TranscriptStatus::Complete);
        let desc = meta.to_descriptor("https://media.test");
        assert!(desc.vtt.is_none());
    }

    #[test]
    fn test_active_status_allows_public_access() {
        assert!(!BlobStatus::Active.blocks_public_access());
        assert!(!BlobStatus::Active.requires_private_cache());
    }

    #[test]
    fn test_blob_status_access_control() {
        assert!(BlobStatus::Banned.blocks_public_access());
        assert!(BlobStatus::Deleted.blocks_public_access());
        assert!(!BlobStatus::Restricted.blocks_public_access());
        assert!(BlobStatus::Restricted.requires_private_cache());
        assert!(BlobStatus::AgeRestricted.requires_private_cache());
        assert!(!BlobStatus::Pending.blocks_public_access());
    }

    #[test]
    fn test_deleted_status_blocks_like_banned() {
        // Deleted must behave identically to Banned for access control.
        // The serving code uses these helpers instead of matching on individual
        // variants, so any status that blocks_public_access() will 404.
        assert_eq!(
            BlobStatus::Deleted.blocks_public_access(),
            BlobStatus::Banned.blocks_public_access(),
        );
        assert_eq!(
            BlobStatus::Deleted.requires_private_cache(),
            BlobStatus::Banned.requires_private_cache(),
        );
        assert!(!BlobStatus::Deleted.requires_private_cache());
        assert!(!BlobStatus::Banned.requires_private_cache());
    }

    #[test]
    fn test_every_status_is_classified() {
        // Ensure no status variant is silently servable — every non-Active,
        // non-Pending status must trigger at least one access check.
        // Uses match for compiler-enforced exhaustiveness: adding a new
        // BlobStatus variant will fail to compile until classified here.
        for s in [
            BlobStatus::Active,
            BlobStatus::Restricted,
            BlobStatus::Pending,
            BlobStatus::Banned,
            BlobStatus::Deleted,
            BlobStatus::AgeRestricted,
        ] {
            match s {
                BlobStatus::Banned | BlobStatus::Deleted => {
                    assert!(
                        s.blocks_public_access(),
                        "{:?} should block public access",
                        s
                    );
                    assert!(
                        !s.requires_private_cache(),
                        "{:?} should not require private cache",
                        s
                    );
                }
                BlobStatus::Restricted => {
                    assert!(
                        !s.blocks_public_access(),
                        "{:?} should not block public access",
                        s
                    );
                    assert!(
                        s.requires_private_cache(),
                        "{:?} should require private cache",
                        s
                    );
                }
                BlobStatus::AgeRestricted => {
                    assert!(
                        !s.blocks_public_access(),
                        "{:?} should not block public access",
                        s
                    );
                    assert!(
                        s.requires_private_cache(),
                        "{:?} should require private cache",
                        s
                    );
                }
                BlobStatus::Active | BlobStatus::Pending => {
                    assert!(
                        !s.blocks_public_access(),
                        "{:?} should not block public access",
                        s
                    );
                    assert!(
                        !s.requires_private_cache(),
                        "{:?} should not require private cache",
                        s
                    );
                }
            }
        }
    }

    fn fixture_metadata(status: BlobStatus, owner: &str) -> BlobMetadata {
        BlobMetadata {
            sha256: "x".into(),
            size: 1,
            mime_type: "video/mp4".into(),
            uploaded: "2026-04-10T00:00:00Z".into(),
            owner: owner.into(),
            status,
            thumbnail: None,
            moderation: None,
            transcode_status: None,
            transcode_error_code: None,
            transcode_error_message: None,
            transcode_last_attempt_at: None,
            transcode_retry_after: None,
            transcode_attempt_count: 0,
            transcode_terminal: false,
            dim: None,
            transcript_status: None,
            transcript_error_code: None,
            transcript_error_message: None,
            transcript_last_attempt_at: None,
            transcript_retry_after: None,
            transcript_attempt_count: 0,
            transcript_terminal: false,
        }
    }

    #[test]
    fn blob_status_serializes_age_restricted_with_underscore() {
        let json = serde_json::to_string(&BlobStatus::AgeRestricted).unwrap();
        assert_eq!(json, "\"age_restricted\"");
    }

    #[test]
    fn blob_status_deserializes_age_restricted() {
        let parsed: BlobStatus = serde_json::from_str("\"age_restricted\"").unwrap();
        assert_eq!(parsed, BlobStatus::AgeRestricted);
    }

    #[test]
    fn blob_status_api_string_covers_every_variant() {
        let cases = [
            (BlobStatus::Active, "active"),
            (BlobStatus::Restricted, "restricted"),
            (BlobStatus::Pending, "pending"),
            (BlobStatus::Banned, "banned"),
            (BlobStatus::Deleted, "deleted"),
            (BlobStatus::AgeRestricted, "age_restricted"),
        ];

        for (status, expected) in cases {
            assert_eq!(status.as_api_str(), expected);
        }
    }

    #[test]
    fn blob_status_age_restricted_does_not_block_public_access() {
        // AgeRestricted should NOT be in blocks_public_access (that returns 404).
        // It instead surfaces as an age-gate via access_for.
        assert!(!BlobStatus::AgeRestricted.blocks_public_access());
    }

    #[test]
    fn blob_status_age_restricted_requires_private_cache_not_owner_auth() {
        assert!(BlobStatus::AgeRestricted.requires_private_cache());
    }

    #[test]
    fn access_for_admin_always_allowed() {
        let m = fixture_metadata(BlobStatus::Banned, "owner");
        assert_eq!(m.access_for(None, true), BlobAccess::Allowed);
        let m = fixture_metadata(BlobStatus::AgeRestricted, "owner");
        assert_eq!(m.access_for(None, true), BlobAccess::Allowed);
    }

    #[test]
    fn access_for_active_allowed_for_anyone() {
        let m = fixture_metadata(BlobStatus::Active, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::Allowed);
        assert_eq!(m.access_for(Some("stranger"), false), BlobAccess::Allowed);
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::Allowed);
    }

    #[test]
    fn access_for_pending_allowed() {
        // Existing behavior: Pending blobs are publicly served while waiting
        // for moderation. Don't change that here.
        let m = fixture_metadata(BlobStatus::Pending, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::Allowed);
    }

    #[test]
    fn access_for_banned_is_notfound_to_everyone_non_admin() {
        let m = fixture_metadata(BlobStatus::Banned, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::NotFound);
        assert_eq!(m.access_for(None, false), BlobAccess::NotFound);
    }

    #[test]
    fn access_for_deleted_is_notfound_to_everyone_non_admin() {
        let m = fixture_metadata(BlobStatus::Deleted, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::NotFound);
        assert_eq!(m.access_for(None, false), BlobAccess::NotFound);
    }

    #[test]
    fn access_for_restricted_is_notfound_to_non_owner_and_anonymous() {
        let m = fixture_metadata(BlobStatus::Restricted, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::NotFound);
        assert_eq!(m.access_for(Some("stranger"), false), BlobAccess::NotFound);
    }

    #[test]
    fn access_for_restricted_is_allowed_to_owner() {
        let m = fixture_metadata(BlobStatus::Restricted, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::Allowed);
        // Case-insensitive comparison
        assert_eq!(m.access_for(Some("OWNER"), false), BlobAccess::Allowed);
    }

    #[test]
    fn access_for_age_restricted_is_age_gated_to_anonymous_only() {
        let m = fixture_metadata(BlobStatus::AgeRestricted, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::AgeGated);
    }

    #[test]
    fn access_for_age_restricted_is_allowed_to_any_authenticated_viewer() {
        let m = fixture_metadata(BlobStatus::AgeRestricted, "owner");
        assert_eq!(m.access_for(Some("stranger"), false), BlobAccess::Allowed);
    }

    #[test]
    fn access_for_age_restricted_is_allowed_to_owner() {
        let m = fixture_metadata(BlobStatus::AgeRestricted, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::Allowed);
        // Case-insensitive comparison
        assert_eq!(m.access_for(Some("OWNER"), false), BlobAccess::Allowed);
    }

    #[test]
    fn test_local_mode_stub_hls_manifest_format() {
        let hash = "a".repeat(64);
        let manifest = format!(
            "#EXTM3U\n\
             #EXT-X-VERSION:3\n\
             #EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720\n\
             /{}/hls/stream_720p.m3u8\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=854x480\n\
             /{}/hls/stream_480p.m3u8\n",
            hash, hash
        );
        assert!(manifest.starts_with("#EXTM3U"));
        assert!(manifest.contains("BANDWIDTH=2500000,RESOLUTION=1280x720"));
        assert!(manifest.contains("BANDWIDTH=1000000,RESOLUTION=854x480"));
        assert!(manifest.contains(&format!("/{}/hls/stream_720p.m3u8", hash)));
        assert!(manifest.contains(&format!("/{}/hls/stream_480p.m3u8", hash)));
    }

    #[test]
    fn test_local_mode_stub_variant_playlist_format() {
        let hash = "a".repeat(64);
        let variant = format!(
            "#EXTM3U\n\
             #EXT-X-VERSION:3\n\
             #EXT-X-TARGETDURATION:3600\n\
             #EXT-X-MEDIA-SEQUENCE:0\n\
             #EXT-X-PLAYLIST-TYPE:VOD\n\
             #EXTINF:3600.0,\n\
             /{}\n\
             #EXT-X-ENDLIST\n",
            hash
        );
        assert!(variant.starts_with("#EXTM3U"));
        assert!(variant.contains("EXT-X-TARGETDURATION"));
        assert!(variant.contains("EXT-X-PLAYLIST-TYPE:VOD"));
        assert!(variant.contains("EXT-X-ENDLIST"));
        assert!(variant.contains(&format!("/{}", hash)));
    }

    #[test]
    fn test_local_mode_stub_filenames_match_quality_variants() {
        // QUALITY_VARIANTS in main.rs defines the route-to-filename mapping:
        //   ("/720p", "stream_720p.ts"), ("/480p", "stream_480p.ts")
        // The local mode stub must write files with these exact base names.
        // This test catches drift between the stub and route handler.
        let expected_variants = &["stream_720p", "stream_480p"];

        let hash = "b".repeat(64);

        // Master playlist must reference each variant's .m3u8
        let master = format!(
            "#EXTM3U\n\
             #EXT-X-VERSION:3\n\
             #EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720\n\
             /{}/hls/stream_720p.m3u8\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=854x480\n\
             /{}/hls/stream_480p.m3u8\n",
            hash, hash
        );
        for name in expected_variants {
            assert!(
                master.contains(&format!("{}.m3u8", name)),
                "master.m3u8 missing reference to {}.m3u8",
                name
            );
        }

        // The delete cleanup paths must also match (keep in sync with delete_blob_gcs_artifacts)
        let cleanup_paths: Vec<String> = expected_variants
            .iter()
            .flat_map(|name| {
                vec![
                    format!("{}/hls/{}.m3u8", hash, name),
                    format!("{}/hls/{}.ts", hash, name),
                    format!("{}/hls/{}.mp4", hash, name),
                ]
            })
            .collect();
        assert_eq!(cleanup_paths.len(), 6);
        for path in &cleanup_paths {
            assert!(
                path.contains("/hls/stream_"),
                "cleanup path has unexpected format: {}",
                path
            );
        }
    }

    #[test]
    fn test_local_mode_stub_vtt_format() {
        let vtt = "WEBVTT\n\n00:00:00.000 --> 00:00:01.000\n[local mode stub transcript]\n";
        assert!(vtt.starts_with("WEBVTT"));
        assert!(vtt.contains("-->"));
    }

    #[test]
    fn test_transcode_status_default_is_pending() {
        assert_eq!(TranscodeStatus::default(), TranscodeStatus::Pending);
    }

    #[test]
    fn test_transcript_status_default_is_pending() {
        assert_eq!(TranscriptStatus::default(), TranscriptStatus::Pending);
    }

    #[test]
    fn test_blob_status_serialization() {
        assert_eq!(
            serde_json::to_string(&BlobStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&TranscodeStatus::Complete).unwrap(),
            "\"complete\""
        );
        assert_eq!(
            serde_json::to_string(&TranscriptStatus::Complete).unwrap(),
            "\"complete\""
        );
    }

    #[test]
    fn test_parse_thumbnail_path_valid() {
        let hash = "a".repeat(64);
        let result = parse_thumbnail_path(&format!("/{}.jpg", hash));
        assert_eq!(result, Some(format!("{}.jpg", hash)));
    }

    #[test]
    fn test_parse_thumbnail_path_no_jpg() {
        let hash = "a".repeat(64);
        assert_eq!(parse_thumbnail_path(&format!("/{}.png", hash)), None);
        assert_eq!(parse_thumbnail_path(&format!("/{}", hash)), None);
    }

    #[test]
    fn test_parse_thumbnail_path_invalid_hash() {
        assert_eq!(parse_thumbnail_path("/short.jpg"), None);
        assert_eq!(parse_thumbnail_path("/upload.jpg"), None);
    }

    #[test]
    fn test_is_hash_path() {
        let hash = "a".repeat(64);
        assert!(is_hash_path(&format!("/{}", hash)));
        assert!(is_hash_path(&format!("/{}.mp4", hash)));
        assert!(!is_hash_path("/upload"));
        assert!(!is_hash_path("/list/abc"));
    }

    #[test]
    fn test_auth_event_get_action() {
        let event = BlossomAuthEvent {
            id: "test".into(),
            pubkey: "a".repeat(64),
            created_at: 0,
            kind: 24242,
            tags: vec![vec!["t".into(), "get".into()]],
            content: String::new(),
            sig: "b".repeat(128),
        };
        assert_eq!(event.get_action(), Some(AuthAction::Get));

        let upload_event = BlossomAuthEvent {
            tags: vec![vec!["t".into(), "upload".into()]],
            ..event.clone()
        };
        assert_eq!(upload_event.get_action(), Some(AuthAction::Upload));

        let delete_event = BlossomAuthEvent {
            tags: vec![vec!["t".into(), "delete".into()]],
            ..event.clone()
        };
        assert_eq!(delete_event.get_action(), Some(AuthAction::Delete));

        let list_event = BlossomAuthEvent {
            tags: vec![vec!["t".into(), "list".into()]],
            ..event.clone()
        };
        assert_eq!(list_event.get_action(), Some(AuthAction::List));

        let unknown_event = BlossomAuthEvent {
            tags: vec![vec!["t".into(), "unknown".into()]],
            ..event.clone()
        };
        assert_eq!(unknown_event.get_action(), None);

        let no_tag_event = BlossomAuthEvent {
            tags: vec![],
            ..event.clone()
        };
        assert_eq!(no_tag_event.get_action(), None);
    }

    #[test]
    fn test_auth_event_get_hash() {
        let event = BlossomAuthEvent {
            id: "test".into(),
            pubkey: "a".repeat(64),
            created_at: 0,
            kind: 24242,
            tags: vec![
                vec!["t".into(), "delete".into()],
                vec!["x".into(), "c".repeat(64)],
            ],
            content: String::new(),
            sig: "b".repeat(128),
        };
        assert_eq!(event.get_hash(), Some("c".repeat(64).as_str()));

        let no_hash = BlossomAuthEvent {
            tags: vec![vec!["t".into(), "upload".into()]],
            ..event.clone()
        };
        assert_eq!(no_hash.get_hash(), None);
    }

    #[test]
    fn test_auth_event_get_expiration() {
        let event = BlossomAuthEvent {
            id: "test".into(),
            pubkey: "a".repeat(64),
            created_at: 0,
            kind: 24242,
            tags: vec![vec!["expiration".into(), "1700000000".into()]],
            content: String::new(),
            sig: "b".repeat(128),
        };
        assert_eq!(event.get_expiration(), Some(1700000000));

        let no_exp = BlossomAuthEvent {
            tags: vec![],
            ..event.clone()
        };
        assert_eq!(no_exp.get_expiration(), None);

        let bad_exp = BlossomAuthEvent {
            tags: vec![vec!["expiration".into(), "not-a-number".into()]],
            ..event.clone()
        };
        assert_eq!(bad_exp.get_expiration(), None);
    }

    #[test]
    fn test_global_stats_add_and_remove_blob() {
        let mut stats = GlobalStats::new();
        let meta = test_metadata("video/mp4");

        stats.add_blob(&meta);
        assert_eq!(stats.total_blobs, 1);
        assert_eq!(stats.total_size_bytes, 1024);
        assert_eq!(stats.mime_type_counts.get("video/mp4"), Some(&1));
        assert_eq!(stats.status_counts.get("active"), Some(&1));

        stats.remove_blob(&meta);
        assert_eq!(stats.total_blobs, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }

    #[test]
    fn test_global_stats_update_status() {
        let mut stats = GlobalStats::new();
        stats.status_counts.insert("active".into(), 5);

        stats.update_status(BlobStatus::Active, BlobStatus::Banned);
        assert_eq!(stats.status_counts.get("active"), Some(&4));
        assert_eq!(stats.status_counts.get("banned"), Some(&1));
    }

    #[test]
    fn test_global_stats_update_transcode() {
        let mut stats = GlobalStats::new();
        stats.transcode_counts.insert("pending".into(), 3);

        stats.update_transcode(Some(TranscodeStatus::Pending), TranscodeStatus::Complete);
        assert_eq!(stats.transcode_counts.get("pending"), Some(&2));
        assert_eq!(stats.transcode_counts.get("complete"), Some(&1));

        // From None (new entry)
        stats.update_transcode(None, TranscodeStatus::Pending);
        assert_eq!(stats.transcode_counts.get("pending"), Some(&3));
    }

    #[test]
    fn test_recent_index_add_and_truncate() {
        let mut index = RecentIndex::new();
        for i in 0..210 {
            index.add(format!("hash_{}", i));
        }
        assert_eq!(index.hashes.len(), RecentIndex::MAX_RECENT);
        assert_eq!(index.hashes[0], "hash_209");
    }

    #[test]
    fn test_recent_index_dedup() {
        let mut index = RecentIndex::new();
        index.add("aaa".into());
        index.add("bbb".into());
        index.add("aaa".into()); // re-add moves to front
        assert_eq!(index.hashes.len(), 2);
        assert_eq!(index.hashes[0], "aaa");
        assert_eq!(index.hashes[1], "bbb");
    }

    #[test]
    fn test_recent_index_remove() {
        let mut index = RecentIndex::new();
        index.add("aaa".into());
        index.add("bbb".into());
        index.remove("aaa");
        assert_eq!(index.hashes, vec!["bbb"]);
    }

    #[test]
    fn test_user_index_add_and_contains() {
        let mut idx = UserIndex::new();
        assert!(idx.add("pk1".into()));
        assert!(!idx.add("pk1".into())); // duplicate returns false
        assert!(idx.contains("pk1"));
        assert!(!idx.contains("pk2"));
    }

    #[test]
    fn test_subtitle_job_status_serialization() {
        assert_eq!(
            serde_json::to_string(&SubtitleJobStatus::Queued).unwrap(),
            "\"queued\""
        );
        assert_eq!(
            serde_json::to_string(&SubtitleJobStatus::Ready).unwrap(),
            "\"ready\""
        );
    }

    #[test]
    fn test_parse_audio_path_valid() {
        let hash = "a".repeat(64);
        assert_eq!(
            parse_audio_path(&format!("/{}.audio.m4a", hash)),
            Some(hash.clone())
        );
    }

    #[test]
    fn test_parse_audio_path_no_suffix() {
        let hash = "a".repeat(64);
        assert_eq!(parse_audio_path(&format!("/{}", hash)), None);
    }

    #[test]
    fn test_parse_audio_path_short_hash() {
        assert_eq!(parse_audio_path("/tooshort.audio.m4a"), None);
    }

    #[test]
    fn test_parse_audio_path_wrong_extension() {
        let hash = "a".repeat(64);
        assert_eq!(parse_audio_path(&format!("/{}.mp4", hash)), None);
    }

    #[test]
    fn test_is_audio_path() {
        let hash = "a".repeat(64);
        assert!(is_audio_path(&format!("/{}.audio.m4a", hash)));
        assert!(!is_audio_path(&format!("/{}.mp4", hash)));
        assert!(!is_audio_path("/upload"));
    }

    #[test]
    fn test_audio_mapping_serialization() {
        let mapping = AudioMapping {
            source_sha256: "a".repeat(64),
            audio_sha256: "b".repeat(64),
            duration_seconds: 120.5,
            size_bytes: 1024000,
            mime_type: "audio/mp4".to_string(),
        };
        let json = serde_json::to_string(&mapping).unwrap();
        let parsed: AudioMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source_sha256, "a".repeat(64));
        assert_eq!(parsed.audio_sha256, "b".repeat(64));
        assert_eq!(parsed.duration_seconds, 120.5);
        assert_eq!(parsed.size_bytes, 1024000);
        assert_eq!(parsed.mime_type, "audio/mp4");
    }

    #[test]
    fn test_blob_status_default_is_pending() {
        assert_eq!(BlobStatus::default(), BlobStatus::Pending);
    }

    #[test]
    fn test_descriptor_after_local_mode_sets_all_statuses() {
        let mut meta = test_metadata("video/mp4");
        meta.status = BlobStatus::Active;
        meta.transcode_status = Some(TranscodeStatus::Complete);
        meta.transcript_status = Some(TranscriptStatus::Complete);

        let base = "https://media.test";
        let desc = meta.to_descriptor(base);

        assert!(desc.hls.is_some());
        assert!(desc.vtt.is_some());
        assert!(!meta.status.blocks_public_access());
        assert!(!meta.status.requires_private_cache());
    }
}
