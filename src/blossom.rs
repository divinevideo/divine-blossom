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
    /// Video dimensions as "WIDTHxHEIGHT" (display dimensions after rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
}

/// Moderation status for blobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobStatus {
    /// Normal, publicly accessible
    Active,
    /// Shadow restricted - only owner can access
    Restricted,
    /// Awaiting moderation review
    Pending,
    /// Permanently banned by moderation - not accessible to anyone
    Banned,
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

        BlobDescriptor {
            url: format!("{}/{}", base_url, self.sha256),
            sha256: self.sha256.clone(),
            size: self.size,
            mime_type: Some(self.mime_type.clone()),
            uploaded: Some(self.uploaded.clone()),
            thumbnail: self.thumbnail.clone(),
            hls,
            dim: self.dim.clone(),
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

        *self.mime_type_counts.entry(metadata.mime_type.clone()).or_insert(0) += 1;
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
    pub fn update_transcode(&mut self, old_status: Option<TranscodeStatus>, new_status: TranscodeStatus) {
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

/// Check if a MIME type is a video type
pub fn is_video_mime_type(mime_type: &str) -> bool {
    VIDEO_MIME_TYPES.iter().any(|&t| mime_type.starts_with(t))
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

        assert_eq!(parse_hash_from_path(&format!("/{}", hash)), Some(hash.clone()));
        assert_eq!(parse_hash_from_path(&format!("/{}.mp4", hash)), Some(hash.clone()));
        assert_eq!(parse_hash_from_path(&format!("/{}.webm", hash)), Some(hash.clone()));

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
}
