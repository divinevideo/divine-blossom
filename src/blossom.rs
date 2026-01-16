// ABOUTME: Blossom protocol types and constants
// ABOUTME: Implements BUD-01 and BUD-02 data structures

use serde::{Deserialize, Serialize};

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
        BlobDescriptor {
            url: format!("{}/{}", base_url, self.sha256),
            sha256: self.sha256.clone(),
            size: self.size,
            mime_type: Some(self.mime_type.clone()),
            uploaded: Some(self.uploaded.clone()),
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
