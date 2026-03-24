// ABOUTME: Error types for the Blossom server
// ABOUTME: Provides unified error handling with HTTP status code mapping

use fastly::http::StatusCode;
use std::fmt;

/// Unified error type for the Blossom server
#[derive(Debug)]
pub enum BlossomError {
    /// Authentication failed or missing
    AuthRequired(String),
    /// Authentication provided but invalid
    AuthInvalid(String),
    /// Forbidden - authenticated but not authorized
    Forbidden(String),
    /// Content exists but is restricted by moderation (403 with status field)
    ContentRestricted(String),
    /// Blob not found
    NotFound(String),
    /// Bad request - malformed input
    BadRequest(String),
    /// Storage backend error
    StorageError(String),
    /// Metadata store error
    MetadataError(String),
    /// Internal server error
    Internal(String),
}

impl BlossomError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            BlossomError::AuthRequired(_) => StatusCode::UNAUTHORIZED,
            BlossomError::AuthInvalid(_) => StatusCode::UNAUTHORIZED,
            BlossomError::Forbidden(_) => StatusCode::FORBIDDEN,
            BlossomError::ContentRestricted(_) => StatusCode::FORBIDDEN,
            BlossomError::NotFound(_) => StatusCode::NOT_FOUND,
            BlossomError::BadRequest(_) => StatusCode::BAD_REQUEST,
            BlossomError::StorageError(_) => StatusCode::BAD_GATEWAY,
            BlossomError::MetadataError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            BlossomError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the moderation status string for ContentRestricted errors
    pub fn moderation_status(&self) -> Option<&str> {
        match self {
            BlossomError::ContentRestricted(status) => Some(status),
            _ => None,
        }
    }

    /// Get the error message
    pub fn message(&self) -> &str {
        match self {
            BlossomError::AuthRequired(msg) => msg,
            BlossomError::AuthInvalid(msg) => msg,
            BlossomError::Forbidden(msg) => msg,
            BlossomError::ContentRestricted(_) => "Content restricted",
            BlossomError::NotFound(msg) => msg,
            BlossomError::BadRequest(msg) => msg,
            BlossomError::StorageError(msg) => msg,
            BlossomError::MetadataError(msg) => msg,
            BlossomError::Internal(msg) => msg,
        }
    }
}

impl fmt::Display for BlossomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for BlossomError {}

/// Result type alias for Blossom operations
pub type Result<T> = std::result::Result<T, BlossomError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(
            BlossomError::AuthRequired("".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            BlossomError::AuthInvalid("".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            BlossomError::Forbidden("".into()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            BlossomError::ContentRestricted("restricted".into()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            BlossomError::NotFound("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            BlossomError::BadRequest("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            BlossomError::StorageError("".into()).status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            BlossomError::MetadataError("".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            BlossomError::Internal("".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_message_extraction() {
        assert_eq!(
            BlossomError::AuthRequired("auth needed".into()).message(),
            "auth needed"
        );
        assert_eq!(
            BlossomError::NotFound("blob gone".into()).message(),
            "blob gone"
        );
        assert_eq!(
            BlossomError::ContentRestricted("banned".into()).message(),
            "Content restricted"
        );
    }

    #[test]
    fn test_content_restricted_moderation_status() {
        let err = BlossomError::ContentRestricted("restricted".into());
        assert_eq!(err.moderation_status(), Some("restricted"));
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(err.message(), "Content restricted");

        let err = BlossomError::ContentRestricted("banned".into());
        assert_eq!(err.moderation_status(), Some("banned"));

        // Other variants return None for moderation_status
        assert_eq!(BlossomError::NotFound("".into()).moderation_status(), None);
        assert_eq!(BlossomError::Forbidden("".into()).moderation_status(), None);
    }

    #[test]
    fn test_display_impl() {
        let err = BlossomError::BadRequest("bad input".into());
        assert_eq!(format!("{}", err), "bad input");
    }
}
