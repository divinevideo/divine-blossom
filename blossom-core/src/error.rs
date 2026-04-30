use http::StatusCode;
use std::fmt;

#[derive(Debug)]
pub enum BlossomError {
    AuthRequired(String),
    AuthInvalid(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    BadRequest(String),
    Gone(String),
    RangeNotSatisfiable(String),
    UnprocessableEntity(String),
    StorageError(String),
    MetadataError(String),
    Internal(String),
}

impl BlossomError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            BlossomError::AuthRequired(_) => StatusCode::UNAUTHORIZED,
            BlossomError::AuthInvalid(_) => StatusCode::UNAUTHORIZED,
            BlossomError::Forbidden(_) => StatusCode::FORBIDDEN,
            BlossomError::NotFound(_) => StatusCode::NOT_FOUND,
            BlossomError::Conflict(_) => StatusCode::CONFLICT,
            BlossomError::BadRequest(_) => StatusCode::BAD_REQUEST,
            BlossomError::Gone(_) => StatusCode::GONE,
            BlossomError::RangeNotSatisfiable(_) => {
                StatusCode::from_u16(416).expect("416 is a valid HTTP status code")
            }
            BlossomError::UnprocessableEntity(_) => {
                StatusCode::from_u16(422).expect("422 is a valid HTTP status code")
            }
            BlossomError::StorageError(_) => StatusCode::BAD_GATEWAY,
            BlossomError::MetadataError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            BlossomError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            BlossomError::AuthRequired(msg) => msg,
            BlossomError::AuthInvalid(msg) => msg,
            BlossomError::Forbidden(msg) => msg,
            BlossomError::NotFound(msg) => msg,
            BlossomError::Conflict(msg) => msg,
            BlossomError::BadRequest(msg) => msg,
            BlossomError::Gone(msg) => msg,
            BlossomError::RangeNotSatisfiable(msg) => msg,
            BlossomError::UnprocessableEntity(msg) => msg,
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
            BlossomError::NotFound("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            BlossomError::Conflict("".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            BlossomError::BadRequest("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            BlossomError::Gone("".into()).status_code(),
            StatusCode::GONE
        );
        assert_eq!(
            BlossomError::RangeNotSatisfiable("".into()).status_code(),
            StatusCode::from_u16(416).unwrap()
        );
        assert_eq!(
            BlossomError::UnprocessableEntity("".into()).status_code(),
            StatusCode::from_u16(422).unwrap()
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
    }

    #[test]
    fn test_display_impl() {
        let err = BlossomError::BadRequest("bad input".into());
        assert_eq!(format!("{}", err), "bad input");
    }
}
