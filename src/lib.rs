pub mod admin_sweep;
pub mod blossom;
pub mod error;
pub mod media_auth_log;
pub mod resumable_complete;
pub mod viewer_auth;

#[cfg(test)]
mod tests {
    use crate::resumable_complete::parse_resumable_complete_request_body;

    #[test]
    fn empty_completion_body_is_allowed() {
        assert_eq!(parse_resumable_complete_request_body("").unwrap(), None);
    }

    #[test]
    fn empty_json_object_is_treated_like_no_completion_body() {
        assert_eq!(parse_resumable_complete_request_body("{}").unwrap(), None);
    }

    #[test]
    fn completion_body_with_sha256_preserves_requested_hash() {
        let hash = "131593302d5e3a84709d3e18b75d8627a3980b2ddbd256a47d30eb396f8baf4e";

        assert_eq!(
            parse_resumable_complete_request_body(&format!(r#"{{"sha256":"{}"}}"#, hash)).unwrap(),
            Some(hash.to_string())
        );
    }

    #[test]
    fn non_empty_completion_object_without_sha256_is_rejected() {
        let error = parse_resumable_complete_request_body(r#"{"unexpected":true}"#)
            .expect_err("missing sha256 should be rejected");

        assert!(error.contains("missing field"));
    }
}
