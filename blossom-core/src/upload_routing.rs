//! Canonical direct-upload routing, independent of downstream storage authority.
pub const INLINE_UPLOAD_MAX_BYTES: u64 = 500 * 1024;

pub fn should_proxy(flag: Option<&str>, size: u64, mime: &str) -> Result<bool, &'static str> {
    let all = match flag {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err("Invalid upload_service_all_uploads configuration"),
    };
    Ok(all || size > INLINE_UPLOAD_MAX_BYTES || crate::types::is_video_mime_type(mime))
}

#[cfg(test)]
mod tests {
    use super::should_proxy;
    #[test]
    fn absent_or_disabled_preserves_small_image_boundary() {
        for flag in [None, Some("false")] {
            for size in [0, 1, 512_000] {
                assert_eq!(should_proxy(flag, size, "image/jpeg"), Ok(false));
            }
            assert_eq!(should_proxy(flag, 512_001, "image/jpeg"), Ok(true));
        }
    }
    #[test]
    fn existing_video_proxy_behavior_is_preserved() {
        for flag in [None, Some("false"), Some("true")] {
            assert_eq!(should_proxy(flag, 1, "video/mp4"), Ok(true));
            assert_eq!(should_proxy(flag, 1, "video/webm"), Ok(true));
        }
    }
    #[test]
    fn enabled_routes_small_nonvideo_through_provider_service() {
        for mime in [
            "image/jpeg",
            "image/png",
            "audio/ogg",
            "application/octet-stream",
        ] {
            assert_eq!(should_proxy(Some("true"), 1, mime), Ok(true));
        }
    }
    #[test]
    fn invalid_values_never_fall_back_to_inline_gcs() {
        for flag in ["", "TRUE", " true", "false ", "b2", "gcs"] {
            for (size, mime) in [
                (1, "image/jpeg"),
                (1, "video/mp4"),
                (1_000_000, "image/jpeg"),
            ] {
                assert!(should_proxy(Some(flag), size, mime).is_err());
            }
        }
    }
}
