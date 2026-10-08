// ABOUTME: Pure helpers for the `?lang=` subtitle-translation query parameter.
// ABOUTME: Lives here (not the Fastly edge) so it can be unit-tested natively.

/// Sanitize a subtitle target-language tag from a `?lang=` query value.
///
/// Returns the bare primary subtag when `raw` is a plausible language code,
/// else `None` so the caller falls back to the source transcript. Restricting
/// to ASCII alphanumerics and hyphen keeps the value from steering the GCS
/// object path (`{hash}/vtt/{lang}.vtt`).
///
/// `auto` and `und` are language-detection sentinels, not targets, so they are
/// treated as absent.
pub fn sanitize_subtitle_lang(raw: Option<String>) -> Option<String> {
    let lang = raw?.trim().to_ascii_lowercase();
    if lang.is_empty() || lang == "auto" || lang == "und" || lang.len() > 35 {
        return None;
    }
    if !lang.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    Some(lang.split('-').next().unwrap_or(&lang).to_string())
}

#[cfg(test)]
mod tests {
    use super::sanitize_subtitle_lang;

    #[test]
    fn accepts_and_normalizes_plain_codes() {
        assert_eq!(sanitize_subtitle_lang(Some("es".into())), Some("es".into()));
        assert_eq!(sanitize_subtitle_lang(Some("EN".into())), Some("en".into()));
        assert_eq!(
            sanitize_subtitle_lang(Some("de-CH".into())),
            Some("de".into())
        );
    }

    #[test]
    fn rejects_sentinels_and_empty() {
        assert_eq!(sanitize_subtitle_lang(None), None);
        assert_eq!(sanitize_subtitle_lang(Some(String::new())), None);
        assert_eq!(sanitize_subtitle_lang(Some("auto".into())), None);
        assert_eq!(sanitize_subtitle_lang(Some("und".into())), None);
    }

    #[test]
    fn rejects_path_steering_and_overlong_values() {
        assert_eq!(sanitize_subtitle_lang(Some("../etc".into())), None);
        assert_eq!(sanitize_subtitle_lang(Some("a/b".into())), None);
        assert_eq!(sanitize_subtitle_lang(Some("a".repeat(40))), None);
    }
}
