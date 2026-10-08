// ABOUTME: Pure helpers for the `?lang=` subtitle-translation query parameter.
// ABOUTME: Lives here (not the Fastly edge) so it can be unit-tested natively.

/// Canonicalize a target language for both the edge and the translation worker.
/// Preserve provider-supported Chinese scripts and Portuguese regions. Other
/// well-formed locale hints fall back to their primary language. Provider support
/// is checked by the translation API; a rejection becomes a terminal job failure.
pub fn sanitize_subtitle_lang(raw: Option<String>) -> Option<String> {
    let lang = raw?.trim().to_ascii_lowercase();
    if lang.len() > 35 {
        return None;
    }
    let parts: Vec<&str> = lang.split('-').collect();
    let primary = parts[0];
    if !(2..=3).contains(&primary.len())
        || !primary.bytes().all(|c| c.is_ascii_lowercase())
        || primary == "und"
        || primary == "auto"
    {
        return None;
    }
    if parts.len() > 2
        || parts.iter().skip(1).any(|part| {
            !matches!(part.len(), 2 | 4) || !part.bytes().all(|c| c.is_ascii_lowercase())
        })
    {
        return None;
    }
    Some(
        match lang.as_str() {
            "zh-tw" | "zh-hant" | "zh-hk" => "zh-TW",
            "zh-cn" | "zh-hans" => "zh-CN",
            "pt-br" => "pt-BR",
            "pt-pt" => "pt-PT",
            _ => primary,
        }
        .to_string(),
    )
}

/// Paths contain the source content digest, so a rewrite cannot reuse old text.
pub fn translated_vtt_path(hash: &str, source_digest: &str, lang: &str) -> String {
    format!("{hash}/vtt/translations/{source_digest}/{lang}.vtt")
}

pub const TRANSLATION_LEASE_SECS: u64 = 120;
pub const TRANSLATION_RETRY_SECS: u64 = 60;

/// Durable claim and failure state shared by polling edge requests and workers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TranslationJob {
    Processing { retry_at: u64 },
    Failed { code: String, retry_at: Option<u64> },
}

impl TranslationJob {
    pub fn can_start(&self, now: u64) -> bool {
        match self {
            Self::Processing { retry_at } => now >= *retry_at,
            Self::Failed {
                retry_at: Some(retry_at),
                ..
            } => now >= *retry_at,
            Self::Failed { retry_at: None, .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[test]
    fn preserves_translation_language_distinctions() {
        for (input, expected) in [
            ("zh-TW", "zh-TW"),
            ("zh-Hant", "zh-TW"),
            ("zh-Hans", "zh-CN"),
            ("pt-BR", "pt-BR"),
            ("pt-PT", "pt-PT"),
        ] {
            assert_eq!(
                sanitize_subtitle_lang(Some(input.into())),
                Some(expected.into())
            );
        }
    }

    #[test]
    fn rejects_invalid_language_shapes_and_reserved_paths() {
        for input in ["-es", "es-a", "main", "123", "auto-US", "und-US", "es--US"] {
            assert_eq!(sanitize_subtitle_lang(Some(input.into())), None, "{input}");
        }
    }

    #[test]
    fn translation_paths_change_with_source_and_keep_language() {
        assert_ne!(
            translated_vtt_path("hash", "old", "es"),
            translated_vtt_path("hash", "new", "es")
        );
        assert!(translated_vtt_path("hash", "new", "pt-BR").ends_with("/pt-BR.vtt"));
    }

    #[test]
    fn claims_and_failures_control_retries() {
        let processing = TranslationJob::Processing { retry_at: 120 };
        assert!(!processing.can_start(119));
        assert!(processing.can_start(120));
        let cooldown = TranslationJob::Failed {
            code: "provider_unavailable".into(),
            retry_at: Some(180),
        };
        assert!(!cooldown.can_start(179));
        assert!(cooldown.can_start(180));
        assert!(!TranslationJob::Failed {
            code: "unsupported_language".into(),
            retry_at: None
        }
        .can_start(u64::MAX));
        let json = serde_json::to_string(&processing).unwrap();
        assert_eq!(
            serde_json::from_str::<TranslationJob>(&json).unwrap(),
            processing
        );
    }
}
