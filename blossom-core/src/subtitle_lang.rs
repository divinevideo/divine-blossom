// ABOUTME: Pure helpers for the `?lang=` subtitle-translation query parameter.
// ABOUTME: Lives here (not the Fastly edge) so it can be unit-tested natively.

// Cloud Translation's default NMT model language codes, checked 2026-10-08.
// https://docs.cloud.google.com/translate/docs/languages#neural_machine_translation_model
// Keep this shared by edge and worker; unsupported targets never dispatch work.
const SUPPORTED_TRANSLATION_LANGUAGES: &[&str] = &[
    "ab", "ace", "ach", "af", "sq", "alz", "am", "ar", "hy", "as", "awa", "ay", "az", "ban", "bm",
    "ba", "eu", "btx", "bts", "bbc", "be", "bem", "bn", "bew", "bho", "bik", "bs", "br", "bg",
    "bua", "yue", "ca", "ceb", "ny", "zh-CN", "zh", "zh-TW", "cv", "co", "crh", "hr", "cs", "da",
    "din", "dv", "doi", "dov", "nl", "dz", "en", "eo", "et", "ee", "fj", "fil", "tl", "fi", "fr",
    "fr-FR", "fr-CA", "fy", "ff", "gaa", "gl", "lg", "ka", "de", "el", "gn", "gu", "ht", "cnh",
    "ha", "haw", "iw", "he", "hil", "hi", "hmn", "hu", "hrx", "is", "ig", "ilo", "id", "ga", "it",
    "ja", "jw", "jv", "kn", "pam", "kk", "km", "cgg", "rw", "ktu", "gom", "ko", "kri", "ku", "ckb",
    "ky", "lo", "ltg", "la", "lv", "lij", "li", "ln", "lt", "lmo", "luo", "lb", "mk", "mai", "mak",
    "mg", "ms", "ms-Arab", "ml", "mt", "mi", "mr", "chm", "mni-Mtei", "min", "lus", "mn", "my",
    "nr", "new", "ne", "nso", "no", "nus", "oc", "or", "om", "pag", "pap", "ps", "fa", "pl", "pt",
    "pt-PT", "pt-BR", "pa", "pa-Arab", "qu", "rom", "ro", "rn", "ru", "sm", "sg", "sa", "gd", "sr",
    "st", "crs", "shn", "sn", "scn", "szl", "sd", "si", "sk", "sl", "so", "es", "su", "sw", "ss",
    "sv", "tg", "ta", "tt", "te", "tet", "th", "ti", "ts", "tn", "tr", "tk", "ak", "uk", "ur",
    "ug", "uz", "vi", "cy", "xh", "yi", "yo", "yua", "zu",
];

/// Canonicalize a target language for both the edge and the translation worker.
/// Preserve provider-supported script and regional codes. Other
/// well-formed locale hints fall back to their primary language. Provider support
/// is checked against the default NMT model before any storage or provider work.
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
    let canonical = match lang.as_str() {
        "zh-tw" | "zh-hant" | "zh-hk" => "zh-TW",
        "zh-cn" | "zh-hans" => "zh-CN",
        _ => SUPPORTED_TRANSLATION_LANGUAGES
            .iter()
            .copied()
            .find(|code| code.eq_ignore_ascii_case(&lang))
            .unwrap_or(primary),
    };
    SUPPORTED_TRANSLATION_LANGUAGES
        .contains(&canonical)
        .then(|| canonical.to_string())
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
    fn rejects_unsupported_provider_languages() {
        for input in ["zz", "zzz", "abc", "zz-US"] {
            assert_eq!(sanitize_subtitle_lang(Some(input.into())), None, "{input}");
        }
    }

    #[test]
    fn every_supported_provider_code_round_trips() {
        for code in SUPPORTED_TRANSLATION_LANGUAGES {
            assert_eq!(
                sanitize_subtitle_lang(Some(code.to_string())),
                Some(code.to_string())
            );
        }
    }

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
