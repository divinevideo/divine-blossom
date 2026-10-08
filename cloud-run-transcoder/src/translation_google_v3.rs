// ABOUTME: Google Cloud Translation (v3) provider for subtitle translation.
// ABOUTME: Translates WebVTT cue text in place, preserving cue timings.

use crate::{fetch_gcp_access_token, Config, ProviderFailure};

/// One WebVTT cue: the original timing line, kept verbatim, and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VttCue {
    pub(crate) timing: String,
    pub(crate) text: String,
}

/// Parse a WebVTT document into cues, preserving each timing line verbatim.
///
/// Tolerant: a malformed cue (timing line without text) is skipped rather than
/// failing the whole document. The header and any `NOTE`/`STYLE` blocks before
/// the first timing line are dropped.
pub(crate) fn parse_vtt_cues(vtt: &str) -> Vec<VttCue> {
    let mut cues = Vec::new();
    let lines: Vec<&str> = vtt.lines().collect();
    let mut i = 0;

    // Skip everything up to the first timing line (WEBVTT header, metadata).
    while i < lines.len() && !lines[i].contains("-->") {
        i += 1;
    }

    while i < lines.len() {
        let line = lines[i].trim();
        if !line.contains("-->") {
            i += 1;
            continue;
        }
        let timing = line.to_string();
        i += 1;
        let mut text_lines: Vec<&str> = Vec::new();
        while i < lines.len() && !lines[i].trim().is_empty() {
            text_lines.push(lines[i].trim());
            i += 1;
        }
        if !text_lines.is_empty() {
            cues.push(VttCue {
                timing,
                text: text_lines.join("\n"),
            });
        }
    }

    cues
}

/// Render a complete translated track, preserving cue timings.
/// Missing or extra provider results must never produce mixed-language cues.
pub(crate) fn render_vtt(
    cues: &[VttCue],
    translated: &[String],
    target_lang: &str,
) -> anyhow::Result<String> {
    anyhow::ensure!(cues.len() == translated.len(), "invalid_provider_response");
    let mut out = format!("WEBVTT\n\nNOTE\nMachine-translated by Google Cloud Translation\nTarget-Language: {target_lang}\n\n");
    for (index, cue) in cues.iter().enumerate() {
        let text = &translated[index];
        out.push_str(&format!(
            "{}\n{}\n{}\n\n",
            index + 1,
            cue.timing,
            escape_vtt_text(text),
        ));
    }
    Ok(out)
}

/// Build the Cloud Translation v3 `translateText` request body.
///
/// One request carries every cue so the provider can use cross-cue context.
pub(crate) fn build_translate_request(contents: &[String], target_lang: &str) -> String {
    let body = serde_json::json!({
        "contents": contents,
        "targetLanguageCode": target_lang,
        "mimeType": "text/plain",
    });
    body.to_string()
}

/// The Cloud Translation v3 endpoint for the configured location.
pub(crate) fn translate_url(config: &Config) -> String {
    let location = config.google_translate_location.trim();
    let location = if location.is_empty() {
        "global"
    } else {
        location
    };
    format!(
        "https://translation.googleapis.com/v3/projects/{}/locations/{}:translateText",
        config.gcp_project_id, location,
    )
}

/// Parse a `translateText` response into one translated string per input,
/// in order. Returns an empty vec when the response carries no translations.
pub(crate) fn parse_translate_response(
    raw: &str,
) -> std::result::Result<Vec<String>, anyhow::Error> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("Invalid translate JSON: {}", e))?;
    let Some(arr) = value.get("translations").and_then(|t| t.as_array()) else {
        return Ok(Vec::new());
    };
    Ok(arr
        .iter()
        .filter_map(|t| t.get("translatedText").and_then(|v| v.as_str()))
        .map(unescape_html_entities)
        .collect())
}

/// Cloud Translation returns a few HTML entities even for `text/plain`
/// (`&#39;`, `&quot;`, `&amp;`); decode the common ones so cue text reads
/// correctly.
fn unescape_html_entities(text: &str) -> String {
    text.replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Cue text is plain text, never WebVTT markup. Escape after decoding once.
fn escape_vtt_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Translate `texts` into `target_lang` in a single v3 call.
pub(crate) async fn translate_texts(
    config: &Config,
    target_lang: &str,
    texts: &[String],
) -> std::result::Result<Vec<String>, ProviderFailure> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    let access_token = fetch_gcp_access_token().await?;
    let url = translate_url(config);
    let body = build_translate_request(texts, target_lang);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&access_token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| {
            crate::parse_provider_status(
                None,
                None,
                &format!("Failed to call Cloud Translation: {}", e),
                e.is_timeout(),
            )
        })?;

    let status = response.status();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let resp_body = response.text().await.map_err(|e| {
        crate::parse_provider_status(
            Some(status.as_u16()),
            retry_after.as_deref(),
            &format!("Failed to read Cloud Translation response: {}", e),
            e.is_timeout(),
        )
    })?;

    if !status.is_success() {
        return Err(crate::parse_provider_status(
            Some(status.as_u16()),
            retry_after.as_deref(),
            &resp_body,
            false,
        ));
    }

    parse_translate_response(&resp_body).map_err(|e| {
        crate::parse_provider_status(Some(status.as_u16()), None, &e.to_string(), false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VTT: &str = "WEBVTT\n\n1\n00:00:00.500 --> 00:00:03.200\nHello world\n\n2\n00:00:03.500 --> 00:00:06.000\nSecond cue\n";

    #[test]
    fn parses_cues_and_keeps_timings_verbatim() {
        let cues = parse_vtt_cues(SAMPLE_VTT);
        assert_eq!(cues.len(), 2);
        assert_eq!(cues[0].timing, "00:00:00.500 --> 00:00:03.200");
        assert_eq!(cues[0].text, "Hello world");
        assert_eq!(cues[1].timing, "00:00:03.500 --> 00:00:06.000");
        assert_eq!(cues[1].text, "Second cue");
    }

    #[test]
    fn render_replaces_text_and_keeps_timings() {
        let cues = parse_vtt_cues(SAMPLE_VTT);
        let rendered = render_vtt(&cues, &["Hola mundo".into(), "Segunda".into()], "es").unwrap();
        assert!(rendered.starts_with("WEBVTT"));
        assert!(rendered.contains("00:00:00.500 --> 00:00:03.200\nHola mundo"));
        assert!(rendered.contains("00:00:03.500 --> 00:00:06.000\nSegunda"));
        assert!(!rendered.contains("Hello world"));
    }

    #[test]
    fn render_rejects_missing_or_extra_translations() {
        let cues = parse_vtt_cues(SAMPLE_VTT);
        assert!(render_vtt(&cues, &["Hola mundo".into()], "es").is_err());
        assert!(render_vtt(
            &cues,
            &["Hola".into(), "Segunda".into(), "Extra".into()],
            "es"
        )
        .is_err());
    }

    #[test]
    fn parse_skips_header_and_malformed_cues() {
        let vtt = "WEBVTT\nKind: captions\nLanguage: en\n\n1\n0:00.000 --> 0:01.000\nHi\n\nno timing here";
        let cues = parse_vtt_cues(vtt);
        assert_eq!(cues.len(), 1);
        assert_eq!(cues[0].text, "Hi");
    }

    #[test]
    fn parse_empty_document_yields_no_cues() {
        assert!(parse_vtt_cues("WEBVTT\n\n").is_empty());
    }

    #[test]
    fn builds_request_with_all_contents_and_target() {
        let body = build_translate_request(&["Hello".into(), "World".into()], "es");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["targetLanguageCode"], "es");
        assert_eq!(v["contents"].as_array().unwrap().len(), 2);
        assert_eq!(v["contents"][0], "Hello");
    }

    #[test]
    fn parses_translations_in_order() {
        let raw = r#"{"translations":[{"translatedText":"Hola"},{"translatedText":"Mundo"}]}"#;
        let parsed = parse_translate_response(raw).unwrap();
        assert_eq!(parsed, vec!["Hola".to_string(), "Mundo".to_string()]);
    }

    #[test]
    fn parses_missing_translations_as_empty() {
        assert!(parse_translate_response("{}").unwrap().is_empty());
    }

    #[test]
    fn decodes_common_html_entities() {
        let raw = r#"{"translations":[{"translatedText":"c&#39;est &quot;bien&quot; &amp; bon"}]}"#;
        let parsed = parse_translate_response(raw).unwrap();
        assert_eq!(parsed, vec!["c'est \"bien\" & bon".to_string()]);
    }

    #[test]
    fn translate_url_defaults_to_global_location() {
        let cfg = Config::from_lookup(|_| None);
        let url = translate_url(&cfg);
        assert!(url.starts_with("https://translation.googleapis.com/v3/projects/"));
        assert!(url.ends_with("/locations/global:translateText"));
    }
    #[test]
    fn renders_machine_translation_marker_and_escapes_text() {
        let cues = parse_vtt_cues(SAMPLE_VTT);
        let rendered = render_vtt(
            &cues,
            &["<test> & literal &lt;".into(), "Second".into()],
            "es",
        )
        .unwrap();
        assert!(rendered.contains("NOTE\nMachine-translated"));
        assert!(rendered.contains("&lt;test&gt; &amp; literal &amp;lt;"));
    }

    #[test]
    fn does_not_double_decode_entities() {
        assert_eq!(unescape_html_entities("&amp;lt;"), "&lt;");
    }
}
