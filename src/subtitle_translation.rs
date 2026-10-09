// ABOUTME: Source-versioned translated VTT serving and observable worker dispatch.
// ABOUTME: Preserves the source lifecycle and labels every translated response.

use super::*;
use blossom_core::subtitle_lang::{translated_vtt_path, TranslationJob};

thread_local! {
    // A guest handles one downstream request, which can dispatch at most one translation.
    static SUBTITLE_TRANSLATION_REQUEST: std::cell::RefCell<Option<(String, fastly::http::request::PendingRequest)>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn finish_subtitle_translation() {
    SUBTITLE_TRANSLATION_REQUEST.with(|slot| {
        let Some((path, pending)) = slot.borrow_mut().take() else {
            return;
        };
        let delivered = match pending.wait() {
            Ok(response) if response.get_status().is_success() => true,
            Ok(response) => {
                eprintln!(
                    "[VTT] Translation worker returned HTTP {}",
                    response.get_status()
                );
                false
            }
            Err(error) => {
                eprintln!("[VTT] Translation worker delivery failed: {}", error);
                false
            }
        };
        if !delivered {
            // Avoid reporting endless pending work when the worker rejects delivery.
            let _ = simple_cache::get_or_set(
                format!("translation-dispatch:{path}"),
                b"failed".as_slice(),
                Duration::from_secs(60),
            );
        }
    });
}

/// Translation cache keys follow the source bytes, rather than mutable main status.
pub(super) fn serve_translated_transcript(
    req: Option<&Request>,
    hash: &str,
    lang: &str,
    source: &[u8],
    secret_value: &str,
) -> Result<Response> {
    let digest = hex::encode(Sha256::digest(source));
    let path = translated_vtt_path(hash, &digest, lang);
    match download_transcript_content(&path) {
        Ok(mut response) => {
            response.set_header("Content-Type", "text/vtt; charset=utf-8");
            response.set_header("Content-Language", lang);
            response.set_header("X-Divine-Machine-Translated", "true");
            add_cors_headers(&mut response);
            return Ok(response);
        }
        Err(BlossomError::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    let job_path = format!("{path}.json");
    let now = unix_timestamp_secs();
    match crate::storage::download_transcript_uncached_from_gcs(&job_path) {
        Ok(mut response) => {
            let job: TranslationJob = serde_json::from_slice(&response.take_body().into_bytes())
                .map_err(|_| BlossomError::StorageError("Invalid translation job state".into()))?;
            match job {
                TranslationJob::Failed { code, retry_at }
                    if retry_at.map_or(true, |at| at > now) =>
                {
                    let mut response = json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &serde_json::json!({
                            "status": "translation_unavailable", "error_code": code, "terminal": retry_at.is_none(),
                            "message": "Translation unavailable; use the original transcript"
                        }),
                    );
                    if let Some(at) = retry_at {
                        response
                            .set_header("Retry-After", at.saturating_sub(now).max(1).to_string());
                    }
                    add_no_cache_headers(&mut response);
                    add_cors_headers(&mut response);
                    return Ok(response);
                }
                TranslationJob::Processing { retry_at } if retry_at > now => {
                    return Ok(translation_pending_response())
                }
                _ => {}
            }
        }
        Err(BlossomError::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    if matches!(
        simple_cache::get(format!("translation-dispatch:{path}")),
        Ok(Some(_))
    ) {
        let mut response = json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &serde_json::json!({
                "status": "translation_unavailable", "error_code": "dispatch_unavailable", "terminal": false
            }),
        );
        response.set_header("Retry-After", "60");
        add_no_cache_headers(&mut response);
        add_cors_headers(&mut response);
        return Ok(response);
    }
    if let Some(req) = req {
        let auth_header = req.get_header_str("Authorization").unwrap_or_default();
        if let Some(response) = enforce_transcribe_rate_limit(req, auth_header) {
            return Ok(response);
        }
    }
    if trigger_subtitle_translation(hash, &digest, lang, secret_value).is_err() {
        return Ok(translation_unavailable_response("dispatch_unavailable"));
    }
    Ok(translation_pending_response())
}

fn translation_pending_response() -> Response {
    let mut response = json_response(
        StatusCode::ACCEPTED,
        &serde_json::json!({
            "status": "translating", "message": "Subtitle translation in progress, please retry soon"
        }),
    );
    response.set_header("Retry-After", SUBTITLE_TRANSLATION_RETRY_AFTER.to_string());
    add_no_cache_headers(&mut response);
    add_cors_headers(&mut response);
    response
}

/// Absence, empty values, and inaccessible stores all disable translation.
pub(super) fn translation_dispatch_secret() -> Option<String> {
    let secret = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()?
        .try_get("translate_shared_secret")
        .ok()??;
    let value = String::from_utf8(secret.try_plaintext().ok()?.to_vec()).ok()?;
    (!value.trim().is_empty()).then_some(value)
}

pub(super) fn translation_unavailable_response(code: &str) -> Response {
    let mut response = json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &serde_json::json!({
            "status": "translation_unavailable", "error_code": code, "terminal": false,
            "message": "Translation unavailable; use the original transcript"
        }),
    );
    response.set_header("Retry-After", "60");
    add_no_cache_headers(&mut response);
    add_cors_headers(&mut response);
    response
}

/// The worker persists its claim and failures; later polls observe their state.
fn trigger_subtitle_translation(
    hash: &str,
    source_digest: &str,
    lang: &str,
    secret_value: &str,
) -> Result<()> {
    let url = format!("https://{}/translate", CLOUD_RUN_TRANSCODER_HOST);
    let mut proxy_req = Request::new(Method::POST, &url);
    proxy_req.set_header("Host", CLOUD_RUN_TRANSCODER_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_header("X-Divine-Translate-Secret", secret_value);
    proxy_req.set_body(
        serde_json::json!({ "hash": hash, "source_digest": source_digest, "lang": lang })
            .to_string(),
    );
    let pending = proxy_req.send_async(TRANSCODER_BACKEND).map_err(|error| {
        eprintln!("[VTT] Translation dispatch failed: {}", error);
        BlossomError::Internal("Translation dispatch unavailable".into())
    })?;
    let path = translated_vtt_path(hash, source_digest, lang);
    SUBTITLE_TRANSLATION_REQUEST.with(|slot| *slot.borrow_mut() = Some((path, pending)));
    Ok(())
}
