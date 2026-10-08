// ABOUTME: Authenticated, source-versioned subtitle translation jobs.
// ABOUTME: GCS claims deduplicate provider work and expose failures to edge polling.

use super::*;
use blossom_core::subtitle_lang::{
    sanitize_subtitle_lang, translated_vtt_path, TranslationJob, TRANSLATION_LEASE_SECS,
    TRANSLATION_RETRY_SECS,
};
use sha2::{Digest, Sha256};

// Translation request: translate a blob's source transcript into `lang`.
#[derive(Debug, Deserialize)]
pub(super) struct TranslateRequest {
    /// SHA256 hash of the original video whose `main.vtt` is the source.
    hash: String,
    /// Digest of the exact source transcript requested by the edge.
    source_digest: String,
    /// Target language code (e.g. `es` or `pt-BR`).
    lang: String,
}

// Translation response
#[derive(Serialize)]
struct TranslateResponse {
    hash: String,
    lang: String,
    status: String,
    vtt_path: String,
    cue_count: u32,
}

pub(super) async fn handle_translate(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TranslateRequest>,
) -> Response {
    match process_translate(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            error!("Translate error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

const TRANSLATE_SECRET_HEADER: &str = "x-divine-translate-secret";

fn authorize_translate(
    config: &Config,
    headers: &axum::http::HeaderMap,
) -> std::result::Result<(), Response> {
    let Some(expected) = config.translate_shared_secret.as_deref() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "translation not enabled").into_response());
    };
    let provided = headers
        .get(TRANSLATE_SECRET_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid translation secret").into_response())
    }
}

pub(super) async fn require_translate_secret(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if let Err(rejection) = authorize_translate(&state.config, request.headers()) {
        return rejection;
    }
    next.run(request).await
}

fn gcs_error_status(error: &google_cloud_storage::http::Error) -> Option<u16> {
    match error {
        google_cloud_storage::http::Error::Response(response) => Some(response.code),
        google_cloud_storage::http::Error::HttpClient(error) => error.status().map(|s| s.as_u16()),
        _ => None,
    }
}

/// Return only genuine 404s as absent. Preserve all other storage failures.
async fn read_translation_object(
    client: &GcsClient,
    bucket: &str,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    match client
        .download_object(
            &GetObjectRequest {
                bucket: bucket.into(),
                object: path.into(),
                ..Default::default()
            },
            &DownloadRange::default(),
        )
        .await
    {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if gcs_error_status(&error) == Some(404) => Ok(None),
        Err(error) => Err(anyhow!("Translation storage read failed: {}", error)),
    }
}

async fn write_translation_job(
    state: &AppState,
    path: &str,
    job: &TranslationJob,
    generation: i64,
) -> Result<Option<i64>> {
    let mut media = Media::new(path.to_string());
    media.content_type = "application/json".into();
    match state
        .gcs_client
        .upload_object(
            &UploadObjectRequest {
                bucket: state.config.gcs_bucket.clone(),
                if_generation_match: Some(generation),
                ..Default::default()
            },
            Bytes::from(serde_json::to_vec(job)?),
            &UploadType::Simple(media),
        )
        .await
    {
        Ok(object) => Ok(Some(object.generation)),
        Err(error) if gcs_error_status(&error) == Some(412) => Ok(None),
        Err(error) => Err(anyhow!("Translation claim write failed: {}", error)),
    }
}

/// The generation precondition serializes workers across Cloud Run instances.
async fn claim_translation(state: &AppState, path: &str) -> Result<Option<i64>> {
    let object = match state
        .gcs_client
        .get_object(&GetObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            object: path.into(),
            ..Default::default()
        })
        .await
    {
        Ok(object) => Some(object),
        Err(error) if gcs_error_status(&error) == Some(404) => None,
        Err(error) => return Err(anyhow!("Translation claim read failed: {}", error)),
    };
    let generation = if let Some(object) = object {
        // Pin the read to this generation; do not reclaim based on another worker's state.
        let raw = state
            .gcs_client
            .download_object(
                &GetObjectRequest {
                    bucket: state.config.gcs_bucket.clone(),
                    object: path.into(),
                    generation: Some(object.generation),
                    ..Default::default()
                },
                &DownloadRange::default(),
            )
            .await?;
        let job: TranslationJob = serde_json::from_slice(&raw)?;
        if !job.can_start(current_epoch_secs()) {
            return Ok(None);
        }
        object.generation
    } else {
        0
    };
    write_translation_job(
        state,
        path,
        &TranslationJob::Processing {
            retry_at: current_epoch_secs() + TRANSLATION_LEASE_SECS,
        },
        generation,
    )
    .await
}

async fn process_translate(
    state: Arc<AppState>,
    request: TranslateRequest,
) -> Result<TranslateResponse> {
    process_translate_with(state.clone(), request, move |lang, texts| async move {
        translation_google_v3::translate_texts(&state.config, &lang, &texts).await
    })
    .await
}

async fn process_translate_with<F, Fut>(
    state: Arc<AppState>,
    request: TranslateRequest,
    translate: F,
) -> Result<TranslateResponse>
where
    F: FnOnce(String, Vec<String>) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<Vec<String>, ProviderFailure>>,
{
    let hash = request.hash.to_lowercase();
    if hash.len() != 64
        || !hash.bytes().all(|c| c.is_ascii_hexdigit())
        || request.source_digest.len() != 64
        || !request.source_digest.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(anyhow!("Invalid hash or source digest"));
    }
    let lang = sanitize_subtitle_lang(Some(request.lang))
        .ok_or_else(|| anyhow!("Invalid target language"))?;
    let source_digest = request.source_digest.to_lowercase();
    let target_path = translated_vtt_path(&hash, &source_digest, &lang);
    let response = |status: &str, cue_count: u32| TranslateResponse {
        hash: hash.clone(),
        lang: lang.clone(),
        status: status.into(),
        vtt_path: target_path.clone(),
        cue_count,
    };
    if read_translation_object(&state.gcs_client, &state.config.gcs_bucket, &target_path)
        .await?
        .is_some()
    {
        return Ok(response("already_exists", 0));
    }
    let source_path = format!("{hash}/vtt/main.vtt");
    let Some(source) =
        read_translation_object(&state.gcs_client, &state.config.gcs_bucket, &source_path).await?
    else {
        return Ok(response("no_source", 0));
    };
    if hex::encode(Sha256::digest(&source)) != source_digest {
        return Ok(response("source_changed", 0));
    }
    let job_path = format!("{target_path}.json");
    let Some(generation) = claim_translation(&state, &job_path).await? else {
        return Ok(response("pending_or_failed", 0));
    };
    // Recheck after the claim: a preceding worker may have completed between reads.
    let result = tokio::time::timeout(Duration::from_secs(100), async {
        if read_translation_object(&state.gcs_client, &state.config.gcs_bucket, &target_path)
            .await?
            .is_some()
        {
            return Ok(response("already_exists", 0));
        }
        let source = String::from_utf8(source)?;
        let cues = translation_google_v3::parse_vtt_cues(&source);
        if cues.is_empty() {
            return Err(anyhow!("empty_source"));
        }
        let texts: Vec<String> = cues.iter().map(|cue| cue.text.clone()).collect();
        // Bound provider concurrency as well as deduplicating individual jobs.
        let _permit = state
            .provider_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("provider_busy"))?;
        let translated = match translate(lang.clone(), texts).await {
            Ok(text) => text,
            Err(failure) => {
                // Store only safe, stable codes; provider bodies may contain transcript text.
                let terminal = failure.status_code == Some(400);
                let code = if terminal {
                    "translation_rejected"
                } else {
                    "provider_unavailable"
                };
                let retry_at = if terminal {
                    None
                } else {
                    Some(
                        current_epoch_secs()
                            + failure
                                .retry_after
                                .map(|d| d.as_secs())
                                .unwrap_or(TRANSLATION_RETRY_SECS),
                    )
                };
                write_translation_job(
                    &state,
                    &job_path,
                    &TranslationJob::Failed {
                        code: code.into(),
                        retry_at,
                    },
                    generation,
                )
                .await?;
                return Ok(response("failed", 0));
            }
        };
        if translated.len() != cues.len() {
            return Err(anyhow!("invalid_provider_response"));
        }
        let rendered = translation_google_v3::render_vtt(&cues, &translated, &lang);
        upload_transcript_variant_to_gcs(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &target_path,
            &rendered,
        )
        .await?;
        Ok(response("complete", cues.len() as u32))
    })
    .await
    .unwrap_or_else(|_| Err(anyhow!("translation_timeout")));
    if let Err(error) = &result {
        error!("Translation job failed: {}", error);
        let empty = error.to_string() == "empty_source";
        write_translation_job(
            &state,
            &job_path,
            &TranslationJob::Failed {
                code: if empty {
                    "empty_source"
                } else {
                    "translation_unavailable"
                }
                .into(),
                retry_at: if empty {
                    None
                } else {
                    Some(current_epoch_secs() + TRANSLATION_RETRY_SECS)
                },
            },
            generation,
        )
        .await?;
    }
    result
}

/// Upload a translated VTT to its source-versioned object path.
async fn upload_transcript_variant_to_gcs(
    client: &GcsClient,
    bucket: &str,
    gcs_path: &str,
    vtt_content: &str,
) -> Result<()> {
    let mut media = Media::new(gcs_path.to_string());
    media.content_type = "text/vtt".into();
    let upload_type = UploadType::Simple(media);

    let req = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(
            &req,
            Bytes::from(vtt_content.as_bytes().to_vec()),
            &upload_type,
        )
        .await
        .map_err(|e| anyhow!("Failed to upload transcript {}: {}", gcs_path, e))?;

    info!("Uploaded transcript {}", gcs_path);
    Ok(())
}

#[cfg(test)]
#[path = "translation_tests.rs"]
mod tests;
