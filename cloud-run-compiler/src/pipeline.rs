// ABOUTME: End-to-end compilation pipeline from resolved Nostr clips to published outputs
// ABOUTME: Downloads and verifies media, probes streams, enforces duration, then renders each aspect

use crate::{
    domain::{AspectFailure, ClipDrop, Job, JobResult, Output},
    render::{render_aspect, AspectRenderJob, ClipInput},
    source::{resolve_sources, ResolvedClip, SourceRepository},
    upload::ResumablePublisher,
    worker::JobExecutor,
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    process::Command,
};

const MAX_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;

pub struct CompilationPipeline {
    repository: Arc<dyn SourceRepository>,
    publisher: ResumablePublisher,
    client: Client,
    temp_root: PathBuf,
    logo_path: PathBuf,
    allowed_media_hosts: HashSet<String>,
    use_gpu: bool,
}

impl CompilationPipeline {
    pub fn new(
        repository: Arc<dyn SourceRepository>,
        publisher: ResumablePublisher,
        temp_root: PathBuf,
        logo_path: PathBuf,
        allowed_media_hosts: impl IntoIterator<Item = String>,
        use_gpu: bool,
    ) -> Result<Self> {
        let allowed_media_hosts: HashSet<String> = allowed_media_hosts.into_iter().collect();
        if allowed_media_hosts.is_empty() {
            bail!("at least one media download host is required");
        }
        Ok(Self {
            repository,
            publisher,
            client: Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(15 * 60))
                .build()
                .context("build media download client")?,
            temp_root,
            logo_path,
            allowed_media_hosts,
            use_gpu,
        })
    }

    async fn execute_inner(&self, job: &Job, work_dir: &Path) -> Result<JobResult> {
        let coordinates = job.request.source.list_event.video_coordinates()?;
        let resolution = resolve_sources(self.repository.as_ref(), &coordinates).await?;
        let mut dropped = resolution.dropped;
        let mut prepared = Vec::new();
        let mut duration_sec = 0.0;
        let max_duration = f64::from(job.request.max_duration_sec);

        for resolved in resolution.usable {
            let path = work_dir.join(format!("{:04}.mp4", resolved.source_index));
            if let Err(error) = self.download(&resolved, &path).await {
                dropped.push(ClipDrop {
                    source_index: resolved.source_index,
                    coordinate: resolved.coordinate,
                    reason: classify_download_error(&error),
                });
                continue;
            }
            let probe = match probe_media(&path).await {
                Ok(probe) => probe,
                Err(_) => {
                    dropped.push(ClipDrop {
                        source_index: resolved.source_index,
                        coordinate: resolved.coordinate,
                        reason: "invalid-media".into(),
                    });
                    continue;
                }
            };
            if duration_sec + probe.duration_sec > max_duration {
                dropped.push(ClipDrop {
                    source_index: resolved.source_index,
                    coordinate: resolved.coordinate,
                    reason: "max-duration".into(),
                });
                continue;
            }

            duration_sec += probe.duration_sec;
            prepared.push(PreparedClip {
                resolved,
                path,
                duration_sec: probe.duration_sec,
                has_audio: probe.has_audio,
            });
        }
        dropped.sort_by_key(|drop| drop.source_index);

        if prepared.is_empty() {
            return Ok(JobResult {
                aspect_failures: job
                    .request
                    .renders
                    .iter()
                    .map(|render| AspectFailure {
                        aspect: render.aspect,
                        code: "no-usable-clips".into(),
                        message: "no signed-list clips could be downloaded and probed".into(),
                    })
                    .collect(),
                clips_dropped: dropped,
                ..JobResult::default()
            });
        }

        let credits = prepared
            .iter()
            .map(|clip| clip.resolved.credit.clone())
            .collect();
        let mut outputs = Vec::new();
        let mut aspect_failures = Vec::new();
        for render in &job.request.renders {
            let output_path = work_dir.join(format!("{}.mp4", aspect_name(render.aspect)));
            let clips = prepared
                .iter()
                .map(|clip| {
                    let fit = render
                        .clip_overrides
                        .iter()
                        .find(|candidate| candidate.coordinate == clip.resolved.coordinate)
                        .map(|candidate| candidate.fit)
                        .unwrap_or(render.default_fit);
                    ClipInput {
                        path: clip.path.clone(),
                        coordinate: clip.resolved.coordinate.clone(),
                        duration_sec: clip.duration_sec,
                        has_audio: clip.has_audio,
                        fit,
                        credit: clip.resolved.credit.clone(),
                    }
                })
                .collect();
            let aspect_job = AspectRenderJob {
                aspect: render.aspect,
                clips,
                logo_path: self.logo_path.clone(),
                output_path: output_path.clone(),
                watermark: job.request.watermark.clone(),
                credit: job.request.credit.clone(),
                audio: job.request.audio.clone(),
                use_gpu: self.use_gpu,
            };

            match render_aspect(&aspect_job).await {
                Ok(_) => match self.publisher.publish(&output_path, render.aspect).await {
                    Ok(blob) => outputs.push(Output {
                        aspect: blob.aspect,
                        url: blob.url,
                        sha256: blob.sha256,
                        size: blob.size,
                        dim: blob.dim,
                    }),
                    Err(error) => aspect_failures.push(AspectFailure {
                        aspect: render.aspect,
                        code: "upload-failed".into(),
                        message: error.to_string(),
                    }),
                },
                Err(error) => aspect_failures.push(AspectFailure {
                    aspect: render.aspect,
                    code: "render-failed".into(),
                    message: error.to_string(),
                }),
            }
        }

        Ok(JobResult {
            outputs,
            aspect_failures,
            duration_sec,
            clips_used: prepared.len(),
            clips_dropped: dropped,
            credits,
        })
    }

    async fn download(&self, clip: &ResolvedClip, destination: &Path) -> Result<()> {
        let url = Url::parse(&clip.media_url).context("invalid media URL")?;
        let host = url.host_str().context("media URL has no host")?;
        if url.scheme() != "https" || !self.allowed_media_hosts.contains(host) {
            bail!("media-host-not-allowed");
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("download source media")?;
        match response.status() {
            StatusCode::UNAUTHORIZED => bail!("age-restricted"),
            StatusCode::FORBIDDEN => bail!("moderation-restricted"),
            StatusCode::NOT_FOUND => bail!("source-not-found"),
            status if !status.is_success() => bail!("source-http-{status}"),
            _ => {}
        }
        if response.content_length().unwrap_or(0) > MAX_SOURCE_BYTES {
            bail!("source-too-large");
        }

        let mut output = File::create(destination)
            .await
            .context("create source media file")?;
        let mut stream = response.bytes_stream();
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("stream source media")?;
            size = size.saturating_add(chunk.len() as u64);
            if size > MAX_SOURCE_BYTES {
                bail!("source-too-large");
            }
            hasher.update(&chunk);
            output
                .write_all(&chunk)
                .await
                .context("write source media")?;
        }
        output.flush().await.context("flush source media")?;
        let actual = hex::encode(hasher.finalize());
        if actual != clip.sha256 {
            bail!("source-hash-mismatch");
        }
        Ok(())
    }
}

#[async_trait]
impl JobExecutor for CompilationPipeline {
    async fn execute(&self, job: &Job) -> Result<JobResult> {
        let work_dir = self.temp_root.join(&job.id);
        fs::create_dir_all(&work_dir)
            .await
            .context("create compilation work directory")?;
        let result = self.execute_inner(job, &work_dir).await;
        if let Err(error) = fs::remove_dir_all(&work_dir).await {
            eprintln!(
                "failed to remove compilation work directory {}: {error}",
                work_dir.display()
            );
        }
        result
    }
}

struct PreparedClip {
    resolved: ResolvedClip,
    path: PathBuf,
    duration_sec: f64,
    has_audio: bool,
}

#[derive(Deserialize)]
struct ProbeOutput {
    format: ProbeFormat,
    streams: Vec<ProbeStream>,
}

#[derive(Deserialize)]
struct ProbeFormat {
    duration: String,
}

#[derive(Deserialize)]
struct ProbeStream {
    codec_type: String,
}

struct Probe {
    duration_sec: f64,
    has_audio: bool,
}

async fn probe_media(path: &Path) -> Result<Probe> {
    let output = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "format=duration:stream=codec_type",
            "-of",
            "json",
        ])
        .arg(path)
        .output()
        .await
        .context("start ffprobe")?;
    if !output.status.success() {
        bail!("ffprobe rejected source media");
    }
    let probe: ProbeOutput =
        serde_json::from_slice(&output.stdout).context("decode ffprobe output")?;
    let duration_sec = probe
        .format
        .duration
        .parse::<f64>()
        .context("parse source duration")?;
    if !duration_sec.is_finite()
        || duration_sec <= 0.0
        || !probe
            .streams
            .iter()
            .any(|stream| stream.codec_type == "video")
    {
        bail!("source has no usable video stream");
    }
    Ok(Probe {
        duration_sec,
        has_audio: probe
            .streams
            .iter()
            .any(|stream| stream.codec_type == "audio"),
    })
}

fn classify_download_error(error: &anyhow::Error) -> String {
    let message = error.to_string();
    for reason in [
        "media-host-not-allowed",
        "age-restricted",
        "moderation-restricted",
        "source-not-found",
        "source-too-large",
        "source-hash-mismatch",
    ] {
        if message.contains(reason) {
            return reason.into();
        }
    }
    "download-failed".into()
}

fn aspect_name(aspect: crate::domain::Aspect) -> &'static str {
    match aspect {
        crate::domain::Aspect::Portrait => "portrait",
        crate::domain::Aspect::Square => "square",
        crate::domain::Aspect::Landscape => "landscape",
    }
}
