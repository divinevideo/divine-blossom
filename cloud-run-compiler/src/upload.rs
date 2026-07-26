// ABOUTME: Publishes rendered compilations through cloud-run-upload resumable sessions
// ABOUTME: Signs Blossom authorization and always suppresses ordinary video derivatives

use crate::domain::Aspect;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableUploadInitRequest {
    pub sha256: String,
    pub size: u64,
    pub content_type: String,
    pub file_name: String,
    pub generate_derivatives: bool,
}

impl ResumableUploadInitRequest {
    pub fn compilation(sha256: &str, size: u64, file_name: &str) -> Self {
        Self {
            sha256: sha256.into(),
            size,
            content_type: "video/mp4".into(),
            file_name: file_name.into(),
            generate_derivatives: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitResponse {
    upload_id: String,
    upload_url: String,
    chunk_size: u64,
    next_offset: u64,
    #[serde(default)]
    required_headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompleteResponse {
    sha256: String,
    size: u64,
    dim: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedBlob {
    pub aspect: Aspect,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub dim: String,
}

#[derive(Clone)]
pub struct ResumablePublisher {
    client: Client,
    upload_origin: String,
    media_origin: String,
    signing_keys: Keys,
}

impl ResumablePublisher {
    pub fn new(upload_origin: &str, media_origin: &str, signing_keys: Keys) -> Result<Self> {
        if upload_origin.ends_with('/') || media_origin.ends_with('/') {
            bail!("publisher origins must not have trailing slashes");
        }
        Ok(Self {
            client: Client::new(),
            upload_origin: upload_origin.into(),
            media_origin: media_origin.into(),
            signing_keys,
        })
    }

    pub async fn publish(&self, path: &Path, aspect: Aspect) -> Result<PublishedBlob> {
        let (sha256, size) = hash_file(path).await?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("render output has no UTF-8 filename")?;
        let authorization = blossom_authorization(&self.signing_keys, &sha256, unix_timestamp()?)?;
        let init = self
            .client
            .post(format!("{}/upload/init", self.upload_origin))
            .header(header::AUTHORIZATION, &authorization)
            .json(&ResumableUploadInitRequest::compilation(
                &sha256, size, file_name,
            ))
            .send()
            .await
            .context("initialize resumable compilation upload")?
            .error_for_status()
            .context("upload service rejected compilation init")?
            .json::<InitResponse>()
            .await
            .context("decode upload init response")?;

        upload_chunks(&self.client, path, size, &init).await?;

        let complete = self
            .client
            .post(format!(
                "{}/upload/{}/complete",
                self.upload_origin, init.upload_id
            ))
            .header(header::AUTHORIZATION, authorization)
            .send()
            .await
            .context("complete resumable compilation upload")?
            .error_for_status()
            .context("upload service rejected compilation completion")?
            .json::<CompleteResponse>()
            .await
            .context("decode upload completion response")?;

        if complete.sha256 != sha256 || complete.size != size {
            bail!("upload completion metadata does not match rendered file");
        }
        let (width, height) = aspect.dimensions();
        Ok(PublishedBlob {
            aspect,
            url: format!("{}/{}", self.media_origin, complete.sha256),
            sha256: complete.sha256,
            size: complete.size,
            dim: complete.dim.unwrap_or_else(|| format!("{width}x{height}")),
        })
    }
}

async fn upload_chunks(client: &Client, path: &Path, size: u64, init: &InitResponse) -> Result<()> {
    if init.chunk_size == 0 {
        bail!("upload service returned a zero chunk size");
    }
    let mut file = File::open(path).await.context("open rendered output")?;
    let mut offset = init.next_offset;
    let mut retries = 0_u8;

    while offset < size {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .context("seek rendered output")?;
        let length = (size - offset).min(init.chunk_size) as usize;
        let mut chunk = vec![0_u8; length];
        file.read_exact(&mut chunk)
            .await
            .context("read rendered output chunk")?;
        let end = offset + length as u64 - 1;

        let mut request = client.put(&init.upload_url);
        for (name, value) in &init.required_headers {
            request = request.header(name, value);
        }
        let response = request
            .header(
                header::CONTENT_RANGE,
                format!("bytes {offset}-{end}/{size}"),
            )
            .body(chunk)
            .send()
            .await;

        match response {
            Ok(response) if response.status().is_success() => {
                offset = response
                    .headers()
                    .get("Upload-Offset")
                    .context("upload chunk response omitted Upload-Offset")?
                    .to_str()
                    .context("Upload-Offset is not text")?
                    .parse()
                    .context("Upload-Offset is not an integer")?;
                retries = 0;
            }
            _ if retries < 3 => {
                retries += 1;
                offset = query_offset(client, init).await?;
            }
            Ok(response) => bail!("upload chunk failed with {}", response.status()),
            Err(error) => return Err(error).context("upload chunk failed after retries"),
        }
    }
    Ok(())
}

async fn query_offset(client: &Client, init: &InitResponse) -> Result<u64> {
    let mut request = client.head(&init.upload_url);
    for (name, value) in &init.required_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("query resumable upload offset")?
        .error_for_status()
        .context("upload service rejected offset query")?;
    response
        .headers()
        .get("Upload-Offset")
        .context("offset response omitted Upload-Offset")?
        .to_str()
        .context("Upload-Offset is not text")?
        .parse()
        .context("Upload-Offset is not an integer")
}

pub fn chunk_ranges(size: u64, chunk_size: u64) -> Vec<(u64, u64)> {
    if size == 0 || chunk_size == 0 {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < size {
        let end = (start + chunk_size - 1).min(size - 1);
        ranges.push((start, end));
        start = end + 1;
    }
    ranges
}

pub fn blossom_authorization(keys: &Keys, sha256: &str, now: u64) -> Result<String> {
    let expiration = now.saturating_add(300).to_string();
    let tags = vec![
        Tag::parse(&["t", "upload"]).context("build upload action tag")?,
        Tag::parse(&["expiration", expiration.as_str()]).context("build expiration tag")?,
        Tag::parse(&["x", sha256]).context("build upload hash tag")?,
    ];
    let event = EventBuilder::new(Kind::Custom(24_242), "", tags)
        .custom_created_at(Timestamp::from(now))
        .to_event(keys)
        .context("sign Blossom upload authorization")?;
    Ok(format!(
        "Nostr {}",
        STANDARD.encode(event.as_json().as_bytes())
    ))
}

async fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path).await.context("open output for hashing")?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await.context("hash output file")?;
        if read == 0 {
            break;
        }
        size += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), size))
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}
