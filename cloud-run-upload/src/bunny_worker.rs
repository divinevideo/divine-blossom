//! Private byte verification for the bounded playback pilot. Compute owns the
//! policy decision and keeps its parent fence throughout this synchronous job.
use axum::{
    body::to_bytes,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use blossom_core::{
    bunny_hls::normalize,
    bunny_pilot::{Asset, DELIVERY_PREFIX},
    bunny_worker::{
        complete, version_valid, Inventory, Job, Operation, Outcome, Pin, Publication, Reply,
        Scope, Verified,
    },
    storage_origin::{MediaReadPolicy, ObjectRef, StorageProvider},
};
use futures::StreamExt;
use reqwest::{Client, Method};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, sync::LazyLock, time::Duration};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::sync::Semaphore;

static SLOTS: Semaphore = Semaphore::const_new(1);
static HTTP: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .user_agent("divine-bunny-worker/1")
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("worker HTTPS client")
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    id: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Readers {
    b2: Key,
    gcs: Option<Key>,
}

struct Worker {
    scope: Scope,
    readers: Readers,
    writer: Key,
    #[cfg(test)]
    test_origin: Option<String>,
}

struct Object {
    identity: ObjectRef,
    bytes: Vec<u8>,
    digest: String,
}

type Work<T> = Result<T, Outcome>;
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn bounded_bytes(response: reqwest::Response, limit: usize) -> Work<Vec<u8>> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(Outcome::SourceChanged);
    }
    let mut bytes = Vec::with_capacity(response.content_length().unwrap_or(0) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Outcome::Unavailable)?;
        if chunk.len() > limit - bytes.len() {
            return Err(Outcome::SourceChanged);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

impl Worker {
    fn load() -> Option<Self> {
        let primary = |name| {
            MediaReadPolicy::parse(Some(&env::var(name).ok()?), None)
                .ok()
                .map(|p| p.primary)
        };
        let original = primary("BUNNY_ORIGINAL_PRIMARY")?;
        let derivative = primary("BUNNY_DERIVED_PRIMARY")?;
        let bucket = |name| {
            env::var(name).ok().filter(|b| {
                !b.is_empty()
                    && b.len() <= 222
                    && b.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
            })
        };
        let gcs_bucket = if [original, derivative].contains(&StorageProvider::Gcs) {
            Some(bucket("GCS_BUCKET")?)
        } else {
            None
        };
        let b2_region = env::var("B2_REGION").ok()?;
        StorageProvider::b2_host(&b2_region).ok()?;
        Some(Self {
            scope: Scope {
                original,
                derivative,
                gcs_bucket,
                b2_bucket: bucket("B2_MEDIA_BUCKET")?,
                b2_bucket_id: bucket("B2_BUCKET_ID")?,
                b2_region,
            },
            readers: serde_json::from_str(&env::var("BUNNY_PILOT_READERS_V1").ok()?).ok()?,
            writer: serde_json::from_str(&env::var("BUNNY_PILOT_WRITER_V1").ok()?).ok()?,
            #[cfg(test)]
            test_origin: env::var("BUNNY_TEST_ORIGIN").ok(),
        })
    }

    fn url(&self, host: &str, path: &str) -> String {
        #[cfg(test)]
        if let Some(origin) = &self.test_origin {
            return format!("{origin}{path}");
        }
        format!("https://{host}{path}")
    }

    fn signed(
        &self,
        provider: StorageProvider,
        method: Method,
        bucket: &str,
        object: &str,
        key: &Key,
        digest: &str,
    ) -> Work<reqwest::RequestBuilder> {
        let (host, region) = match provider {
            StorageProvider::Gcs => ("storage.googleapis.com".to_owned(), "auto"),
            StorageProvider::B2 => (
                StorageProvider::b2_host(&self.scope.b2_region)
                    .map_err(|_| Outcome::Unavailable)?,
                self.scope.b2_region.as_str(),
            ),
        };
        let path = format!("/{bucket}/{object}");
        let now = OffsetDateTime::now_utc();
        let date = format!("{:04}{:02}{:02}", now.year(), now.month() as u8, now.day());
        let stamp = format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );
        let names = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!("{method}\n{path}\n\nhost:{host}\nx-amz-content-sha256:{digest}\nx-amz-date:{stamp}\n\n{names}\n{digest}");
        let auth = blossom_core::s3_signing::authorization(
            &key.id, &key.key, region, &date, &stamp, &canonical, names,
        )
        .map_err(|_| Outcome::Unavailable)?;
        Ok(HTTP
            .request(method, self.url(&host, &path))
            .header("Host", host)
            .header("Authorization", auth)
            .header("x-amz-content-sha256", digest)
            .header("x-amz-date", stamp))
    }

    async fn get(&self, asset: &Asset<'_>, delivery: bool) -> Work<Option<Object>> {
        let (provider, bucket, object) = if delivery {
            (
                StorageProvider::B2,
                self.scope.b2_bucket.as_str(),
                asset.delivery_key(),
            )
        } else {
            let (provider, bucket) = self.scope.source(asset);
            (provider, bucket, asset.source_key())
        };
        let reader = match provider {
            StorageProvider::B2 => &self.readers.b2,
            StorageProvider::Gcs => self.readers.gcs.as_ref().ok_or(Outcome::Unavailable)?,
        };
        let res = self
            .signed(provider, Method::GET, bucket, &object, reader, &sha(&[]))?
            .header("Cache-Control", "no-cache")
            .send()
            .await
            .map_err(|_| Outcome::Unavailable)?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if res.status() != reqwest::StatusCode::OK {
            return Err(Outcome::Unavailable);
        }
        let header = |name| res.headers().get(name).and_then(|v| v.to_str().ok());
        let size = header("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|s| (1..=asset.max_size()).contains(s))
            .ok_or(Outcome::SourceChanged)?;
        let version = header(match provider {
            StorageProvider::B2 => "x-amz-version-id",
            StorageProvider::Gcs => "x-goog-generation",
        })
        .filter(|v| version_valid(provider, v))
        .ok_or(Outcome::SourceChanged)?
        .to_owned();
        if !header("content-type")
            .and_then(|t| t.split(';').next())
            .is_some_and(|t| t.eq_ignore_ascii_case(asset.mime()))
            || res.headers().contains_key("content-range")
            || header("content-encoding").is_some_and(|e| e != "identity")
        {
            return Err(Outcome::SourceChanged);
        }
        let bytes = bounded_bytes(res, size).await?;
        if bytes.len() != size {
            return Err(Outcome::SourceChanged);
        }
        Ok(Some(Object {
            identity: ObjectRef {
                provider,
                bucket: bucket.to_owned(),
                key: object,
                version: Some(version),
            },
            digest: sha(&bytes),
            bytes,
        }))
    }

    async fn authorize_writer(&self) -> Work<()> {
        let host = "api.backblazeb2.com";
        let response = HTTP
            .get(self.url(host, "/b2api/v4/b2_authorize_account"))
            .basic_auth(&self.writer.id, Some(&self.writer.key))
            .send()
            .await
            .map_err(|_| Outcome::Unavailable)?;
        if !response.status().is_success() {
            return Err(Outcome::Unavailable);
        }
        let bytes = bounded_bytes(response, 64 * 1024).await?;
        let auth: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Outcome::Unavailable)?;
        let allowed = &auth["apiInfo"]["storageApi"]["allowed"];
        if allowed["capabilities"] != serde_json::json!(["writeFiles"])
            || allowed["namePrefix"].as_str() != Some(DELIVERY_PREFIX)
            || allowed["buckets"].as_array().map(Vec::len) != Some(1)
            || allowed["buckets"][0]["id"].as_str() != Some(&self.scope.b2_bucket_id)
            || allowed["buckets"][0]["name"].as_str() != Some(&self.scope.b2_bucket)
        {
            return Err(Outcome::Rejected);
        }
        Ok(())
    }

    async fn publish(&self, p: &Publication, original_size: Option<u64>) -> Work<Outcome> {
        let asset = p.asset().ok_or(Outcome::Rejected)?;
        let source = self
            .get(&asset, false)
            .await?
            .ok_or(Outcome::SourceMissing)?;
        if source.digest != p.sha256
            || (asset.is_original() && original_size != Some(source.bytes.len() as u64))
        {
            return Err(Outcome::SourceChanged);
        }
        let mut child_size = 0;
        for d in &p.dependencies {
            let child = Asset::parse(&d.path).ok_or(Outcome::Rejected)?;
            let copy = self
                .get(&child, true)
                .await?
                .filter(|obj| obj.digest == d.sha256)
                .ok_or(Outcome::SourceChanged)?;
            child_size = copy.bytes.len();
        }
        let bytes = if asset.is_playlist() {
            normalize(&asset, &source.bytes, child_size).ok_or(Outcome::SourceChanged)?
        } else {
            source.bytes
        };
        let digest = sha(&bytes);
        let existing = self.get(&asset, true).await?;
        let already = existing.is_some();
        let delivery = if let Some(existing) = existing {
            if existing.digest != digest {
                return Err(Outcome::DeliveryConflict);
            }
            existing
        } else {
            self.authorize_writer().await?;
            let res = self
                .signed(
                    StorageProvider::B2,
                    Method::PUT,
                    &self.scope.b2_bucket,
                    &asset.delivery_key(),
                    &self.writer,
                    &digest,
                )?
                .header("Content-Type", asset.mime())
                .header("Cache-Control", "private, no-store")
                .body(bytes)
                .send()
                .await
                .map_err(|_| Outcome::Uncertain)?;
            if matches!(res.status().as_u16(), 400 | 401 | 403) {
                return Err(Outcome::Rejected);
            }
            if !res.status().is_success() {
                return Err(Outcome::Uncertain);
            }
            let written_version = res
                .headers()
                .get("x-amz-version-id")
                .and_then(|h| h.to_str().ok())
                .filter(|v| version_valid(StorageProvider::B2, v))
                .ok_or(Outcome::ReadbackFailed)?;
            self.get(&asset, true)
                .await
                .map_err(|_| Outcome::ReadbackFailed)?
                .filter(|o| {
                    o.digest == digest && o.identity.version.as_deref() == Some(written_version)
                })
                .ok_or(Outcome::ReadbackFailed)?
        };
        let verified = Verified {
            asset: Pin {
                path: p.path.clone(),
                source_sha256: source.digest,
                delivery_sha256: digest,
            },
            source: source.identity,
            destination_version: delivery.identity.version.ok_or(Outcome::ReadbackFailed)?,
            delivery_size: delivery.bytes.len(),
        };
        Ok(if already {
            Outcome::AlreadyPublished { verified }
        } else {
            Outcome::Published { verified }
        })
    }

    async fn finalize(&self, mut inventory: Inventory) -> Work<Outcome> {
        if inventory.version != 1 || !complete(&inventory.parent, inventory.assets.iter()) {
            return Err(Outcome::Rejected);
        }
        inventory.assets.sort_by_key(|p| p.path.ends_with(".m3u8"));
        let mut sizes = BTreeMap::new();
        let mut verified = Vec::new();
        for pin in inventory.assets {
            let asset = Asset::parse(&pin.path).ok_or(Outcome::Rejected)?;
            let source = self
                .get(&asset, false)
                .await?
                .ok_or(Outcome::SourceChanged)?;
            let copy = self
                .get(&asset, true)
                .await?
                .ok_or(Outcome::SourceChanged)?;
            if source.digest != pin.source_sha256 || copy.digest != pin.delivery_sha256 {
                return Err(Outcome::SourceChanged);
            }
            if asset.is_playlist() {
                let size = match asset.child_names() {
                    [child] => *sizes
                        .get(&format!("/{}/hls/{child}", asset.hash()))
                        .ok_or(Outcome::SourceChanged)?,
                    _ => 0,
                };
                if normalize(&asset, &source.bytes, size).as_deref() != Some(copy.bytes.as_slice())
                {
                    return Err(Outcome::SourceChanged);
                }
            }
            sizes.insert(pin.path.clone(), copy.bytes.len());
            verified.push(Verified {
                asset: pin,
                source: source.identity,
                destination_version: copy.identity.version.ok_or(Outcome::SourceChanged)?,
                delivery_size: copy.bytes.len(),
            });
        }
        Ok(Outcome::Verified { assets: verified })
    }
}

pub(crate) async fn handle(req: Request) -> Response {
    let token = env::var("BUNNY_PILOT_WORKER_TOKEN")
        .ok()
        .filter(|t| t.len() >= 32);
    let provided = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    if !provided
        .zip(token.as_deref())
        .is_some_and(|(a, b)| bool::from(a.as_bytes().ct_eq(b.as_bytes())))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(body) = to_bytes(req.into_body(), 16 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(job) = serde_json::from_slice::<Job>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(worker) = Worker::load() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if worker.scope != job.scope {
        return Json(Reply {
            scope: job.scope,
            result: Outcome::Rejected,
        })
        .into_response();
    }
    let Ok(_slot) = SLOTS.try_acquire() else {
        return Json(Reply {
            scope: job.scope,
            result: Outcome::Unavailable,
        })
        .into_response();
    };
    let deadline = Duration::from_secs(45);
    let result = match job.operation {
        Operation::Publish {
            publication,
            original_size,
        } => tokio::time::timeout(deadline, worker.publish(&publication, original_size))
            .await
            .unwrap_or(Err(Outcome::Uncertain)),
        Operation::Finalize { inventory } => {
            tokio::time::timeout(deadline, worker.finalize(inventory))
                .await
                .unwrap_or(Err(Outcome::Unavailable))
        }
    }
    .unwrap_or_else(|outcome| outcome);
    Json(Reply {
        scope: worker.scope,
        result,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn public_requests_cannot_dispatch_worker_io() {
        let req = Request::post("/internal/bunny-pilot/v1")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        assert_eq!(handle(req).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "local service for the Viceroy integration fixture"]
    async fn serve_fixture() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        std::fs::write(
            env::var("BUNNY_TEST_PORT_FILE").unwrap(),
            listener.local_addr().unwrap().port().to_string(),
        )
        .unwrap();
        let app =
            axum::Router::new().route("/internal/bunny-pilot/v1", axum::routing::post(handle));
        axum::serve(listener, app).await.unwrap();
    }
}
