// ABOUTME: Reads Blossom metadata KV entries from the Fastly KV origin API when edge reads are stale.
// ABOUTME: Read-only, and disabled unless a read token and the metadata store id are configured.
use crate::error::{BlossomError, Result};
use blossom_core::kv_origin::{interpret, key_path, OriginEntry};
use fastly::backend::{Backend, BackendCreationError};
use fastly::Request;
use std::time::Duration;

const HOST: &str = "api.fastly.com";
const BACKEND_NAME: &str = "kv-origin-api";
/// Secret holding a Fastly API token that can read the metadata KV store.
const TOKEN_SECRET: &str = "kv_origin_read_token";
/// Config key naming the metadata KV store on the API.
const STORE_ID_CONFIG: &str = "metadata_kv_store_id";

struct Settings {
    token: String,
    store_id: String,
}

fn settings() -> Option<Settings> {
    let token = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()?
        .get(TOKEN_SECRET)
        .and_then(|secret| String::from_utf8(secret.plaintext().to_vec()).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let store_id = crate::admin::get_config(STORE_ID_CONFIG)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    Some(Settings { token, store_id })
}

fn backend() -> Result<Backend> {
    match Backend::builder(BACKEND_NAME, HOST)
        .override_host(HOST)
        .enable_ssl()
        .check_certificate(HOST)
        .sni_hostname(HOST)
        .connect_timeout(Duration::from_secs(2))
        .first_byte_timeout(Duration::from_secs(3))
        .finish()
    {
        Ok(backend) => Ok(backend),
        Err(BackendCreationError::NameInUse) => Backend::from_name(BACKEND_NAME)
            .map_err(|_| BlossomError::MetadataError("KV origin backend unavailable".into())),
        Err(_) => Err(BlossomError::MetadataError("KV origin backend unavailable".into())),
    }
}

/// Whether origin reads are configured for this service.
pub(crate) fn enabled() -> bool {
    settings().is_some()
}

/// Read `key` from the KV origin. `Ok(None)` means origin reads are not configured;
/// `Ok(Some(None))` means the key does not exist at the origin.
pub(crate) fn lookup(key: &str) -> Result<Option<Option<OriginEntry>>> {
    let Some(settings) = settings() else {
        return Ok(None);
    };
    let mut response = Request::get(format!("https://{HOST}{}", key_path(&settings.store_id, key)))
        .with_header("Fastly-Key", settings.token)
        .send(backend()?)
        .map_err(|_| BlossomError::MetadataError("KV origin read failed".into()))?;
    let status = response.get_status().as_u16();
    let generation = response.get_header_str("generation").map(str::to_owned);
    let body = response.take_body_bytes();
    interpret(status, generation.as_deref(), body)
        .map(Some)
        .map_err(BlossomError::MetadataError)
}
