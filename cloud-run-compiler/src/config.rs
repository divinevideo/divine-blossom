// ABOUTME: Environment-derived compiler configuration
// ABOUTME: Keeps public auth audiences and infrastructure identifiers out of code

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerConfig {
    pub port: u16,
    pub public_origin: String,
    pub firestore_project: String,
    pub firestore_collection: String,
    pub source_relays: Vec<String>,
    pub source_timeout_seconds: u64,
    pub upload_origin: String,
    pub media_origin: String,
    pub allowed_media_hosts: Vec<String>,
    pub temp_root: PathBuf,
    pub logo_path: PathBuf,
    pub credit_font_path: PathBuf,
    pub max_jobs_per_hour: usize,
    pub max_concurrent_jobs: usize,
    pub use_gpu: bool,
}

impl CompilerConfig {
    pub fn from_env() -> Result<Self> {
        let public_origin = std::env::var("PUBLIC_ORIGIN")
            .unwrap_or_else(|_| "https://compiler.divine.video".into());
        if !public_origin.starts_with("https://") || public_origin.ends_with('/') {
            bail!("PUBLIC_ORIGIN must be an https origin without a trailing slash");
        }

        let config = Self {
            port: parse_env("PORT", 8080)?,
            public_origin,
            firestore_project: std::env::var("FIRESTORE_PROJECT")
                .context("FIRESTORE_PROJECT is required")?,
            firestore_collection: std::env::var("FIRESTORE_COLLECTION")
                .unwrap_or_else(|_| "compilation_jobs".into()),
            source_relays: csv_env("SOURCE_RELAYS", "wss://relay.divine.video"),
            source_timeout_seconds: parse_env("SOURCE_TIMEOUT_SECONDS", 10)?,
            upload_origin: std::env::var("UPLOAD_SERVICE_URL")
                .unwrap_or_else(|_| "https://upload.divine.video".into()),
            media_origin: std::env::var("MEDIA_ORIGIN")
                .unwrap_or_else(|_| "https://media.divine.video".into()),
            allowed_media_hosts: csv_env("ALLOWED_MEDIA_HOSTS", "media.divine.video"),
            temp_root: PathBuf::from(
                std::env::var("COMPILER_TEMP_ROOT")
                    .unwrap_or_else(|_| "/tmp/divine-compiler".into()),
            ),
            logo_path: PathBuf::from(
                std::env::var("DIVINE_LOGO_PATH")
                    .unwrap_or_else(|_| "/opt/divine/divine-logo.png".into()),
            ),
            credit_font_path: PathBuf::from(
                std::env::var("CREDIT_FONT_PATH")
                    .unwrap_or_else(|_| crate::render::DEFAULT_FONT_PATH.into()),
            ),
            max_jobs_per_hour: parse_env("RATE_LIMIT_PER_HOUR", 20)?,
            max_concurrent_jobs: parse_env("MAX_CONCURRENT_JOBS", 4)?,
            use_gpu: parse_bool_env("USE_GPU", true)?,
        };
        for (name, origin) in [
            ("UPLOAD_SERVICE_URL", &config.upload_origin),
            ("MEDIA_ORIGIN", &config.media_origin),
        ] {
            if !origin.starts_with("https://") || origin.ends_with('/') {
                bail!("{name} must be an https origin without a trailing slash");
            }
        }
        if config.source_relays.is_empty()
            || config.allowed_media_hosts.is_empty()
            || config.max_jobs_per_hour == 0
            || config.max_concurrent_jobs == 0
        {
            bail!("relay, media host, rate limit, and concurrency settings must be non-zero");
        }
        Ok(config)
    }
}

fn csv_env(name: &str, default: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_else(|_| default.into())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(String::from)
        .collect()
}

fn parse_env<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|error| anyhow::anyhow!("{name} is invalid: {error}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Ok(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        Ok(_) => bail!("{name} must be true, false, 1, or 0"),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
}
