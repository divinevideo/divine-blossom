// ABOUTME: Environment-derived compiler configuration
// ABOUTME: Keeps public auth audiences and infrastructure identifiers out of code

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerConfig {
    pub public_origin: String,
    pub firestore_project: String,
    pub firestore_collection: String,
}

impl CompilerConfig {
    pub fn from_env() -> Result<Self> {
        let public_origin = std::env::var("PUBLIC_ORIGIN")
            .unwrap_or_else(|_| "https://compiler.divine.video".into());
        if !public_origin.starts_with("https://") || public_origin.ends_with('/') {
            bail!("PUBLIC_ORIGIN must be an https origin without a trailing slash");
        }

        Ok(Self {
            public_origin,
            firestore_project: std::env::var("FIRESTORE_PROJECT")
                .context("FIRESTORE_PROJECT is required")?,
            firestore_collection: std::env::var("FIRESTORE_COLLECTION")
                .unwrap_or_else(|_| "compilation_jobs".into()),
        })
    }
}
