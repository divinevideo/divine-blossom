// ABOUTME: Process entry point for the Divine compilation service
// ABOUTME: Connects Firestore, Nostr relays, render workers, and the authenticated API

use anyhow::{Context, Result};
use divine_compiler::{
    config::CompilerConfig,
    http::{router, ApiState},
    pipeline::CompilationPipeline,
    render::verify_render_toolchain,
    source::RelaySourceRepository,
    store::{FirestoreJobStore, JobStore},
    upload::ResumablePublisher,
    worker::{run_worker, JobExecutor},
};
use nostr::Keys;
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "divine_compiler=info".into()),
        )
        .init();

    let config = CompilerConfig::from_env()?;
    verify_render_toolchain(&config.credit_font_path)
        .await
        .context("the render toolchain cannot burn creator credits")?;
    let signing_secret =
        std::env::var("COMPILER_OUTPUT_NSEC").context("COMPILER_OUTPUT_NSEC is required")?;
    let signing_keys =
        Keys::parse(&signing_secret).context("COMPILER_OUTPUT_NSEC is not a valid Nostr key")?;

    let store: Arc<dyn JobStore> = Arc::new(FirestoreJobStore::new(
        &config.firestore_project,
        &config.firestore_collection,
    )?);
    let repository = Arc::new(
        RelaySourceRepository::connect(
            &config.source_relays,
            Duration::from_secs(config.source_timeout_seconds),
        )
        .await?,
    );
    let publisher =
        ResumablePublisher::new(&config.upload_origin, &config.media_origin, signing_keys)?;
    let pipeline: Arc<dyn JobExecutor> = Arc::new(CompilationPipeline::new(
        repository,
        publisher,
        config.temp_root.clone(),
        config.logo_path.clone(),
        config.credit_font_path.clone(),
        config.allowed_media_hosts.clone(),
        config.use_gpu,
    )?);

    let state = ApiState::new(
        store.clone(),
        config.public_origin.clone(),
        config.max_jobs_per_hour,
    );
    for worker_index in 0..config.max_concurrent_jobs {
        let store = store.clone();
        let pipeline = pipeline.clone();
        let notify = state.worker_notify.clone();
        tokio::spawn(async move {
            if let Err(error) = run_worker(store, pipeline, notify, Duration::from_secs(15)).await {
                tracing::error!(worker_index, %error, "compiler worker stopped");
            }
        });
    }

    let address = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("bind compiler server to {address}"))?;
    tracing::info!(%address, "compiler service listening");
    axum::serve(listener, router(state))
        .await
        .context("serve compiler API")
}
