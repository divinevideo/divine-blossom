// ABOUTME: Claims queued compilation jobs and records terminal pipeline outcomes
// ABOUTME: Preserves successful aspects when another requested render fails

use crate::{
    domain::{Job, JobError, JobResult, JobStatus},
    store::{JobStore, LEASE_SECONDS},
};
use anyhow::Result;
use async_trait::async_trait;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;

#[async_trait]
pub trait JobExecutor: Send + Sync {
    async fn execute(&self, job: &Job) -> Result<JobResult>;
}

/// Heartbeat interval. Well inside the lease, so one slow or failed write does
/// not hand a live job to another instance.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(LEASE_SECONDS / 5);

pub async fn run_next_job(store: Arc<dyn JobStore>, executor: &dyn JobExecutor) -> Result<bool> {
    let Some(mut job) = store.claim_next().await? else {
        return Ok(false);
    };

    // Hold the claim for as long as this instance is actually rendering. If the
    // instance disappears, the heartbeat stops and the lease expires, so
    // claim_next requeues the job instead of leaving it running forever.
    let heartbeat = tokio::spawn({
        let store = store.clone();
        let id = job.id.clone();
        async move {
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;
                if let Err(error) = store.renew_lease(&id).await {
                    tracing::warn!(%error, job_id = %id, "could not renew compilation job lease");
                }
            }
        }
    });

    let outcome = executor.execute(&job).await;
    heartbeat.abort();

    match outcome {
        Ok(result) => {
            job.status = result.terminal_status();
            job.progress = 1.0;
            if job.status == JobStatus::Failed {
                job.error = Some(JobError {
                    code: "all-aspects-failed".into(),
                    message: "no requested aspect produced an output".into(),
                });
            }
            job.result = Some(result);
        }
        Err(error) => {
            job.status = JobStatus::Failed;
            job.progress = 1.0;
            job.error = Some(JobError {
                code: "compilation-failed".into(),
                message: error.to_string(),
            });
        }
    }
    job.updated_at = unix_timestamp();
    job.lease_expires_at = None;
    store.save(&job).await?;
    Ok(true)
}

pub async fn run_worker(
    store: Arc<dyn JobStore>,
    executor: Arc<dyn JobExecutor>,
    notify: Arc<Notify>,
    poll_interval: Duration,
) -> Result<()> {
    loop {
        loop {
            match run_next_job(store.clone(), executor.as_ref()).await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(error) => {
                    tracing::warn!(%error, "compiler worker could not read or save the queue");
                    break;
                }
            }
        }
        tokio::select! {
            () = notify.notified() => {}
            () = tokio::time::sleep(poll_interval) => {}
        }
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
