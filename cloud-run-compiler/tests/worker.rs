use anyhow::{anyhow, Result};
use async_trait::async_trait;
use divine_compiler::{
    domain::{
        Aspect, AspectFailure, AudioSettings, CompileRequest, CreditSettings, FitMode, Job,
        JobResult, JobStatus, NostrEvent, Output, RenderRequest, Source, Watermark,
    },
    store::{JobStore, MemoryJobStore},
    worker::{run_next_job, run_worker, JobExecutor},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;

fn queued_job() -> Job {
    Job {
        id: "job-1".into(),
        status: JobStatus::Queued,
        progress: 0.0,
        request: CompileRequest {
            source: Source {
                list_event: NostrEvent {
                    id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    pubkey:
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into(),
                    created_at: 1,
                    kind: 30_005,
                    tags: vec![
                        vec!["d".into(), "staff-picks".into()],
                        vec![
                            "a".into(),
                            "34236:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:first"
                                .into(),
                        ],
                    ],
                    content: String::new(),
                    sig: "d".repeat(128),
                },
            },
            renders: vec![RenderRequest {
                aspect: Aspect::Portrait,
                default_fit: FitMode::BlurPad,
                clip_overrides: vec![],
            }],
            watermark: Watermark::default(),
            credit: CreditSettings::default(),
            audio: AudioSettings::default(),
            max_duration_sec: 600,
        },
        signer_pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .into(),
        initiated_by: "editor@example.com".into(),
        created_at: 1,
        updated_at: 1,
        result: None,
        error: None,
    }
}

struct PartialExecutor;

#[async_trait]
impl JobExecutor for PartialExecutor {
    async fn execute(&self, _job: &Job) -> Result<JobResult> {
        Ok(JobResult {
            outputs: vec![Output {
                aspect: Aspect::Portrait,
                url: "https://media.divine.video/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
                size: 100,
                dim: "1080x1920".into(),
            }],
            aspect_failures: vec![AspectFailure {
                aspect: Aspect::Square,
                code: "render-failed".into(),
                message: "square failed".into(),
            }],
            ..JobResult::default()
        })
    }
}

struct FailingExecutor;

#[async_trait]
impl JobExecutor for FailingExecutor {
    async fn execute(&self, _job: &Job) -> Result<JobResult> {
        Err(anyhow!("no usable source clips"))
    }
}

#[tokio::test]
async fn aspect_failure_does_not_discard_success() {
    let store = Arc::new(MemoryJobStore::default());
    store.create(&queued_job()).await.unwrap();

    assert!(run_next_job(store.clone(), &PartialExecutor).await.unwrap());
    let job = store.get("job-1").await.unwrap().unwrap();

    assert_eq!(job.status, JobStatus::Done);
    assert_eq!(job.progress, 1.0);
    assert_eq!(job.result.unwrap().outputs.len(), 1);
}

#[tokio::test]
async fn pipeline_error_marks_claimed_job_failed() {
    let store = Arc::new(MemoryJobStore::default());
    store.create(&queued_job()).await.unwrap();

    assert!(run_next_job(store.clone(), &FailingExecutor).await.unwrap());
    let job = store.get("job-1").await.unwrap().unwrap();

    assert_eq!(job.status, JobStatus::Failed);
    assert_eq!(job.error.unwrap().code, "compilation-failed");
}

#[tokio::test]
async fn worker_polls_for_jobs_created_without_a_local_notification() {
    let store = Arc::new(MemoryJobStore::default());
    let worker = tokio::spawn(run_worker(
        store.clone(),
        Arc::new(PartialExecutor),
        Arc::new(Notify::new()),
        Duration::from_millis(10),
    ));

    tokio::time::sleep(Duration::from_millis(20)).await;
    store.create(&queued_job()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if store
                .get("job-1")
                .await
                .unwrap()
                .is_some_and(|job| job.status == JobStatus::Done)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker should discover an unnotified queued job");

    worker.abort();
}
