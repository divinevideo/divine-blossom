use divine_compiler::{
    domain::{
        Aspect, AudioSettings, CompileRequest, CreditSettings, FitMode, Job, JobStatus, NostrEvent,
        RenderRequest, Source, Watermark,
    },
    store::{FirestoreJobStore, JobStore, MemoryJobStore},
};

fn request() -> CompileRequest {
    CompileRequest {
        source: Source {
            list_event: NostrEvent {
                id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
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
                sig: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
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
    }
}

fn job(id: &str, initiated_by: &str, created_at: u64) -> Job {
    Job {
        id: id.into(),
        status: JobStatus::Queued,
        progress: 0.0,
        request: request(),
        signer_pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        initiated_by: initiated_by.into(),
        created_at,
        updated_at: created_at,
        result: None,
        error: None,
    }
}

#[tokio::test]
async fn claim_next_marks_only_oldest_queued_job_running() {
    let store = MemoryJobStore::default();
    store
        .create(&job("newer", "editor@example.com", 20))
        .await
        .unwrap();
    store
        .create(&job("older", "editor@example.com", 10))
        .await
        .unwrap();

    let claimed = store.claim_next().await.unwrap().unwrap();

    assert_eq!(claimed.id, "older");
    assert_eq!(claimed.status, JobStatus::Running);
    assert_eq!(
        store.get("newer").await.unwrap().unwrap().status,
        JobStatus::Queued
    );
    assert_eq!(
        store.get("older").await.unwrap().unwrap().status,
        JobStatus::Running
    );
}

#[tokio::test]
async fn recent_jobs_are_filtered_by_access_identity() {
    let store = MemoryJobStore::default();
    store
        .create(&job("first", "one@example.com", 10))
        .await
        .unwrap();
    store
        .create(&job("other", "two@example.com", 30))
        .await
        .unwrap();
    store
        .create(&job("latest", "one@example.com", 20))
        .await
        .unwrap();

    let jobs = store
        .recent_for_initiator("one@example.com", 10)
        .await
        .unwrap();

    assert_eq!(
        jobs.into_iter().map(|job| job.id).collect::<Vec<_>>(),
        vec!["latest", "first"]
    );
}

#[tokio::test]
async fn create_rejects_duplicate_job_ids() {
    let store = MemoryJobStore::default();
    store
        .create(&job("same", "one@example.com", 10))
        .await
        .unwrap();

    let error = store
        .create(&job("same", "one@example.com", 20))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("already exists"));
}

#[tokio::test]
async fn firestore_transaction_round_trip_when_emulator_is_available() {
    if std::env::var("FIRESTORE_EMULATOR_HOST").is_err() {
        return;
    }
    let store =
        FirestoreJobStore::new("test-project", "compilation_jobs_test").expect("emulator store");
    let id = format!("job_{}", uuid::Uuid::new_v4().simple());
    let fixture = job(&id, "firestore@example.com", 10);

    assert!(store.create_limited(&fixture, 0, 10).await.unwrap());
    assert_eq!(store.get(&id).await.unwrap().unwrap(), fixture);
    assert_eq!(store.claim_next().await.unwrap().unwrap().id, id);
}
