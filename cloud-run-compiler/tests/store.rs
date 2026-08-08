use divine_compiler::{
    domain::{
        Aspect, AudioSettings, CompileRequest, CreditSettings, FitMode, Job, JobStatus, NostrEvent,
        RenderRequest, Source, Watermark,
    },
    store::{unix_timestamp, FirestoreJobStore, JobStore, MemoryJobStore, LEASE_SECONDS},
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
        lease_expires_at: None,
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
async fn claiming_a_job_takes_a_lease() {
    let store = MemoryJobStore::default();
    store.create(&job("leased", "one@example.com", 10)).await.unwrap();

    let claimed = store.claim_next().await.unwrap().unwrap();

    assert_eq!(claimed.status, JobStatus::Running);
    assert!(claimed.lease_expires_at.unwrap() >= unix_timestamp() + LEASE_SECONDS - 5);
    // A live claim is not up for grabs.
    assert!(store.claim_next().await.unwrap().is_none());
}

#[tokio::test]
async fn a_running_job_with_an_expired_lease_is_reclaimed() {
    let store = MemoryJobStore::default();
    let mut stranded = job("stranded", "one@example.com", 10);
    stranded.status = JobStatus::Running;
    stranded.lease_expires_at = Some(unix_timestamp() - 1);
    store.create(&stranded).await.unwrap();

    let reclaimed = store.claim_next().await.unwrap().unwrap();

    assert_eq!(reclaimed.id, "stranded");
    assert!(reclaimed.lease_expires_at.unwrap() > unix_timestamp());
}

#[tokio::test]
async fn queued_jobs_are_claimed_before_expired_leases() {
    let store = MemoryJobStore::default();
    let mut stranded = job("stranded", "one@example.com", 1);
    stranded.status = JobStatus::Running;
    stranded.lease_expires_at = Some(unix_timestamp() - 1);
    store.create(&stranded).await.unwrap();
    store.create(&job("queued", "one@example.com", 20)).await.unwrap();

    assert_eq!(store.claim_next().await.unwrap().unwrap().id, "queued");
    assert_eq!(store.claim_next().await.unwrap().unwrap().id, "stranded");
}

#[tokio::test]
async fn renewing_a_lease_keeps_a_slow_render_claimed() {
    let store = MemoryJobStore::default();
    let mut expiring = job("slow", "one@example.com", 10);
    expiring.status = JobStatus::Running;
    expiring.lease_expires_at = Some(unix_timestamp() - 1);
    store.create(&expiring).await.unwrap();

    store.renew_lease("slow").await.unwrap();

    assert!(store.claim_next().await.unwrap().is_none());
}

/// Runs against the Firestore emulator in CI. Explicitly ignored rather than
/// silently skipped, so an absent emulator shows as an unrun test instead of a
/// green one that never touched the persistence boundary.
#[tokio::test]
#[ignore = "requires FIRESTORE_EMULATOR_HOST"]
async fn firestore_persists_claims_and_reclaims_expired_leases() {
    std::env::var("FIRESTORE_EMULATOR_HOST")
        .expect("set FIRESTORE_EMULATOR_HOST to run the Firestore persistence test");
    let collection = format!("compilation_jobs_test_{}", uuid::Uuid::new_v4().simple());
    let store = FirestoreJobStore::new("test-project", &collection).expect("emulator store");
    let id = format!("job_{}", uuid::Uuid::new_v4().simple());
    let fixture = job(&id, "firestore@example.com", 10);

    // Rate-limit transaction.
    assert!(store.create_limited(&fixture, 0, 10).await.unwrap());
    assert!(!store
        .create_limited(
            &job(&format!("job_{}", uuid::Uuid::new_v4().simple()), "firestore@example.com", 20),
            0,
            1
        )
        .await
        .unwrap());
    assert_eq!(store.get(&id).await.unwrap().unwrap(), fixture);

    // Claim CAS takes a lease, and a live lease is not reclaimable.
    let claimed = store.claim_next().await.unwrap().unwrap();
    assert_eq!(claimed.id, id);
    assert_eq!(claimed.status, JobStatus::Running);
    assert!(claimed.lease_expires_at.unwrap() > unix_timestamp());
    assert!(store.claim_next().await.unwrap().is_none());

    // An expired lease is reclaimed rather than left running forever.
    let mut stranded = claimed.clone();
    stranded.lease_expires_at = Some(unix_timestamp() - 1);
    store.save(&stranded).await.unwrap();
    let reclaimed = store.claim_next().await.unwrap().unwrap();
    assert_eq!(reclaimed.id, id);
    assert!(reclaimed.lease_expires_at.unwrap() > unix_timestamp());

    // Renewing keeps a slow render claimed.
    store.save(&stranded).await.unwrap();
    store.renew_lease(&id).await.unwrap();
    assert!(store.claim_next().await.unwrap().is_none());
}
