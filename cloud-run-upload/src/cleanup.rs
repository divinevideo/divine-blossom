use async_trait::async_trait;
use google_cloud_storage::{
    client::Client as GcsClient,
    http::objects::{delete::DeleteObjectRequest, list::ListObjectsRequest},
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};

const MAX_PREFIX_OBJECTS_PER_ATTEMPT: usize = 25;
// Half of the 60-second production caller timeout for this route. The handler
// deadline starts after cold start, and the caller still needs time for the
// edge work and response travel that follow it, so the ceiling must leave a
// margin rather than match the caller's budget.
pub const CLEANUP_REQUEST_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Completed,
    Retryable,
    Permanent,
}

/// Typed evidence for the private generation inventory. Omitted on uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateFamilyCleanup {
    Absent,
    Remaining,
}

#[derive(Debug, Serialize)]
pub struct HashCleanupResult {
    pub hash: String,
    pub status: CleanupStatus,
    pub main_deleted_or_absent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_family: Option<PrivateFamilyCleanup>,
    pub deleted: usize,
    pub absent: usize,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteOutcome {
    Deleted,
    Absent,
}

#[derive(Debug)]
struct PrivateObjectVersion {
    name: String,
    generation: i64,
}

struct PrivateVersionPage {
    objects: Vec<PrivateObjectVersion>,
    more: bool,
}

#[async_trait]
trait CleanupBackend {
    async fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, String>;
    async fn delete_object(&self, object: &str) -> Result<DeleteOutcome, String>;
    async fn list_private_versions(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<PrivateVersionPage, String>;
    async fn delete_private_version(
        &self,
        object: &PrivateObjectVersion,
    ) -> Result<DeleteOutcome, String>;
}

pub struct GcsCleanupBackend<'a> {
    client: &'a GcsClient,
    bucket: &'a str,
}

impl<'a> GcsCleanupBackend<'a> {
    pub fn new(client: &'a GcsClient, bucket: &'a str) -> Self {
        Self { client, bucket }
    }
}

#[async_trait]
impl CleanupBackend for GcsCleanupBackend<'_> {
    async fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, String> {
        let response = self
            .client
            .list_objects(&ListObjectsRequest {
                bucket: self.bucket.to_string(),
                prefix: Some(prefix.to_string()),
                max_results: Some(limit.min(i32::MAX as usize) as i32),
                ..Default::default()
            })
            .await
            .map_err(|error| format!("failed to list derivative objects: {error}"))?;
        Ok(response
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|object| object.name)
            .collect())
    }

    async fn list_private_versions(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<PrivateVersionPage, String> {
        let response = self
            .client
            .list_objects(&ListObjectsRequest {
                bucket: self.bucket.to_string(),
                prefix: Some(prefix.to_string()),
                versions: Some(true),
                max_results: Some(limit as i32),
                ..Default::default()
            })
            .await
            .map_err(|error| format!("failed to list private family versions: {error}"))?;
        let objects = response
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|object| PrivateObjectVersion {
                name: object.name,
                generation: object.generation,
            })
            .collect::<Vec<_>>();
        if objects.len() > limit
            || objects
                .iter()
                .any(|object| !object.name.starts_with(prefix) || object.generation <= 0)
        {
            return Err("invalid private family version inventory".to_string());
        }
        Ok(PrivateVersionPage {
            objects,
            more: response.next_page_token.is_some(),
        })
    }

    async fn delete_private_version(
        &self,
        object: &PrivateObjectVersion,
    ) -> Result<DeleteOutcome, String> {
        match self
            .client
            .delete_object(&DeleteObjectRequest {
                bucket: self.bucket.to_string(),
                object: object.name.clone(),
                generation: Some(object.generation),
                ..Default::default()
            })
            .await
        {
            Ok(()) => Ok(DeleteOutcome::Deleted),
            Err(error) if is_not_found_error(&error) => Ok(DeleteOutcome::Absent),
            Err(error) => Err(format!("failed to delete private family version: {error}")),
        }
    }

    async fn delete_object(&self, object: &str) -> Result<DeleteOutcome, String> {
        match self
            .client
            .delete_object(&DeleteObjectRequest {
                bucket: self.bucket.to_string(),
                object: object.to_string(),
                ..Default::default()
            })
            .await
        {
            Ok(()) => Ok(DeleteOutcome::Deleted),
            Err(error) if is_not_found_error(&error) => Ok(DeleteOutcome::Absent),
            Err(error) => Err(format!("failed to delete object: {error}")),
        }
    }
}

pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub async fn cleanup_hash(backend: &GcsCleanupBackend<'_>, hash: &str) -> HashCleanupResult {
    cleanup_hash_before(backend, hash, Instant::now() + CLEANUP_REQUEST_DEADLINE).await
}

pub async fn cleanup_hash_before(
    backend: &GcsCleanupBackend<'_>,
    hash: &str,
    deadline: Instant,
) -> HashCleanupResult {
    cleanup_hash_with_backend(backend, hash, deadline).await
}

async fn cleanup_hash_with_backend<B: CleanupBackend + Sync>(
    backend: &B,
    hash: &str,
    deadline: Instant,
) -> HashCleanupResult {
    let private_prefix = format!("_private/artifact-families/v1/{hash}/");
    let mut deleted = 0;
    let mut absent = 0;
    // Only the reserved private namespace gains all-generation cleanup here.
    // Existing parent-media generation and retention semantics are unchanged.
    if Instant::now() >= deadline {
        return HashCleanupResult {
            hash: hash.to_string(),
            status: CleanupStatus::Retryable,
            main_deleted_or_absent: false,
            private_family: None,
            deleted,
            absent,
            failures: vec!["deadline exceeded while listing private family versions".to_string()],
        };
    }
    let private_page = timeout_at(
        deadline,
        backend.list_private_versions(&private_prefix, MAX_PREFIX_OBJECTS_PER_ATTEMPT),
    )
    .await;
    let private_page = match private_page {
        Ok(Ok(page)) => page,
        result => {
            return HashCleanupResult {
                hash: hash.to_string(),
                status: CleanupStatus::Retryable,
                main_deleted_or_absent: false,
                private_family: None,
                deleted,
                absent,
                failures: vec![match result {
                    Ok(Err(error)) => error,
                    _ => "deadline exceeded while listing private family versions".to_string(),
                }],
            }
        }
    };
    for object in &private_page.objects {
        if Instant::now() >= deadline {
            return HashCleanupResult {
                hash: hash.to_string(),
                status: CleanupStatus::Retryable,
                main_deleted_or_absent: false,
                private_family: None,
                deleted,
                absent,
                failures: vec![
                    "deadline exceeded while deleting private family versions".to_string()
                ],
            };
        }
        let result = timeout_at(deadline, backend.delete_private_version(object)).await;
        match result {
            Ok(Ok(DeleteOutcome::Deleted)) => deleted += 1,
            Ok(Ok(DeleteOutcome::Absent)) => absent += 1,
            result => {
                return HashCleanupResult {
                    hash: hash.to_string(),
                    status: CleanupStatus::Retryable,
                    main_deleted_or_absent: false,
                    private_family: None,
                    deleted,
                    absent,
                    failures: vec![match result {
                        Ok(Err(error)) => error,
                        _ => "deadline exceeded while deleting private family versions".to_string(),
                    }],
                }
            }
        }
    }
    let prefix = format!("{hash}/");
    let mut candidates = BTreeSet::from([hash.to_string(), format!("{hash}.jpg")]);
    let mut failures = Vec::new();

    if Instant::now() >= deadline {
        failures.push("deadline exceeded while listing derivative objects".to_string());
    } else if private_page.objects.len() < MAX_PREFIX_OBJECTS_PER_ATTEMPT {
        match timeout_at(
            deadline,
            backend.list_prefix(
                &prefix,
                MAX_PREFIX_OBJECTS_PER_ATTEMPT - private_page.objects.len(),
            ),
        )
        .await
        {
            Err(_) => {
                failures.push("deadline exceeded while listing derivative objects".to_string())
            }
            Ok(result) => match result {
                Ok(objects) => candidates.extend(objects),
                Err(error) => failures.push(error),
            },
        }
    }

    let mut main_deleted_or_absent = false;
    for object in candidates {
        if Instant::now() >= deadline {
            failures.push(format!("{object}: cleanup deadline exceeded"));
            continue;
        }
        match timeout_at(deadline, backend.delete_object(&object)).await {
            Err(_) => failures.push(format!("{object}: cleanup deadline exceeded")),
            Ok(Ok(DeleteOutcome::Deleted)) => {
                deleted += 1;
                main_deleted_or_absent |= object == hash;
            }
            Ok(Ok(DeleteOutcome::Absent)) => {
                absent += 1;
                main_deleted_or_absent |= object == hash;
            }
            Ok(Err(error)) => failures.push(format!("{object}: {error}")),
        }
    }

    if Instant::now() >= deadline {
        failures.push("cleanup deadline exceeded during verification".to_string());
    } else {
        match timeout_at(deadline, backend.list_prefix(&prefix, 1)).await {
            Err(_) => failures.push("cleanup deadline exceeded during verification".to_string()),
            Ok(Ok(remaining)) => failures.extend(
                remaining
                    .into_iter()
                    .map(|object| format!("{object}: remained after cleanup")),
            ),
            Ok(Err(error)) => failures.push(format!("verification {error}")),
        }
    }

    let private_family =
        match timeout_at(deadline, backend.list_private_versions(&private_prefix, 1)).await {
            Ok(Ok(page)) if page.objects.is_empty() && !page.more && !private_page.more => {
                Some(PrivateFamilyCleanup::Absent)
            }
            Ok(Ok(_)) => Some(PrivateFamilyCleanup::Remaining),
            Ok(Err(error)) => {
                failures.push(format!("private family verification: {error}"));
                None
            }
            Err(_) => {
                failures.push("deadline exceeded during private family verification".to_string());
                None
            }
        };

    HashCleanupResult {
        hash: hash.to_string(),
        status: if failures.is_empty() && private_family == Some(PrivateFamilyCleanup::Absent) {
            CleanupStatus::Completed
        } else {
            CleanupStatus::Retryable
        },
        main_deleted_or_absent,
        private_family,
        deleted,
        absent,
        failures,
    }
}

fn is_not_found_error(error: &google_cloud_storage::http::Error) -> bool {
    matches!(error, google_cloud_storage::http::Error::Response(response) if response.code == 404)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Mutex,
        time::Duration,
    };

    #[derive(Default)]
    struct FakeBackend {
        objects: Mutex<BTreeSet<String>>,
        failures: Mutex<BTreeMap<String, usize>>,
    }

    #[async_trait]
    impl CleanupBackend for FakeBackend {
        async fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, String> {
            Ok(self
                .objects
                .lock()
                .expect("objects lock")
                .iter()
                .filter(|object| object.starts_with(prefix))
                .take(limit)
                .cloned()
                .collect())
        }

        async fn list_private_versions(
            &self,
            prefix: &str,
            limit: usize,
        ) -> Result<PrivateVersionPage, String> {
            let objects = self
                .list_prefix(prefix, limit)
                .await?
                .into_iter()
                .map(|name| PrivateObjectVersion {
                    name,
                    generation: 1,
                })
                .collect();
            Ok(PrivateVersionPage {
                objects,
                more: false,
            })
        }

        async fn delete_private_version(
            &self,
            object: &PrivateObjectVersion,
        ) -> Result<DeleteOutcome, String> {
            self.delete_object(&object.name).await
        }

        async fn delete_object(&self, object: &str) -> Result<DeleteOutcome, String> {
            let mut failures = self.failures.lock().expect("failures lock");
            if let Some(remaining) = failures.get_mut(object) {
                if *remaining > 0 {
                    *remaining -= 1;
                    return Err("retryable failure".to_string());
                }
            }
            if self.objects.lock().expect("objects lock").remove(object) {
                Ok(DeleteOutcome::Deleted)
            } else {
                Ok(DeleteOutcome::Absent)
            }
        }
    }

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn missing_objects_are_confirmed_absent() {
        let result = cleanup_hash_with_backend(
            &FakeBackend::default(),
            HASH_A,
            Instant::now() + CLEANUP_REQUEST_DEADLINE,
        )
        .await;

        assert_eq!(result.status, CleanupStatus::Completed);
        assert!(result.main_deleted_or_absent);
        assert_eq!(result.deleted, 0);
        assert_eq!(result.absent, 2);
        assert!(result.failures.is_empty());
    }

    #[tokio::test]
    async fn retry_converges_after_transient_delete_failure() {
        let backend = FakeBackend::default();
        let object = format!("{HASH_A}/hls/custom.ts");
        backend
            .objects
            .lock()
            .expect("objects lock")
            .insert(object.clone());
        backend
            .failures
            .lock()
            .expect("failures lock")
            .insert(object, 1);

        let first =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() + CLEANUP_REQUEST_DEADLINE)
                .await;
        let retry =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() + CLEANUP_REQUEST_DEADLINE)
                .await;

        assert_eq!(first.status, CleanupStatus::Retryable);
        assert!(first.main_deleted_or_absent);
        assert_eq!(retry.status, CleanupStatus::Completed);
    }

    #[tokio::test]
    async fn large_prefix_is_cleaned_in_bounded_retryable_slices() {
        let backend = FakeBackend::default();
        backend.objects.lock().expect("objects lock").extend(
            (0..MAX_PREFIX_OBJECTS_PER_ATTEMPT + 1).map(|index| format!("{HASH_A}/hls/{index}.ts")),
        );

        let first =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() + CLEANUP_REQUEST_DEADLINE)
                .await;
        let second =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() + CLEANUP_REQUEST_DEADLINE)
                .await;

        assert_eq!(first.status, CleanupStatus::Retryable);
        assert_eq!(first.deleted, MAX_PREFIX_OBJECTS_PER_ATTEMPT);
        assert_eq!(second.status, CleanupStatus::Completed);
        assert_eq!(second.deleted, 1);
    }

    #[tokio::test]
    async fn main_outcome_is_preserved_when_a_derivative_fails() {
        let backend = FakeBackend::default();
        let derivative = format!("{HASH_A}.jpg");
        backend
            .failures
            .lock()
            .expect("failures lock")
            .insert(derivative, 1);

        let result =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() + CLEANUP_REQUEST_DEADLINE)
                .await;

        assert_eq!(result.status, CleanupStatus::Retryable);
        assert!(result.main_deleted_or_absent);
    }

    #[tokio::test]
    async fn private_marker_is_removed_without_touching_sibling_parent() {
        let backend = FakeBackend::default();
        let marker = format!("_private/artifact-families/v1/{HASH_A}/complete.json");
        let sibling = format!("_private/artifact-families/v1/{HASH_A}0/complete.json");
        backend
            .objects
            .lock()
            .unwrap()
            .extend([marker.clone(), sibling.clone()]);
        let result =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() + CLEANUP_REQUEST_DEADLINE)
                .await;
        assert_eq!(result.status, CleanupStatus::Completed);
        let remaining = backend.objects.lock().unwrap();
        assert!(
            !remaining.contains(&marker),
            "private marker survived completed cleanup"
        );
        assert!(remaining.contains(&sibling));
    }

    #[derive(Clone)]
    struct VersionedGcsFixture {
        mode: &'static str,
        generations: std::sync::Arc<Mutex<BTreeSet<i64>>>,
        requests: std::sync::Arc<Mutex<Vec<wiremock::Request>>>,
    }

    impl wiremock::Respond for VersionedGcsFixture {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.requests.lock().unwrap().push(request.clone());
            let query: BTreeMap<_, _> = request.url.query_pairs().into_owned().collect();
            if self.mode == "list_failure" && request.method == wiremock::http::Method::Get {
                return wiremock::ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error":{"code":400,"message":"listing unavailable","errors":[]}
                }));
            }
            if request.method == wiremock::http::Method::Delete {
                if self.mode == "retention" {
                    return wiremock::ResponseTemplate::new(403).set_body_json(serde_json::json!({
                        "error":{"code":403,"message":"retention constraint","errors":[]}
                    }));
                }
                if let Some(generation) = query.get("generation") {
                    self.generations
                        .lock()
                        .unwrap()
                        .remove(&generation.parse().unwrap());
                    return wiremock::ResponseTemplate::new(204);
                }
                return wiremock::ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {"code":404,"message":"absent","errors":[]}
                }));
            }
            let prefix = query.get("prefix").unwrap();
            let mut items = Vec::new();
            let mut more = false;
            if prefix.starts_with("_private/") && query.get("versions").is_some_and(|v| v == "true")
            {
                let generations = self.generations.lock().unwrap();
                // Deliberately short nonterminal pages: maxResults is not a promise.
                let limit = query["maxResults"].parse::<usize>().unwrap().min(
                    if self.mode == "full_page" {
                        MAX_PREFIX_OBJECTS_PER_ATTEMPT
                    } else {
                        3
                    },
                );
                more = generations.len() > limit;
                for generation in generations.iter().take(limit) {
                    let name = if self.mode == "foreign_prefix" {
                        "_private/artifact-families/v1/foreign/complete.json".to_string()
                    } else {
                        format!("{prefix}complete.json")
                    };
                    items.push(serde_json::json!({"name":name,
                        "generation":if self.mode == "invalid_generation" {"0".to_string()} else {generation.to_string()},"metageneration":"1","size":"1",
                        "id":"synthetic","etag":"synthetic","selfLink":"","mediaLink":"",
                        "bucket":"synthetic"}));
                }
            }
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items":items,"nextPageToken":if more {Some("next")} else {None}
            }))
        }
    }

    #[tokio::test]
    async fn private_marker_retained_generations_drain_through_real_gcs_sdk() {
        let server = wiremock::MockServer::start().await;
        let fixture = VersionedGcsFixture {
            mode: "normal",
            generations: std::sync::Arc::new(Mutex::new((1..=7).collect())),
            requests: Default::default(),
        };
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(fixture.clone())
            .mount(&server)
            .await;
        let mut config = google_cloud_storage::client::ClientConfig::default().anonymous();
        config.storage_endpoint = server.uri();
        let client = GcsClient::new(config);
        let backend = GcsCleanupBackend::new(&client, "synthetic");
        for attempt in 0..3 {
            let result = cleanup_hash(&backend, HASH_A).await;
            assert_eq!(
                result.status,
                if attempt == 2 {
                    CleanupStatus::Completed
                } else {
                    CleanupStatus::Retryable
                }
            );
        }
        assert!(fixture.generations.lock().unwrap().is_empty());
        let requests = fixture.requests.lock().unwrap();
        let pinned_deletes: Vec<_> = requests
            .iter()
            .filter(|request| {
                request.method == wiremock::http::Method::Delete
                    && request.url.query_pairs().any(|(k, _)| k == "generation")
            })
            .collect();
        assert_eq!(pinned_deletes.len(), 7);
        assert!(requests
            .iter()
            .filter(|r| r.method == wiremock::http::Method::Get
                && r.url
                    .query_pairs()
                    .any(|(k, v)| k == "prefix" && v.starts_with("_private/")))
            .all(|r| r
                .url
                .query_pairs()
                .any(|(k, v)| k == "versions" && v == "true")));
    }

    #[tokio::test]
    async fn private_gcs_uncertainty_retains_pending_without_later_side_effects() {
        for mode in [
            "list_failure",
            "retention",
            "foreign_prefix",
            "invalid_generation",
        ] {
            let server = wiremock::MockServer::start().await;
            let fixture = VersionedGcsFixture {
                mode,
                generations: std::sync::Arc::new(Mutex::new([1, 2].into_iter().collect())),
                requests: Default::default(),
            };
            wiremock::Mock::given(wiremock::matchers::any())
                .respond_with(fixture.clone())
                .mount(&server)
                .await;
            let mut config = google_cloud_storage::client::ClientConfig::default().anonymous();
            config.storage_endpoint = server.uri();
            let client = GcsClient::new(config);
            let backend = GcsCleanupBackend::new(&client, "synthetic");
            let result = cleanup_hash(&backend, HASH_A).await;
            assert_eq!(result.status, CleanupStatus::Retryable, "{mode}");
            assert!(!result.main_deleted_or_absent);
            assert_eq!(fixture.generations.lock().unwrap().len(), 2);
            assert_eq!(
                fixture.requests.lock().unwrap().len(),
                if mode == "retention" { 2 } else { 1 }
            );
        }
    }

    #[tokio::test]
    async fn private_gcs_full_page_shares_the_existing_delete_cap() {
        let server = wiremock::MockServer::start().await;
        let fixture = VersionedGcsFixture {
            mode: "full_page",
            generations: std::sync::Arc::new(Mutex::new((1..=26).collect())),
            requests: Default::default(),
        };
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(fixture.clone())
            .mount(&server)
            .await;
        let mut config = google_cloud_storage::client::ClientConfig::default().anonymous();
        config.storage_endpoint = server.uri();
        let client = GcsClient::new(config);
        let backend = GcsCleanupBackend::new(&client, "synthetic");
        let first = cleanup_hash(&backend, HASH_A).await;
        assert_eq!(first.status, CleanupStatus::Retryable);
        assert_eq!(first.deleted, MAX_PREFIX_OBJECTS_PER_ATTEMPT);
        assert_eq!(
            serde_json::to_value(&first).unwrap()["private_family"],
            "remaining",
            "known private remainder needs a typed progress signal"
        );
        assert_eq!(fixture.generations.lock().unwrap().len(), 1);
        let deletes = fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::Delete)
            .count();
        assert_eq!(deletes, MAX_PREFIX_OBJECTS_PER_ATTEMPT + 2);
        assert_eq!(
            cleanup_hash(&backend, HASH_A).await.status,
            CleanupStatus::Completed
        );
        assert!(fixture.generations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_deadline_never_starts_ready_private_deletes() {
        let backend = FakeBackend::default();
        let marker = format!("_private/artifact-families/v1/{HASH_A}/complete.json");
        backend.objects.lock().unwrap().insert(marker.clone());
        let result =
            cleanup_hash_with_backend(&backend, HASH_A, Instant::now() - Duration::from_secs(1))
                .await;
        assert_eq!(result.status, CleanupStatus::Retryable);
        assert_eq!(result.deleted, 0);
        assert!(backend.objects.lock().unwrap().contains(&marker));
    }

    struct SlowBackend;

    #[async_trait]
    impl CleanupBackend for SlowBackend {
        async fn list_prefix(&self, _prefix: &str, _limit: usize) -> Result<Vec<String>, String> {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(Vec::new())
        }

        async fn list_private_versions(
            &self,
            prefix: &str,
            limit: usize,
        ) -> Result<PrivateVersionPage, String> {
            self.list_prefix(prefix, limit).await?;
            Ok(PrivateVersionPage {
                objects: Vec::new(),
                more: false,
            })
        }

        async fn delete_private_version(
            &self,
            object: &PrivateObjectVersion,
        ) -> Result<DeleteOutcome, String> {
            self.delete_object(&object.name).await
        }

        async fn delete_object(&self, _object: &str) -> Result<DeleteOutcome, String> {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(DeleteOutcome::Deleted)
        }
    }

    #[tokio::test]
    async fn deadline_returns_a_fail_closed_per_hash_result() {
        let result = cleanup_hash_with_backend(
            &SlowBackend,
            HASH_A,
            Instant::now() + Duration::from_millis(1),
        )
        .await;

        assert_eq!(result.status, CleanupStatus::Retryable);
        assert!(!result.main_deleted_or_absent);
        assert!(result
            .failures
            .iter()
            .any(|failure| failure.contains("deadline exceeded")));
    }

    #[test]
    fn validates_hashes() {
        assert!(valid_hash(HASH_A));
        assert!(!valid_hash("short"));
        assert!(!valid_hash(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn not_found_classification_uses_the_gcs_status_code() {
        let not_found = google_cloud_storage::http::Error::Response(
            google_cloud_storage::http::error::ErrorResponse {
                code: 404,
                errors: Vec::new(),
                message: "object absent".to_string(),
            },
        );
        let misleading_message = google_cloud_storage::http::Error::Response(
            google_cloud_storage::http::error::ErrorResponse {
                code: 500,
                errors: Vec::new(),
                message: "Not Found while processing".to_string(),
            },
        );

        assert!(is_not_found_error(&not_found));
        assert!(!is_not_found_error(&misleading_message));
    }
}
