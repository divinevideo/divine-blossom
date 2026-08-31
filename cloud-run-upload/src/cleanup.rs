use async_trait::async_trait;
use google_cloud_storage::{
    client::Client as GcsClient,
    http::objects::{delete::DeleteObjectRequest, list::ListObjectsRequest},
};
use serde::Serialize;
use std::collections::BTreeSet;

const MAX_PREFIX_OBJECTS_PER_ATTEMPT: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Completed,
    Retryable,
    Permanent,
}

#[derive(Debug, Serialize)]
pub struct HashCleanupResult {
    pub hash: String,
    pub status: CleanupStatus,
    pub deleted: usize,
    pub absent: usize,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteOutcome {
    Deleted,
    Absent,
}

#[async_trait]
trait CleanupBackend {
    async fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<String>, String>;
    async fn delete_object(&self, object: &str) -> Result<DeleteOutcome, String>;
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
    cleanup_hash_with_backend(backend, hash).await
}

async fn cleanup_hash_with_backend<B: CleanupBackend + Sync>(
    backend: &B,
    hash: &str,
) -> HashCleanupResult {
    let prefix = format!("{hash}/");
    let mut candidates = BTreeSet::from([hash.to_string(), format!("{hash}.jpg")]);
    let mut failures = Vec::new();

    match backend
        .list_prefix(&prefix, MAX_PREFIX_OBJECTS_PER_ATTEMPT)
        .await
    {
        Ok(objects) => candidates.extend(objects),
        Err(error) => failures.push(error),
    }

    let mut deleted = 0;
    let mut absent = 0;
    for object in candidates {
        match backend.delete_object(&object).await {
            Ok(DeleteOutcome::Deleted) => deleted += 1,
            Ok(DeleteOutcome::Absent) => absent += 1,
            Err(error) => failures.push(format!("{object}: {error}")),
        }
    }

    match backend.list_prefix(&prefix, 1).await {
        Ok(remaining) => failures.extend(
            remaining
                .into_iter()
                .map(|object| format!("{object}: remained after cleanup")),
        ),
        Err(error) => failures.push(format!("verification {error}")),
    }

    HashCleanupResult {
        hash: hash.to_string(),
        status: if failures.is_empty() {
            CleanupStatus::Completed
        } else {
            CleanupStatus::Retryable
        },
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
        let result = cleanup_hash_with_backend(&FakeBackend::default(), HASH_A).await;

        assert_eq!(result.status, CleanupStatus::Completed);
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

        let first = cleanup_hash_with_backend(&backend, HASH_A).await;
        let retry = cleanup_hash_with_backend(&backend, HASH_A).await;

        assert_eq!(first.status, CleanupStatus::Retryable);
        assert_eq!(retry.status, CleanupStatus::Completed);
    }

    #[tokio::test]
    async fn large_prefix_is_cleaned_in_bounded_retryable_slices() {
        let backend = FakeBackend::default();
        backend.objects.lock().expect("objects lock").extend(
            (0..MAX_PREFIX_OBJECTS_PER_ATTEMPT + 1)
                .map(|index| format!("{HASH_A}/hls/{index}.ts")),
        );

        let first = cleanup_hash_with_backend(&backend, HASH_A).await;
        let second = cleanup_hash_with_backend(&backend, HASH_A).await;

        assert_eq!(first.status, CleanupStatus::Retryable);
        assert_eq!(first.deleted, MAX_PREFIX_OBJECTS_PER_ATTEMPT);
        assert_eq!(second.status, CleanupStatus::Completed);
        assert_eq!(second.deleted, 1);
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
