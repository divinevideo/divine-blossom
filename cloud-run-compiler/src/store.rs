// ABOUTME: Persistence boundary for compilation jobs
// ABOUTME: Includes an atomic in-memory implementation for tests and local execution

use crate::domain::{Job, JobStatus};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

#[async_trait]
pub trait JobStore: Send + Sync {
    async fn create(&self, job: &Job) -> Result<()>;
    async fn create_limited(&self, job: &Job, since: u64, limit: usize) -> Result<bool>;
    async fn get(&self, id: &str) -> Result<Option<Job>>;
    async fn save(&self, job: &Job) -> Result<()>;
    async fn recent_for_initiator(&self, initiated_by: &str, limit: usize) -> Result<Vec<Job>>;
    async fn claim_next(&self) -> Result<Option<Job>>;
}

#[derive(Clone, Default)]
pub struct MemoryJobStore {
    jobs: Arc<RwLock<HashMap<String, Job>>>,
}

#[async_trait]
impl JobStore for MemoryJobStore {
    async fn create(&self, job: &Job) -> Result<()> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        if jobs.contains_key(&job.id) {
            return Err(anyhow!("job {} already exists", job.id));
        }
        jobs.insert(job.id.clone(), job.clone());
        Ok(())
    }

    async fn create_limited(&self, job: &Job, since: u64, limit: usize) -> Result<bool> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        if jobs.contains_key(&job.id) {
            return Err(anyhow!("job {} already exists", job.id));
        }
        let recent = jobs
            .values()
            .filter(|candidate| {
                candidate.initiated_by == job.initiated_by && candidate.created_at >= since
            })
            .count();
        if recent >= limit {
            return Ok(false);
        }
        jobs.insert(job.id.clone(), job.clone());
        Ok(true)
    }

    async fn get(&self, id: &str) -> Result<Option<Job>> {
        let jobs = self
            .jobs
            .read()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        Ok(jobs.get(id).cloned())
    }

    async fn save(&self, job: &Job) -> Result<()> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        if !jobs.contains_key(&job.id) {
            return Err(anyhow!("job {} does not exist", job.id));
        }
        jobs.insert(job.id.clone(), job.clone());
        Ok(())
    }

    async fn recent_for_initiator(&self, initiated_by: &str, limit: usize) -> Result<Vec<Job>> {
        let jobs = self
            .jobs
            .read()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        let mut matching: Vec<Job> = jobs
            .values()
            .filter(|job| job.initiated_by == initiated_by)
            .cloned()
            .collect();
        matching.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        matching.truncate(limit);
        Ok(matching)
    }

    async fn claim_next(&self) -> Result<Option<Job>> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        let next_id = jobs
            .values()
            .filter(|job| job.status == JobStatus::Queued)
            .min_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|job| job.id.clone());

        let Some(next_id) = next_id else {
            return Ok(None);
        };
        let job = jobs
            .get_mut(&next_id)
            .ok_or_else(|| anyhow!("claimed job disappeared"))?;
        job.status = JobStatus::Running;
        Ok(Some(job.clone()))
    }
}

#[derive(Clone)]
pub struct FirestoreJobStore {
    client: Client,
    documents_url: String,
    project_id: String,
    collection: String,
    emulator: bool,
}

impl FirestoreJobStore {
    pub fn new(project_id: &str, collection: &str) -> Result<Self> {
        if !valid_resource_segment(project_id) || !valid_resource_segment(collection) {
            bail!("Firestore project and collection must be simple resource segments");
        }
        let emulator_host = std::env::var("FIRESTORE_EMULATOR_HOST").ok();
        let root = emulator_host
            .as_ref()
            .map(|host| format!("http://{host}"))
            .unwrap_or_else(|| "https://firestore.googleapis.com".into());
        let database_url = format!("{root}/v1/projects/{project_id}/databases/(default)");
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                .build()
                .context("build Firestore HTTP client")?,
            documents_url: format!("{database_url}/documents"),
            project_id: project_id.into(),
            collection: collection.into(),
            emulator: emulator_host.is_some(),
        })
    }

    fn collection_url(&self) -> String {
        format!("{}/{}", self.documents_url, self.collection)
    }

    fn document_url(&self, id: &str) -> Result<String> {
        if !valid_resource_segment(id) {
            bail!("invalid job document id");
        }
        Ok(format!("{}/{}", self.collection_url(), id))
    }

    fn document_name(&self, id: &str) -> Result<String> {
        if !valid_resource_segment(id) {
            bail!("invalid job document id");
        }
        Ok(format!(
            "projects/{}/databases/(default)/documents/{}/{}",
            self.project_id, self.collection, id
        ))
    }

    async fn authorize(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        if self.emulator {
            return Ok(request);
        }
        let token = self
            .client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .context("request Firestore access token")?
            .error_for_status()
            .context("metadata server rejected Firestore token request")?
            .json::<MetadataToken>()
            .await
            .context("decode Firestore access token")?;
        Ok(request.bearer_auth(token.access_token))
    }

    async fn begin_transaction(&self) -> Result<String> {
        let request = self
            .client
            .post(format!("{}:beginTransaction", self.documents_url));
        let response = self
            .authorize(request)
            .await?
            .json(&json!({}))
            .send()
            .await
            .context("begin Firestore transaction")?
            .error_for_status()
            .context("Firestore rejected transaction begin")?
            .json::<TransactionResponse>()
            .await
            .context("decode Firestore transaction")?;
        Ok(response.transaction)
    }

    async fn rollback(&self, transaction: &str) {
        let request = self.client.post(format!("{}:rollback", self.documents_url));
        if let Ok(request) = self.authorize(request).await {
            let _ = request
                .json(&json!({ "transaction": transaction }))
                .send()
                .await;
        }
    }

    async fn run_query(&self, query: Value, transaction: Option<&str>) -> Result<Vec<QueryRow>> {
        let mut body = json!({ "structuredQuery": query });
        if let Some(transaction) = transaction {
            body["transaction"] = Value::String(transaction.into());
        }
        let request = self.client.post(format!("{}:runQuery", self.documents_url));
        self.authorize(request)
            .await?
            .json(&body)
            .send()
            .await
            .context("run Firestore job query")?
            .error_for_status()
            .context("Firestore rejected job query")?
            .json()
            .await
            .context("decode Firestore job query")
    }

    async fn commit(&self, transaction: &str, writes: Value) -> Result<bool> {
        let request = self.client.post(format!("{}:commit", self.documents_url));
        let response = self
            .authorize(request)
            .await?
            .json(&json!({ "transaction": transaction, "writes": writes }))
            .send()
            .await
            .context("commit Firestore transaction")?;
        if matches!(
            response.status(),
            StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED
        ) {
            return Ok(false);
        }
        response
            .error_for_status()
            .context("Firestore rejected transaction commit")?;
        Ok(true)
    }
}

#[async_trait]
impl JobStore for FirestoreJobStore {
    async fn create(&self, job: &Job) -> Result<()> {
        let request = self
            .client
            .post(self.collection_url())
            .query(&[("documentId", &job.id)]);
        self.authorize(request)
            .await?
            .json(&job_document(job, None)?)
            .send()
            .await
            .context("create Firestore job")?
            .error_for_status()
            .context("Firestore rejected job creation")?;
        Ok(())
    }

    async fn create_limited(&self, job: &Job, since: u64, limit: usize) -> Result<bool> {
        for _ in 0..3 {
            let transaction = self.begin_transaction().await?;
            let query = initiated_jobs_query(&self.collection, &job.initiated_by, limit);
            let rows = self.run_query(query, Some(&transaction)).await?;
            let recent = rows
                .iter()
                .filter_map(|row| row.document.as_ref())
                .filter_map(|document| decode_job(document).ok())
                .filter(|candidate| candidate.created_at >= since)
                .count();
            if recent >= limit {
                self.rollback(&transaction).await;
                return Ok(false);
            }
            let document_name = self.document_name(&job.id)?;
            let write = json!({
                "update": job_document(job, Some(&document_name))?,
                "currentDocument": { "exists": false }
            });
            if self.commit(&transaction, json!([write])).await? {
                return Ok(true);
            }
        }
        bail!("Firestore rate-limit transaction aborted repeatedly")
    }

    async fn get(&self, id: &str) -> Result<Option<Job>> {
        let request = self.client.get(self.document_url(id)?);
        let response = self
            .authorize(request)
            .await?
            .send()
            .await
            .context("get Firestore job")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let document: FirestoreDocument = response
            .error_for_status()
            .context("Firestore rejected job read")?
            .json()
            .await
            .context("decode Firestore job")?;
        Ok(Some(decode_job(&document)?))
    }

    async fn save(&self, job: &Job) -> Result<()> {
        let request = self.client.patch(self.document_url(&job.id)?);
        self.authorize(request)
            .await?
            .json(&job_document(job, None)?)
            .send()
            .await
            .context("save Firestore job")?
            .error_for_status()
            .context("Firestore rejected job save")?;
        Ok(())
    }

    async fn recent_for_initiator(&self, initiated_by: &str, limit: usize) -> Result<Vec<Job>> {
        self.run_query(
            initiated_jobs_query(&self.collection, initiated_by, limit),
            None,
        )
        .await?
        .into_iter()
        .filter_map(|row| row.document)
        .map(|document| decode_job(&document))
        .collect()
    }

    async fn claim_next(&self) -> Result<Option<Job>> {
        for _ in 0..3 {
            let transaction = self.begin_transaction().await?;
            let query = json!({
                "from": [{ "collectionId": self.collection }],
                "where": {
                    "fieldFilter": {
                        "field": { "fieldPath": "status" },
                        "op": "EQUAL",
                        "value": { "stringValue": "queued" }
                    }
                },
                "orderBy": [
                    { "field": { "fieldPath": "created_at" }, "direction": "ASCENDING" },
                    { "field": { "fieldPath": "__name__" }, "direction": "ASCENDING" }
                ],
                "limit": 1
            });
            let rows = self.run_query(query, Some(&transaction)).await?;
            let Some(document) = rows.into_iter().find_map(|row| row.document) else {
                self.rollback(&transaction).await;
                return Ok(None);
            };
            let mut job = decode_job(&document)?;
            if job.status != JobStatus::Queued {
                self.rollback(&transaction).await;
                continue;
            }
            job.status = JobStatus::Running;
            let name = document.name.context("claimed Firestore job has no name")?;
            let update_time = document
                .update_time
                .context("claimed Firestore job has no update time")?;
            let write = json!({
                "update": job_document(&job, Some(&name))?,
                "currentDocument": { "updateTime": update_time }
            });
            if self.commit(&transaction, json!([write])).await? {
                return Ok(Some(job));
            }
        }
        Ok(None)
    }
}

#[derive(Deserialize)]
struct MetadataToken {
    access_token: String,
}

#[derive(Deserialize)]
struct TransactionResponse {
    transaction: String,
}

#[derive(Debug, Deserialize)]
struct QueryRow {
    document: Option<FirestoreDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirestoreDocument {
    name: Option<String>,
    fields: HashMap<String, Value>,
    update_time: Option<String>,
}

fn job_document(job: &Job, name: Option<&str>) -> Result<Value> {
    let mut document = json!({
        "fields": {
            "job_json": { "stringValue": serde_json::to_string(job)? },
            "status": { "stringValue": status_name(job.status) },
            "initiated_by": { "stringValue": job.initiated_by },
            "created_at": { "integerValue": job.created_at.to_string() },
            "updated_at": { "integerValue": job.updated_at.to_string() }
        }
    });
    if let Some(name) = name {
        document["name"] = Value::String(name.into());
    }
    Ok(document)
}

fn decode_job(document: &FirestoreDocument) -> Result<Job> {
    let json = document
        .fields
        .get("job_json")
        .and_then(|field| field.get("stringValue"))
        .and_then(Value::as_str)
        .context("Firestore job is missing job_json")?;
    serde_json::from_str(json).context("decode persisted job JSON")
}

fn initiated_jobs_query(collection: &str, initiated_by: &str, limit: usize) -> Value {
    json!({
        "from": [{ "collectionId": collection }],
        "where": {
            "fieldFilter": {
                "field": { "fieldPath": "initiated_by" },
                "op": "EQUAL",
                "value": { "stringValue": initiated_by }
            }
        },
        "orderBy": [
            { "field": { "fieldPath": "created_at" }, "direction": "DESCENDING" },
            { "field": { "fieldPath": "__name__" }, "direction": "ASCENDING" }
        ],
        "limit": limit
    })
}

fn status_name(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Queued => "queued",
        JobStatus::Running => "running",
        JobStatus::Done => "done",
        JobStatus::Failed => "failed",
    }
}

fn valid_resource_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
