//! GCS generation CAS serializes writers of the stable HLS and MP4 object keys.
//! An expired preparation lease can be replaced. A potentially outstanding
//! provider PUT is reclaimable only with positive evidence it has committed.

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use google_cloud_storage::{
    client::Client as GcsClient,
    http::{
        objects::{
            delete::DeleteObjectRequest,
            get::GetObjectRequest,
            upload::{UploadObjectRequest, UploadType},
            Object,
        },
        Error,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, future::Future, time::Duration};
use tokio::time::Instant;

use crate::object_storage::MediaStorage;

const LEASE: Duration = Duration::from_secs(90);
const HEARTBEAT: Duration = Duration::from_secs(20);
// Work must stop preparing new mutations after the dispatch deadline.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(900);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
// Cloud Storage limits mutations of an object name to one per second.
const MUTATION_INTERVAL: Duration = Duration::from_secs(1);
const STATE: &str = "hls_claim_v1";
pub(crate) const WRITE_ID: &str = "hls_write_id";

#[derive(Debug, thiserror::Error)]
#[error("Could not acquire transcode lock: rendition set is busy")]
pub(crate) struct Busy;

#[derive(Debug, thiserror::Error)]
#[error("Transcode ownership changed")]
pub(crate) struct OwnershipLost;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Dirty {
    #[default]
    Clean,
    Mp4,
    Hls,
    Repair,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Journal {
    dirty: Dirty,
    phase: Phase,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
enum Phase {
    #[default]
    Preparing,
    Writing {
        gcs: bool,
        key: String,
        id: String,
    },
    Retry,
}

#[derive(Clone)]
pub(crate) struct ClaimStore {
    client: GcsClient,
    bucket: String,
}

pub(crate) struct Claim {
    store: ClaimStore,
    key: String,
    generation: i64,
    journal: Journal,
    intent: Dirty,
    deadline: Instant,
    next_heartbeat: Instant,
    next_mutation: Instant,
    // A provider success proves this PUT settled for the active worker. The
    // durable Writing entry stays until the next CAS, so recovery can prove
    // settlement independently by finding the same marker on the provider.
    write_acknowledged: bool,
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Claim")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

pub(crate) fn count(event: &'static str) {
    // Each event increments a log-based counter by one. Call sites use a
    // fixed vocabulary and include no identifiers or request-derived labels.
    tracing::info!(target: "divine_transcoder::hls_counter", event, count = 1, "hls_counter");
}

fn lock_key(hash: &str) -> String {
    // Media erasure enumerates the hash prefix. It must never remove the
    // control record of an in-flight writer.
    format!(".internal/hls-claims/{hash}")
}

pub(crate) fn gcs_status(error: &Error) -> Option<u16> {
    match error {
        Error::Response(response) => Some(response.code),
        Error::HttpClient(error) => error.status().map(|status| status.as_u16()),
        _ => None,
    }
}

impl ClaimStore {
    pub(crate) fn new(client: GcsClient, bucket: &str) -> Self {
        Self {
            client,
            bucket: bucket.to_owned(),
        }
    }

    pub(crate) async fn claim(&self, hash: &str, storage: Option<&MediaStorage>) -> Result<Claim> {
        self.claim_key(lock_key(hash), storage).await
    }

    pub(crate) async fn claim_sound(
        &self,
        hash: &str,
        storage: &MediaStorage,
    ) -> Result<Claim> {
        // Keep the write journal outside the media prefix, like the HLS claim.
        self.claim_key(format!(".internal/sound-claims/{hash}"), Some(storage))
            .await
    }

    async fn claim_key(&self, key: String, storage: Option<&MediaStorage>) -> Result<Claim> {
        // Active contenders only read the journal. The conditional create
        // still arbitrates concurrent observations of an absent object.
        let mut journal = Journal::default();
        let mut prior_generation = 0;
        let mut not_before = Instant::now();
        if let Some(object) = self.lookup(&key, None).await? {
            prior_generation = object.generation;
            if prior_generation <= 0 {
                bail!("Transcode lock generation missing");
            }
            let Some(encoded) = object
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get(STATE))
            else {
                count("invalid_lock_blocked");
                return Err(Busy.into());
            };
            journal = serde_json::from_str(encoded).context("Invalid transcode lock journal")?;
            let stale = object
                .time_created
                .is_some_and(|created| time::OffsetDateTime::now_utc() - created > LEASE);
            match &journal.phase {
                Phase::Retry => {}
                Phase::Preparing if stale => {}
                Phase::Writing { gcs, key, id } if stale => {
                    let committed = if let Some(storage) = storage {
                        storage.hls_write_committed(*gcs, key, id).await
                    } else {
                        Ok(false)
                    };
                    match committed {
                        Ok(true) => {}
                        Ok(false) => {
                            count("recovery_failed");
                            return Err(Busy.into());
                        }
                        Err(error) => {
                            count("recovery_failed");
                            return Err(error).context("Transcode write recovery lookup failed");
                        }
                    }
                }
                _ => return Err(Busy.into()),
            }
            journal.phase = Phase::Preparing;
            let age = object
                .time_created
                .and_then(|created| {
                    Duration::try_from(time::OffsetDateTime::now_utc() - created).ok()
                })
                .unwrap_or_default();
            not_before = Instant::now() + MUTATION_INTERVAL.saturating_sub(age);
        }
        let generation = self
            .replace(&key, prior_generation, &journal, not_before, None)
            .await?
            .ok_or(Busy)?;
        if prior_generation != 0 {
            count("claim_recovered");
        }
        count("claim_acquired");
        let now = Instant::now();
        Ok(Claim {
            store: self.clone(),
            key,
            generation,
            journal,
            intent: Dirty::Hls,
            deadline: now + ATTEMPT_BUDGET,
            next_heartbeat: now + HEARTBEAT,
            next_mutation: now + MUTATION_INTERVAL,
            write_acknowledged: false,
        })
    }

    async fn lookup(&self, key: &str, generation: Option<i64>) -> Result<Option<Object>> {
        let request = GetObjectRequest {
            bucket: self.bucket.clone(),
            object: key.to_owned(),
            if_generation_match: generation,
            ..Default::default()
        };
        let result = tokio::time::timeout(CONTROL_TIMEOUT, self.client.get_object(&request))
            .await
            .context("Transcode lock lookup timed out")?;
        match result {
            Ok(object) => Ok(Some(object)),
            Err(error) if matches!(gcs_status(&error), Some(404 | 412)) => Ok(None),
            Err(error) => Err(error).context("Transcode lock lookup failed"),
        }
    }

    async fn replace(
        &self,
        key: &str,
        previous: i64,
        journal: &Journal,
        not_before: Instant,
        work_deadline: Option<Instant>,
    ) -> Result<Option<i64>> {
        let metadata = Object {
            name: key.to_owned(),
            content_type: Some("application/octet-stream".to_owned()),
            metadata: Some(HashMap::from([(
                STATE.to_owned(),
                serde_json::to_string(journal)?,
            )])),
            ..Default::default()
        };
        let request = UploadObjectRequest {
            bucket: self.bucket.clone(),
            if_generation_match: Some(previous),
            ..Default::default()
        };
        let upload = UploadType::Multipart(Box::new(metadata));
        let result = mutate_claim(not_before, work_deadline, || {
            self.client.upload_object(&request, Bytes::new(), &upload)
        })
        .await
        .context("Transcode lock update timed out")?;
        match result {
            Ok(object) if object.generation > 0 => Ok(Some(object.generation)),
            Ok(_) => bail!("Transcode lock generation missing"),
            Err(error) if gcs_status(&error) == Some(412) => Ok(None),
            Err(error) => Err(error).context("Transcode lock update failed"),
        }
    }
}

/// Only an explicit throttle is retried. A timeout or ambiguous response may
/// have committed, so the caller must keep the existing recovery semantics.
async fn mutate_claim<T, F>(
    not_before: Instant,
    work_deadline: Option<Instant>,
    mut operation: impl FnMut() -> F,
) -> Result<std::result::Result<T, Error>>
where
    F: Future<Output = std::result::Result<T, Error>>,
{
    let mut start_deadline = Instant::now() + CONTROL_TIMEOUT;
    if let Some(work_deadline) = work_deadline {
        start_deadline = start_deadline.min(work_deadline);
    }
    tokio::time::timeout_at(start_deadline, tokio::time::sleep_until(not_before)).await?;
    let mut backoff = MUTATION_INTERVAL;
    loop {
        if Instant::now() >= start_deadline {
            bail!("Transcode lock mutation exceeded its admission deadline");
        }
        // A request admitted before the deadline still needs its normal
        // response window. Canceling a committed intent early can leave a
        // durable Writing record for a media PUT the worker never started.
        let result = tokio::time::timeout(CONTROL_TIMEOUT, operation()).await?;
        if result.as_ref().err().and_then(gcs_status) != Some(429) {
            return Ok(result);
        }
        count("claim_mutation_throttled");
        let delay = backoff.mul_f64(1.0 + 0.25 * crate::retry_jitter_ratio());
        if Instant::now() + delay >= start_deadline {
            return Ok(result);
        }
        tokio::time::sleep(delay).await;
        backoff *= 2;
    }
}

impl Claim {
    pub(crate) fn dirty(&self) -> Dirty {
        self.journal.dirty
    }

    pub(crate) fn set_intent(&mut self, intent: Dirty) {
        self.intent = intent;
    }

    pub(crate) fn write_id(&self) -> String {
        self.generation.to_string()
    }

    async fn transition(&mut self, journal: Journal, work_deadline: Option<Instant>) -> Result<()> {
        self.generation = self
            .store
            .replace(
                &self.key,
                self.generation,
                &journal,
                self.next_mutation,
                work_deadline,
            )
            .await?
            .ok_or(OwnershipLost)?;
        self.journal = journal;
        self.write_acknowledged = false;
        let now = Instant::now();
        self.next_heartbeat = now + HEARTBEAT;
        self.next_mutation = now + MUTATION_INTERVAL;
        Ok(())
    }

    fn has_unconfirmed_write(&self) -> bool {
        matches!(self.journal.phase, Phase::Writing { .. }) && !self.write_acknowledged
    }

    fn check_deadline(&self) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            bail!("Transcode attempt exceeded its preparation deadline");
        }
        Ok(())
    }

    pub(crate) async fn confirm(&mut self) -> Result<()> {
        self.check_deadline()?;
        if self.has_unconfirmed_write() {
            bail!("Transcode has an unconfirmed publication");
        }
        if Instant::now() >= self.next_heartbeat {
            return self
                .transition(
                    Journal {
                        phase: Phase::Preparing,
                        ..self.journal.clone()
                    },
                    Some(self.deadline),
                )
                .await;
        }
        let object = tokio::time::timeout_at(
            self.deadline,
            self.store.lookup(&self.key, Some(self.generation)),
        )
        .await??;
        if object.is_none_or(|object| object.generation != self.generation) {
            return Err(OwnershipLost.into());
        }
        Ok(())
    }

    /// Renew only during cancellable preparation or read-only verification.
    /// The mutation path uses a distinct journal phase and never runs here.
    pub(crate) async fn hold<T>(&mut self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.check_deadline()?;
        tokio::pin!(work);
        loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(self.deadline) => {
                    bail!("Transcode attempt exceeded its preparation deadline");
                }
                () = tokio::time::sleep_until(self.next_heartbeat) => self.confirm().await?,
                result = &mut work => return result,
            }
        }
    }

    pub(crate) async fn mark_verified(&mut self) -> Result<()> {
        if self.has_unconfirmed_write() {
            bail!("Cannot verify an unconfirmed publication");
        }
        self.transition(Journal::default(), None).await
    }

    pub(crate) async fn begin_write(&mut self, gcs: bool, key: &str, id: &str) -> Result<()> {
        self.check_deadline()?;
        if self.has_unconfirmed_write() {
            bail!("Cannot begin another write with an unconfirmed publication");
        }
        self.transition(
            Journal {
                dirty: self.journal.dirty.max(self.intent),
                phase: Phase::Writing {
                    gcs,
                    key: key.to_owned(),
                    id: id.to_owned(),
                },
            },
            Some(self.deadline),
        )
        .await
    }

    pub(crate) fn acknowledge_write(&mut self) {
        self.write_acknowledged = true;
    }

    /// A definite rejection settles the request without an object to prove it.
    /// Persist that outcome so a crash cannot leave recovery waiting for it.
    pub(crate) async fn reject_write(&mut self) -> Result<()> {
        self.transition(
            Journal {
                phase: Phase::Preparing,
                ..self.journal.clone()
            },
            None,
        )
        .await
    }

    pub(crate) async fn finish(mut self, success: bool) -> Result<()> {
        if self.has_unconfirmed_write() {
            count("recovery_failed");
            return Err(anyhow!(
                "Publication outcome unconfirmed; retained transcode lock"
            ));
        }
        if !success && self.journal.dirty != Dirty::Clean {
            return self
                .transition(
                    Journal {
                        phase: Phase::Retry,
                        ..self.journal.clone()
                    },
                    None,
                )
                .await;
        }
        let request = DeleteObjectRequest {
            bucket: self.store.bucket.clone(),
            object: self.key,
            if_generation_match: Some(self.generation),
            ..Default::default()
        };
        let deletion = mutate_claim(self.next_mutation, None, || {
            self.store.client.delete_object(&request)
        })
        .await
        .context("Transcode lock release timed out")?;
        match deletion {
            Ok(()) => Ok(()),
            Err(error) if gcs_status(&error) == Some(404) => Ok(()),
            Err(error) => Err(error).context("Transcode lock release failed"),
        }
    }
}

#[cfg(test)]
#[path = "hls_claim_tests.rs"]
pub(crate) mod tests;
