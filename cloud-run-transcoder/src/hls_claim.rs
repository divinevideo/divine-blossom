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
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

use crate::object_storage::MediaStorage;

const LEASE: Duration = Duration::from_secs(90);
pub(crate) const B2_RETRY_LEASE_MARGIN: Duration = Duration::from_secs(45);
const HEARTBEAT: Duration = Duration::from_secs(20);
// Work must stop preparing new mutations after the dispatch deadline.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(900);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
// Cloud Storage limits mutations of an object name to one per second; a small
// buffer avoids clock/RTT jitter tripping 429s on consecutive transitions.
const MUTATION_INTERVAL: Duration = Duration::from_millis(1100);
// GCS limits total custom object metadata to 8 KiB; keep the serialized
// journal safely below that limit with headroom for key name and overhead.
const MAX_JOURNAL_BYTES: usize = 7_500;
const STATE: &str = "hls_claim_v1";
pub(crate) const WRITE_ID: &str = "hls_write_id";

/// Shared publication lease handle observed by tiered uploads and bounded
/// retries. `renewed_at` is stamped conservatively *before* each claim CAS
/// leaves the client and invalidated immediately when ownership is lost or
/// heartbeat renewal fails past the safe lease margin.
#[derive(Clone)]
pub(crate) struct PublishLease {
    state: Arc<Mutex<Option<Instant>>>,
}

impl PublishLease {
    pub(crate) fn new(renewed_at: Instant) -> Self {
        Self {
            state: Arc::new(Mutex::new(Some(renewed_at))),
        }
    }

    pub(crate) fn renew(&self, renewed_at: Instant) {
        if let Ok(mut guard) = self.state.lock() {
            if guard.is_some() {
                *guard = Some(renewed_at);
            }
        }
    }

    pub(crate) fn invalidate(&self) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = None;
        }
    }

    /// Remaining time strictly inside the conservative lease margin
    /// (`renewed_at + B2_RETRY_LEASE_MARGIN`), or `None` if invalidated or
    /// expired.
    pub(crate) fn remaining_after(&self, delay: Duration) -> Option<Duration> {
        let renewed = (*self.state.lock().ok()?)?;
        let limit = renewed + B2_RETRY_LEASE_MARGIN;
        let start = Instant::now() + delay;
        limit.checked_duration_since(start)
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WriteTarget {
    pub(crate) gcs: bool,
    pub(crate) key: String,
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
    Publishing {
        id: String,
        writes: Vec<WriteTarget>,
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
    lease_renewed_at: Instant,
    next_heartbeat: Instant,
    next_mutation: Instant,
    // A provider success proves the journaled PUT(s) settled for the active
    // worker. The durable Writing/Publishing entry stays until the next CAS,
    // so recovery can prove settlement independently by finding the same
    // marker on the provider.
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
        let key = lock_key(hash);
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
                    if id.is_empty() {
                        count("invalid_lock_blocked");
                        return Err(Busy.into());
                    }
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
                Phase::Publishing { id, writes } if stale => {
                    if writes.is_empty() || id.is_empty() {
                        count("invalid_lock_blocked");
                        return Err(Busy.into());
                    }
                    let Some(storage) = storage else {
                        count("recovery_failed");
                        return Err(Busy.into());
                    };
                    let checks =
                        futures::future::try_join_all(writes.iter().map(|target| {
                            storage.hls_write_committed(target.gcs, &target.key, id)
                        }))
                        .await;
                    match checks {
                        Ok(results) if results.iter().all(|&committed| committed) => {}
                        Ok(_) => {
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
        let (generation, started_at) = self
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
            lease_renewed_at: started_at,
            next_heartbeat: started_at + HEARTBEAT,
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
    ) -> Result<Option<(i64, Instant)>> {
        let encoded = serde_json::to_string(journal)?;
        if encoded.len() > MAX_JOURNAL_BYTES {
            bail!(
                "Transcode lock journal exceeds metadata size limit ({} > {MAX_JOURNAL_BYTES})",
                encoded.len()
            );
        }
        let metadata = Object {
            name: key.to_owned(),
            content_type: Some("application/octet-stream".to_owned()),
            metadata: Some(HashMap::from([(STATE.to_owned(), encoded)])),
            ..Default::default()
        };
        let request = UploadObjectRequest {
            bucket: self.bucket.clone(),
            if_generation_match: Some(previous),
            ..Default::default()
        };
        let upload = UploadType::Multipart(Box::new(metadata));
        let (result, started_at) = mutate_claim(not_before, work_deadline, || {
            self.client.upload_object(&request, Bytes::new(), &upload)
        })
        .await
        .context("Transcode lock update timed out")?;
        match result {
            Ok(object) if object.generation > 0 => Ok(Some((object.generation, started_at))),
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
) -> Result<(std::result::Result<T, Error>, Instant)>
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
        // Stamp the conservative lease start *before* the request leaves the
        // client so GCS `timeCreated` is never earlier than our local clock.
        let attempt_started = Instant::now();
        // A request admitted before the deadline still needs its normal
        // response window. Canceling a committed intent early can leave a
        // durable Writing record for a media PUT the worker never started.
        let result = tokio::time::timeout(CONTROL_TIMEOUT, operation()).await?;
        if result.as_ref().err().and_then(gcs_status) != Some(429) {
            return Ok((result, attempt_started));
        }
        count("claim_mutation_throttled");
        let delay = backoff.mul_f64(1.0 + 0.25 * crate::retry_jitter_ratio());
        if Instant::now() + delay >= start_deadline {
            return Ok((result, attempt_started));
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

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn lease_renewed_at(&self) -> Instant {
        self.lease_renewed_at
    }

    async fn transition(&mut self, journal: Journal, work_deadline: Option<Instant>) -> Result<()> {
        let (generation, started_at) = self
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
        self.generation = generation;
        self.journal = journal;
        self.write_acknowledged = false;
        let now = Instant::now();
        self.lease_renewed_at = started_at;
        self.next_heartbeat = started_at + HEARTBEAT;
        self.next_mutation = now + MUTATION_INTERVAL;
        Ok(())
    }

    fn has_unconfirmed_write(&self) -> bool {
        matches!(
            self.journal.phase,
            Phase::Writing { .. } | Phase::Publishing { .. }
        ) && !self.write_acknowledged
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

    pub(crate) async fn begin_publication(
        &mut self,
        writes: Vec<WriteTarget>,
        id: &str,
    ) -> Result<()> {
        self.check_deadline()?;
        if self.has_unconfirmed_write() {
            bail!("Cannot begin another write with an unconfirmed publication");
        }
        if writes.is_empty() {
            bail!("Publication batch must include at least one target");
        }
        if id.is_empty() {
            bail!("Publication batch write id must not be empty");
        }
        self.transition(
            Journal {
                dirty: self.journal.dirty.max(self.intent),
                phase: Phase::Publishing {
                    id: id.to_owned(),
                    writes,
                },
            },
            Some(self.deadline),
        )
        .await
    }

    /// Renew an active `Publishing` lease concurrently alongside `work` without
    /// ever cancelling or dropping in-flight provider PUT futures. On
    /// `OwnershipLost` or lease-margin expiry, `lease` is invalidated immediately
    /// so `work` launches no further tiers, backups, or retries while letting
    /// already-started PUTs settle.
    pub(crate) async fn hold_publishing<T>(
        &mut self,
        lease: PublishLease,
        work: impl Future<Output = T>,
    ) -> (T, Option<anyhow::Error>) {
        type HeartbeatFuture = Pin<Box<dyn Future<Output = Result<Option<(i64, Instant)>>> + Send>>;
        tokio::pin!(work);
        let mut heartbeat_error: Option<anyhow::Error> = None;
        let mut in_flight: Option<HeartbeatFuture> = None;
        loop {
            if heartbeat_error.is_some() {
                return (work.await, heartbeat_error);
            }
            if let Some(hb) = in_flight.as_mut() {
                tokio::select! {
                    biased;
                    result = &mut work => {
                        // Await any already-dispatched heartbeat so self.generation
                        // reflects the live GCS generation before mark_verified/reject.
                        if let Some(hb) = in_flight.take() {
                            match hb.await {
                                Ok(Some((generation, started_at))) => {
                                    self.generation = generation;
                                    self.lease_renewed_at = started_at;
                                    self.next_heartbeat = started_at + HEARTBEAT;
                                    self.next_mutation = Instant::now() + MUTATION_INTERVAL;
                                    lease.renew(started_at);
                                }
                                Ok(None) => {
                                    lease.invalidate();
                                    heartbeat_error = Some(OwnershipLost.into());
                                }
                                Err(error) => {
                                    lease.invalidate();
                                    heartbeat_error = Some(error);
                                }
                            }
                        }
                        return (result, heartbeat_error);
                    }
                    hb_result = hb.as_mut() => {
                        in_flight = None;
                        match hb_result {
                            Ok(Some((generation, started_at))) => {
                                self.generation = generation;
                                self.lease_renewed_at = started_at;
                                self.next_heartbeat = started_at + HEARTBEAT;
                                self.next_mutation = Instant::now() + MUTATION_INTERVAL;
                                lease.renew(started_at);
                            }
                            Ok(None) => {
                                lease.invalidate();
                                heartbeat_error = Some(OwnershipLost.into());
                            }
                            Err(error) => {
                                // A single transient GCS hiccup early in the lease
                                // should retry rather than guaranteeing expiry at 90 s.
                                if lease.remaining_after(MUTATION_INTERVAL).is_some() {
                                    self.next_heartbeat = Instant::now() + MUTATION_INTERVAL;
                                } else {
                                    lease.invalidate();
                                    heartbeat_error = Some(error);
                                }
                            }
                        }
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    result = &mut work => return (result, None),
                    () = tokio::time::sleep_until(self.deadline) => {
                        lease.invalidate();
                        heartbeat_error = Some(anyhow!(
                            "Transcode attempt exceeded its preparation deadline"
                        ));
                    }
                    () = tokio::time::sleep_until(self.next_heartbeat) => {
                        if let Err(error) = self.check_deadline() {
                            lease.invalidate();
                            heartbeat_error = Some(error);
                            continue;
                        }
                        let store = self.store.clone();
                        let key = self.key.clone();
                        let generation = self.generation;
                        let journal = self.journal.clone();
                        let not_before = self.next_mutation;
                        let deadline = self.deadline;
                        in_flight = Some(Box::pin(async move {
                            store
                                .replace(&key, generation, &journal, not_before, Some(deadline))
                                .await
                        }));
                    }
                }
            }
        }
    }

    #[cfg(test)]
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
        let (deletion, _) = mutate_claim(self.next_mutation, None, || {
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
mod tests;
