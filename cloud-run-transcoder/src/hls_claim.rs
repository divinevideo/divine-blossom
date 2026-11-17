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

use crate::object_storage::MediaStorage;

const LEASE: Duration = Duration::from_secs(90);
const HEARTBEAT: Duration = Duration::from_secs(20);
// Work must stop preparing new mutations after the dispatch deadline.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(900);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
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
    deadline: tokio::time::Instant,
    next_heartbeat: tokio::time::Instant,
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
        let mut journal = Journal::default();
        let mut previous = 0;
        let initial = self.replace(&key, previous, &journal).await?;
        let generation = if let Some(generation) = initial {
            generation
        } else {
            let object = match tokio::time::timeout(
                CONTROL_TIMEOUT,
                self.client.get_object(&GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: key.clone(),
                    ..Default::default()
                }),
            )
            .await
            .context("Transcode lock lookup timed out")?
            {
                Ok(object) => object,
                Err(error) if gcs_status(&error) == Some(404) => return Err(Busy.into()),
                Err(error) => return Err(error).context("Transcode lock lookup failed"),
            };
            previous = object.generation;
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
            let Some(generation) = self.replace(&key, previous, &journal).await? else {
                return Err(Busy.into());
            };
            count("claim_recovered");
            generation
        };

        count("claim_acquired");
        Ok(Claim {
            store: self.clone(),
            key,
            generation,
            journal,
            intent: Dirty::Hls,
            deadline: tokio::time::Instant::now() + ATTEMPT_BUDGET,
            next_heartbeat: tokio::time::Instant::now() + HEARTBEAT,
        })
    }

    async fn replace(&self, key: &str, previous: i64, journal: &Journal) -> Result<Option<i64>> {
        let metadata = Object {
            name: key.to_owned(),
            content_type: Some("application/octet-stream".to_owned()),
            metadata: Some(HashMap::from([(
                STATE.to_owned(),
                serde_json::to_string(journal)?,
            )])),
            ..Default::default()
        };
        let result = tokio::time::timeout(
            CONTROL_TIMEOUT,
            self.client.upload_object(
                &UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    if_generation_match: Some(previous),
                    ..Default::default()
                },
                Bytes::new(),
                &UploadType::Multipart(Box::new(metadata)),
            ),
        )
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

    async fn transition(&mut self, journal: Journal) -> Result<()> {
        self.generation = self
            .store
            .replace(&self.key, self.generation, &journal)
            .await?
            .ok_or(OwnershipLost)?;
        self.journal = journal;
        self.next_heartbeat = tokio::time::Instant::now() + HEARTBEAT;
        Ok(())
    }

    fn check_deadline(&self) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            bail!("Transcode attempt exceeded its preparation deadline");
        }
        Ok(())
    }

    pub(crate) async fn confirm(&mut self) -> Result<()> {
        self.check_deadline()?;
        if !matches!(self.journal.phase, Phase::Preparing) {
            bail!("Transcode has an unconfirmed publication");
        }
        self.transition(self.journal.clone()).await
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
        if !matches!(self.journal.phase, Phase::Preparing) {
            bail!("Cannot verify an unconfirmed publication");
        }
        self.transition(Journal::default()).await
    }

    pub(crate) async fn begin_write(&mut self, gcs: bool, key: &str, id: &str) -> Result<()> {
        self.check_deadline()?;
        if !matches!(self.journal.phase, Phase::Preparing) {
            bail!("Cannot begin another write with an unconfirmed publication");
        }
        self.transition(Journal {
            dirty: self.journal.dirty.max(self.intent),
            phase: Phase::Writing {
                gcs,
                key: key.to_owned(),
                id: id.to_owned(),
            },
        })
        .await
    }

    pub(crate) async fn end_write(&mut self) -> Result<()> {
        self.transition(Journal {
            phase: Phase::Preparing,
            ..self.journal.clone()
        })
        .await
    }

    pub(crate) async fn finish(mut self, success: bool) -> Result<()> {
        if matches!(self.journal.phase, Phase::Writing { .. }) {
            count("recovery_failed");
            return Err(anyhow!(
                "Publication outcome unconfirmed; retained transcode lock"
            ));
        }
        if !success && self.journal.dirty != Dirty::Clean {
            return self
                .transition(Journal {
                    phase: Phase::Retry,
                    ..self.journal.clone()
                })
                .await;
        }
        let deletion = tokio::time::timeout(
            CONTROL_TIMEOUT,
            self.store.client.delete_object(&DeleteObjectRequest {
                bucket: self.store.bucket.clone(),
                object: self.key,
                if_generation_match: Some(self.generation),
                ..Default::default()
            }),
        )
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
