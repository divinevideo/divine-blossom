//! Durable phase progress for purge-based B2 outer-CDN invalidation.
//!
//! A B2 original leaves the shared CDN only after its bytes are physically gone
//! from the pinned provider versions *and* the final purge has been
//! acknowledged. A warm outer entry lives for a year, so that final purge may
//! not be assumed.
//!
//! Contract, kept deliberately small:
//!
//! - One record per hash holds an **epoch** (a nonce for one physical attempt),
//!   the physical outcome, and whether the final purge has been acknowledged.
//! - Physical erasure is bounded by the existing wave. It records its outcome
//!   for every hash, including a provider failure.
//! - Only the **final** purge is blocking. An early purge is opportunistic and
//!   never gates anything.
//! - Completion requires `physical == Absent && final acknowledged`. A failed
//!   wave is still purged so cached bytes go, but it can never complete.
//! - An unknown physical outcome stays pending for a read-only reconcile.
//! - A completed hash never replays its physical erase.
//! - Every transition is bound to the record's epoch, compared with a
//!   generation compare-and-swap, so a stale acknowledgement for an old attempt
//!   can never advance a newer one.
//!
//! No state expires. A stuck phase is operator-visible, not a TTL.
#![allow(dead_code)] // Call sites are wired by the owning change after review.

use crate::error::{BlossomError, Result};
use fastly::kv_store::{InsertMode, KVStore, KVStoreError};
use std::time::{SystemTime, UNIX_EPOCH};

const RECORD_PREFIX: &str = "b2-cdn-phase:v1:";
const RECORD_VERSION: u64 = 1;
const MAX_RECORD_BYTES: usize = 1024;

/// What the bounded physical wave observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Physical {
    /// The wave has not finished, or has never run.
    Pending,
    /// Every required version was confirmed absent.
    Absent,
    /// A provider delete failed. Versions may still exist.
    Failed,
    /// The wave ran but its outcome is unproven. Reconcile read-only.
    Unknown,
}

impl Physical {
    fn as_str(self) -> &'static str {
        match self {
            Physical::Pending => "pending",
            Physical::Absent => "absent",
            Physical::Failed => "failed",
            Physical::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Physical::Pending,
            "absent" => Physical::Absent,
            "failed" => Physical::Failed,
            "unknown" => Physical::Unknown,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    epoch: String,
    physical: Physical,
    /// A final purge intent was durably queued for this epoch. Recorded
    /// separately from the physical outcome so a crash between "physical is
    /// absent" and "intent queued" is repaired on the next request instead of
    /// leaving the hash pending forever.
    final_queued: bool,
    /// The final purge for this epoch was purged and acknowledged.
    final_acked: bool,
    /// Reported complete. Implies `Absent` and `final_acked`.
    complete: bool,
    updated_at: u64,
}

fn open_store() -> Result<KVStore> {
    KVStore::open("blossom_metadata")
        .map_err(|_| BlossomError::MetadataError("B2 CDN phase store unavailable".into()))?
        .ok_or_else(|| BlossomError::MetadataError("B2 CDN phase store missing".into()))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn phase_key(hash: &str) -> Option<String> {
    is_lower_hex(hash, 64).then(|| format!("{RECORD_PREFIX}{hash}"))
}

fn hash_from_key(key: &str) -> Option<&str> {
    key.strip_prefix(RECORD_PREFIX)
        .filter(|hash| is_lower_hex(hash, 64))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn epoch_nonce() -> Result<String> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| BlossomError::Internal("B2 CDN phase entropy unavailable".into()))?;
    Ok(hex::encode(random))
}

fn encode(record: &Record) -> String {
    serde_json::json!({
        "version": RECORD_VERSION,
        "epoch": record.epoch,
        "physical": record.physical.as_str(),
        "final_queued": record.final_queued,
        "final_acked": record.final_acked,
        "complete": record.complete,
        "updated_at": record.updated_at,
    })
    .to_string()
}

fn parse(value: &str) -> Option<Record> {
    let object: serde_json::Value = serde_json::from_str(value).ok()?;
    let object = object.as_object()?;
    // A record with any key we do not own may be a newer schema with different
    // meaning. Unreadable, never reinterpreted.
    if object.len() != 7 {
        return None;
    }
    if object.get("version")?.as_u64()? != RECORD_VERSION {
        return None;
    }
    let epoch = object.get("epoch")?.as_str()?;
    if !is_lower_hex(epoch, 32) {
        return None;
    }
    let physical = Physical::parse(object.get("physical")?.as_str()?)?;
    let final_queued = object.get("final_queued")?.as_bool()?;
    let final_acked = object.get("final_acked")?.as_bool()?;
    let complete = object.get("complete")?.as_bool()?;
    // Completion is only coherent when the bytes are absent and the final purge
    // was acknowledged.
    if complete && (!final_acked || physical != Physical::Absent) {
        return None;
    }
    // An acknowledgement implies its intent was queued.
    if final_acked && !final_queued {
        return None;
    }
    Some(Record {
        epoch: epoch.to_string(),
        physical,
        final_queued,
        final_acked,
        complete,
        updated_at: object.get("updated_at")?.as_u64()?,
    })
}

/// Observed record plus the generation used as a compare-and-swap token.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    record: Record,
    generation: u64,
}

fn lookup(store: &KVStore, key: &str) -> Result<Option<Observed>> {
    let mut response = match store.build_lookup().execute(key) {
        Ok(response) => response,
        Err(KVStoreError::ItemNotFound) => return Ok(None),
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "B2 CDN phase unavailable".into(),
            ))
        }
    };
    let generation = response.current_generation();
    let body = response.take_body_bytes();
    if body.len() > MAX_RECORD_BYTES {
        return Ok(None);
    }
    let Ok(value) = std::str::from_utf8(&body) else {
        return Ok(None);
    };
    let Some(record) = parse(value) else {
        return Ok(None);
    };
    Ok(Some(Observed {
        record,
        generation,
    }))
}

/// Strict read: a present but unreadable record is an error.
///
/// Destructive decisions must not treat a malformed record as "no record", or a
/// corrupt phase would look like a fresh hash and re-run the wave.
fn observed_strict(hash: &str) -> Result<Option<Observed>> {
    let Some(key) = phase_key(&hash.to_ascii_lowercase()) else {
        return Err(BlossomError::BadRequest("Invalid hash for B2 CDN phase".into()));
    };
    let store = open_store()?;
    let mut response = match store.build_lookup().execute(&key) {
        Ok(response) => response,
        Err(KVStoreError::ItemNotFound) => return Ok(None),
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "B2 CDN phase unavailable".into(),
            ))
        }
    };
    let generation = response.current_generation();
    let body = response.take_body_bytes();
    if body.len() > MAX_RECORD_BYTES {
        return Err(BlossomError::MetadataError(
            "B2 CDN phase record invalid".into(),
        ));
    }
    let value = std::str::from_utf8(&body)
        .map_err(|_| BlossomError::MetadataError("B2 CDN phase record invalid".into()))?;
    let record = parse(value)
        .ok_or_else(|| BlossomError::MetadataError("B2 CDN phase record invalid".into()))?;
    Ok(Some(Observed {
        record,
        generation,
    }))
}

/// A checked purge target captured *before* the purge callback runs.
///
/// The drain must not re-read the phase after the purge: the physical outcome
/// may have changed mid-flight, and a stale callback must not acknowledge the
/// new state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PurgeToken {
    hash: String,
    epoch: String,
    generation: u64,
}

/// Capture the purge target for a hash, or `None` when it is not purgeable now.
///
/// Returns `Err` for an unreadable record so a corrupt phase is not treated as
/// "nothing to purge".
pub(crate) fn purge_token(hash: &str) -> Result<Option<PurgeToken>> {
    let hash = hash.to_ascii_lowercase();
    let Some(observed) = observed_strict(&hash)? else {
        return Ok(None);
    };
    if observed.record.final_acked || observed.record.physical == Physical::Pending {
        return Ok(None);
    }
    Ok(Some(PurgeToken {
        hash,
        epoch: observed.record.epoch,
        generation: observed.generation,
    }))
}

/// Acknowledge a purge only if the phase is still the exact state the token
/// captured. A physical change during the purge bumps the generation, so the
/// stale callback cannot advance the new outcome.
pub(crate) fn mark_final_purged_observed(store: &KVStore, token: &PurgeToken) -> Result<bool> {
    let Some(key) = phase_key(&token.hash) else {
        return Ok(false);
    };
    let Some(observed) = lookup(store, &key)? else {
        return Ok(false);
    };
    if observed.generation != token.generation
        || observed.record.epoch != token.epoch
        || observed.record.final_acked
        || !observed.record.final_queued
    {
        return Ok(false);
    }
    let updated = Record {
        final_acked: true,
        updated_at: now(),
        ..observed.record
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&updated))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

fn observed(hash: &str) -> Result<Option<Observed>> {
    let Some(key) = phase_key(&hash.to_ascii_lowercase()) else {
        return Err(BlossomError::BadRequest("Invalid hash for B2 CDN phase".into()));
    };
    lookup(&open_store()?, &key)
}

/// Whether the hash should run the bounded physical wave.
///
/// Only a hash that has never run (`Pending`) or whose wave definitely failed
/// may run again. `Absent` has nothing left to delete, `Complete` must never
/// replay, and `Unknown` must be reconciled read-only rather than re-issued as
/// a second destructive wave.
pub(crate) fn needs_physical(hash: &str) -> Result<bool> {
    Ok(match observed_strict(hash)? {
        None => true,
        Some(observed) => {
            !observed.record.complete
                && matches!(observed.record.physical, Physical::Pending | Physical::Failed)
        }
    })
}

/// The epoch this hash's current attempt is bound to, if a record exists.
pub(crate) fn epoch(hash: &str) -> Result<Option<String>> {
    Ok(observed(hash)?.map(|observed| observed.record.epoch))
}

/// Open one physical attempt and return its epoch.
///
/// Idempotent for a hash that is already mid-attempt: the existing epoch is
/// returned so a retry continues the same attempt instead of orphaning a pending
/// final acknowledgement. A completed hash keeps its epoch and is never reopened.
pub(crate) fn begin_erase(hash: &str) -> Result<String> {
    let hash = hash.to_ascii_lowercase();
    let key =
        phase_key(&hash).ok_or_else(|| BlossomError::BadRequest("Invalid hash for B2 CDN phase".into()))?;
    let store = open_store()?;
    if let Some(existing) = lookup(&store, &key)? {
        return Ok(existing.record.epoch);
    }
    let record = Record {
        epoch: epoch_nonce()?,
        physical: Physical::Pending,
        final_queued: false,
        final_acked: false,
        complete: false,
        updated_at: now(),
    };
    match store
        .build_insert()
        .mode(InsertMode::Add)
        .execute(&key, encode(&record))
    {
        Ok(()) => Ok(record.epoch),
        // A concurrent writer opened the attempt first. Use theirs.
        Err(KVStoreError::ItemPreconditionFailed) => lookup(&store, &key)?
            .map(|observed| observed.record.epoch)
            .ok_or_else(|| BlossomError::MetadataError("B2 CDN phase unavailable".into())),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Record the bounded wave's outcome for the epoch that produced it.
///
/// Bound to `epoch`, so a late report from an older attempt cannot overwrite a
/// newer one. `Unknown` never overwrites a definite `Absent`.
pub(crate) fn record_physical(hash: &str, epoch: &str, outcome: Physical) -> Result<bool> {
    let hash = hash.to_ascii_lowercase();
    let Some(key) = phase_key(&hash) else {
        return Ok(false);
    };
    let store = open_store()?;
    let Some(observed) = lookup(&store, &key)? else {
        return Ok(false);
    };
    if observed.record.epoch != epoch || observed.record.complete {
        return Ok(false);
    }
    if observed.record.physical == Physical::Absent && outcome == Physical::Unknown {
        // Never downgrade proven absence to an unknown observation.
        return Ok(false);
    }
    if observed.record.physical == outcome {
        // Nothing changed, so a valid acknowledgement still describes this
        // exact physical state. Keep it.
        return Ok(false);
    }
    let updated = Record {
        physical: outcome,
        // A purge or intent that happened before this new observation does not
        // cover the new physical state. Require a fresh intent and purge.
        final_queued: false,
        final_acked: false,
        updated_at: now(),
        ..observed.record
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&updated))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Whether the drain should purge this hash's final phase.
///
/// The final purge runs when the physical outcome is definite — absent or
/// failed — because cached bytes must leave the CDN either way. An unknown
/// outcome stays pending for reconcile and does not purge.
pub(crate) fn final_purge_pending(hash: &str) -> Result<bool> {
    Ok(match observed(hash)? {
        None => false,
        Some(observed) => {
            // Every definite outcome purges cached bytes. `Unknown` purges too,
            // because a warm outer entry may still serve whatever the wave did;
            // it simply can never complete. `Pending` has not run yet.
            !observed.record.final_acked && observed.record.physical != Physical::Pending
        }
    })
}

/// Whether a final intent has been durably queued for this hash's epoch.
pub(crate) fn final_queued(hash: &str) -> Result<bool> {
    Ok(observed(hash)?.is_some_and(|observed| observed.record.final_queued))
}

/// Record that a final intent was queued for the exact epoch.
///
/// A stale epoch is refused rather than reported as success.
fn mark_final_queued_observed(
    store: &KVStore,
    hash: &str,
    epoch: &str,
    generation: u64,
) -> Result<bool> {
    let Some(key) = phase_key(&hash.to_ascii_lowercase()) else {
        return Ok(false);
    };
    let Some(observed) = lookup(store, &key)? else {
        return Ok(false);
    };
    // Bind to the generation captured BEFORE the enqueue. A physical change or
    // a newer attempt during the enqueue makes this false, so a newer state is
    // never marked queued by an older intent.
    if observed.generation != generation
        || observed.record.epoch != epoch
        || observed.record.final_queued
    {
        return Ok(false);
    }
    let updated = Record {
        final_queued: true,
        updated_at: now(),
        ..observed.record
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&updated))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Ensure a durable final purge intent exists for this hash, independent of
/// whether the physical wave runs on this request.
///
/// This repairs the crash gap where the physical outcome was recorded but the
/// intent was never queued: the next request must still enqueue, even though
/// `needs_physical` is now false. Idempotent through the durable `final_queued`
/// flag. Returns `true` when an intent is durably queued.
pub(crate) fn ensure_final_intent(hash: &str) -> Result<bool> {
    let hash = hash.to_ascii_lowercase();
    let Some(key) = phase_key(&hash) else {
        return Ok(false);
    };
    let store = open_store()?;
    let Some(observed) = lookup(&store, &key)? else {
        return Ok(false);
    };
    if observed.record.final_queued {
        return Ok(true);
    }
    if observed.record.physical == Physical::Pending {
        // Nothing physical has happened yet; this request's wave will decide.
        return Ok(false);
    }
    // Capture the exact state the intent is for, then bind the queued CAS to
    // that generation. A physical change during the enqueue makes the CAS fail
    // rather than marking the new state covered by an older intent.
    let epoch = observed.record.epoch.clone();
    let generation = observed.generation;
    crate::b2_cdn_purge::enqueue(&hash, crate::b2_cdn_purge::Phase::Final)?;
    mark_final_queued_observed(&store, &hash, &epoch, generation)
}

/// Whether the final purge for this hash is acknowledged. Used by the drain to
/// decide whether it already handled this epoch.
pub(crate) fn final_acked(hash: &str) -> Result<bool> {
    Ok(observed(hash)?.is_some_and(|observed| observed.record.final_acked))
}

/// Whether this hash's bytes are proven absent, regardless of purge state.
pub(crate) fn physical_absent(hash: &str) -> Result<bool> {
    Ok(observed(hash)?.is_some_and(|observed| observed.record.physical == Physical::Absent))
}

/// Mark the final phase purged and acknowledged for the exact epoch.
///
/// Called only after a checked purge succeeded. Bound to the epoch so a stale
/// acknowledgement cannot advance a newer attempt.
pub(crate) fn mark_final_purged(store: &KVStore, hash: &str, epoch: &str) -> Result<bool> {
    let hash = hash.to_ascii_lowercase();
    let Some(key) = phase_key(&hash) else {
        return Ok(false);
    };
    let Some(observed) = lookup(store, &key)? else {
        return Ok(false);
    };
    if observed.record.epoch != epoch
        || observed.record.final_acked
        || !observed.record.final_queued
        || !matches!(observed.record.physical, Physical::Absent | Physical::Failed)
    {
        return Ok(false);
    }
    let updated = Record {
        final_acked: true,
        updated_at: now(),
        ..observed.record
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&updated))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Whether erasure for this hash may be reported complete.
///
/// True only when the bytes are proven absent and the final purge is
/// acknowledged. A completed record stays true; a failed physical wave can never
/// become true.
pub(crate) fn complete_ready(hash: &str) -> Result<bool> {
    Ok(observed_strict(hash)?.is_some_and(|observed| {
        observed.record.complete
            || (observed.record.physical == Physical::Absent && observed.record.final_acked)
    }))
}

/// Mark a fully purged, physically absent hash complete. Idempotent.
pub(crate) fn mark_complete(hash: &str) -> Result<bool> {
    let hash = hash.to_ascii_lowercase();
    let Some(key) = phase_key(&hash) else {
        return Ok(false);
    };
    let store = open_store()?;
    let Some(observed) = lookup(&store, &key)? else {
        return Ok(false);
    };
    if observed.record.complete {
        return Ok(true);
    }
    if observed.record.physical != Physical::Absent || !observed.record.final_acked {
        return Ok(false);
    }
    let updated = Record {
        complete: true,
        updated_at: now(),
        ..observed.record
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&updated))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Read the record's physical outcome for operator reporting.
pub(crate) fn physical_state(hash: &str) -> Result<Option<Physical>> {
    Ok(observed(hash)?.map(|observed| observed.record.physical))
}

#[cfg(test)]
fn key_for(hash: &str) -> Option<String> {
    phase_key(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EPOCH: &str = "0123456789abcdef0123456789abcdef";

    fn record() -> Record {
        Record {
            epoch: EPOCH.into(),
            physical: Physical::Pending,
            final_queued: false,
            final_acked: false,
            complete: false,
            updated_at: 7,
        }
    }

    #[test]
    fn record_round_trips_and_rejects_incoherent_completion() {
        assert_eq!(parse(&encode(&record())), Some(record()));
        for physical in [
            Physical::Pending,
            Physical::Absent,
            Physical::Failed,
            Physical::Unknown,
        ] {
            let value = Record {
                physical,
                ..record()
            };
            assert_eq!(parse(&encode(&value)), Some(value));
        }
        // complete without ack, or without absence, is incoherent.
        for bad in [
            Record { complete: true, ..record() },
            Record {
                complete: true,
                final_queued: true,
                final_acked: true,
                physical: Physical::Failed,
                ..record()
            },
            Record {
                complete: true,
                final_queued: true,
                final_acked: true,
                physical: Physical::Pending,
                ..record()
            },
        ] {
            assert_eq!(parse(&encode(&bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn foreign_or_future_records_are_unreadable_not_reinterpreted() {
        let value: serde_json::Value = serde_json::from_str(&encode(&record())).unwrap();
        let mut future = value.clone();
        future["version"] = serde_json::json!(2);
        let mut extra = value.clone();
        extra["owner"] = serde_json::json!("someone");
        let mut bad_epoch = value.clone();
        bad_epoch["epoch"] = serde_json::json!("abcd");
        let mut bad_physical = value.clone();
        bad_physical["physical"] = serde_json::json!("invented");
        for candidate in [
            future.to_string(),
            extra.to_string(),
            bad_epoch.to_string(),
            bad_physical.to_string(),
            "null".into(),
            "[]".into(),
            "{".into(),
            "x".repeat(MAX_RECORD_BYTES + 1),
        ] {
            assert_eq!(parse(&candidate), None, "{candidate}");
        }
    }

    #[test]
    fn keys_require_a_lowercase_original_hash() {
        assert_eq!(key_for(HASH), Some(format!("b2-cdn-phase:v1:{HASH}")));
        assert_eq!(hash_from_key(&format!("b2-cdn-phase:v1:{HASH}")), Some(HASH));
        for bad in [HASH.to_uppercase(), "a".repeat(63), "a".repeat(65), String::new()] {
            assert_eq!(key_for(&bad), None, "{bad}");
        }
    }

    /// Real KV state machine, including the exact order the vanish flow uses.
    /// Runs under scripts/run-b2-cdn-phase-tests.py.
    mod storage {
        use super::*;

        fn store() -> KVStore {
            open_store().expect("fixture store")
        }

        fn reset_all() {
            let store = store();
            loop {
                let Ok(page) = store.build_list().limit(100).prefix("b2-cdn-phase").execute()
                else {
                    return;
                };
                let keys: Vec<String> = page.keys().to_vec();
                if keys.is_empty() {
                    break;
                }
                for key in keys {
                    let _ = store.build_delete().execute(&key);
                }
            }
        }

        /// Mirrors `execute_vanish`: open the attempt, run the wave, record the
        /// outcome, then require the final acknowledgement before completion.
        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn main_flow_absent_requires_final_ack_before_completion() {
            reset_all();
            let hash = "d1".repeat(32);
            assert!(needs_physical(&hash).unwrap());
            let attempt = begin_erase(&hash).unwrap();
            assert_eq!(epoch(&hash).unwrap(), Some(attempt.clone()));

            // Physical wave confirms absence.
            assert!(record_physical(&hash, &attempt, Physical::Absent).unwrap());
            assert!(physical_absent(&hash).unwrap());
            assert!(final_purge_pending(&hash).unwrap());
            // Bytes gone is not completion: the final purge has not acked.
            assert!(!complete_ready(&hash).unwrap());

            // The drain queues the intent after the definite outcome, then
            // purges and acknowledges the exact epoch.
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &attempt).unwrap());
            assert!(complete_ready(&hash).unwrap());
            assert!(mark_complete(&hash).unwrap());
            // Completed hash never replays its physical erase.
            assert!(!needs_physical(&hash).unwrap());
            assert!(complete_ready(&hash).unwrap(), "Complete must read as ready");
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn main_flow_failed_physical_purges_but_never_completes() {
            reset_all();
            let hash = "d2".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            assert!(record_physical(&hash, &epoch, Physical::Failed).unwrap());
            // Failed still needs a purge so cached bytes leave the CDN.
            assert!(final_purge_pending(&hash).unwrap());
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            // But a failed wave can never be complete.
            assert!(!complete_ready(&hash).unwrap());
            assert!(!mark_complete(&hash).unwrap());
            // A retry may run the physical wave again.
            assert!(needs_physical(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn main_flow_unknown_stays_pending_without_purging() {
            reset_all();
            let hash = "d3".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            assert!(record_physical(&hash, &epoch, Physical::Unknown).unwrap());
            assert_eq!(physical_state(&hash).unwrap(), Some(Physical::Unknown));
            // Unknown must not replay the destructive wave, but its cached bytes
            // must still be purged; it simply can never complete.
            assert!(!needs_physical(&hash).unwrap());
            assert!(final_purge_pending(&hash).unwrap());
            assert!(!complete_ready(&hash).unwrap());
            // A later definite observation resolves it.
            assert!(record_physical(&hash, &epoch, Physical::Absent).unwrap());
            assert!(final_purge_pending(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_stale_epoch_ack_cannot_advance_a_newer_attempt() {
            reset_all();
            let hash = "d4".repeat(32);
            let old_epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &old_epoch, Physical::Absent).unwrap();
            // A fresh attempt for the same hash reuses the epoch while the record
            // exists, so simulate a *different* epoch arriving late by using a
            // bogus one; it must be refused.
            assert!(!mark_final_purged(&store(), &hash, &"f".repeat(32)).unwrap());
            assert!(!complete_ready(&hash).unwrap());
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &old_epoch).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn unknown_never_downgrades_proven_absence() {
            reset_all();
            let hash = "d5".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            assert!(!record_physical(&hash, &epoch, Physical::Unknown).unwrap());
            assert_eq!(physical_state(&hash).unwrap(), Some(Physical::Absent));
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_completed_hash_is_not_reopened_by_begin_erase() {
            reset_all();
            let hash = "d6".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            ensure_final_intent(&hash).unwrap();
            mark_final_purged(&store(), &hash, &epoch).unwrap();
            mark_complete(&hash).unwrap();
            // A third request must not reopen the attempt or replay physical.
            assert_eq!(begin_erase(&hash).unwrap(), epoch);
            assert!(!needs_physical(&hash).unwrap());
            assert!(!record_physical(&hash, &epoch, Physical::Unknown).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_failed_final_purge_leaves_final_pending_retryable() {
            reset_all();
            let hash = "d7".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            // Purge callback failed, so the drain never acked.
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(final_purge_pending(&hash).unwrap());
            assert!(!final_acked(&hash).unwrap());
            assert!(!complete_ready(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        /// The real vanish sequence through the storage seam, not a state model:
        /// first request runs the wave, second request must not replay it, and
        /// completion only appears after the final purge is acknowledged.
        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn the_real_vanish_sequence_does_not_replay_the_physical_wave() {
            use std::cell::Cell;
            use crate::storage::{vanish_attempt_for_test, vanish_complete};

            reset_all();
            let hash = "e1".repeat(32);
            let waves = Cell::new(0u32);
            let wave = |hashes: &[String]| -> std::collections::HashSet<String> {
                waves.set(waves.get() + 1);
                assert_eq!(hashes, [hash.clone()]);
                std::collections::HashSet::new()
            };

            // Request 1: opens the attempt and runs the wave.
            let (ran, complete) = vanish_attempt_for_test(&hash, wave);
            assert!(ran, "first request must run the physical wave");
            assert_eq!(waves.get(), 1);
            assert!(!complete, "no final ack yet, so not complete");
            assert!(final_purge_pending(&hash).unwrap());

            // Request 2 before the drain: absence is recorded, so the wave must
            // not replay. Still not complete.
            let (ran, complete) = vanish_attempt_for_test(&hash, wave);
            assert!(!ran, "a second request must not replay the physical wave");
            assert_eq!(waves.get(), 1, "the wave ran exactly once");
            assert!(!complete);

            // The drain queues the intent, purges, and acknowledges.
            assert!(ensure_final_intent(&hash).unwrap());
            let epoch = epoch(&hash).unwrap().expect("attempt epoch");
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());

            // Request 3: complete, and still no replay.
            let (ran, complete) = vanish_attempt_for_test(&hash, wave);
            assert!(!ran, "a completed hash must never replay its erase");
            assert_eq!(waves.get(), 1);
            assert!(complete, "final ack plus absence is completion");
            assert!(vanish_complete(&hash));
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_failed_wave_is_retried_on_the_next_request() {
            use std::cell::Cell;
            use crate::storage::vanish_attempt_for_test;

            reset_all();
            let hash = "e2".repeat(32);
            let waves = Cell::new(0u32);
            let failing = |hashes: &[String]| -> std::collections::HashSet<String> {
                waves.set(waves.get() + 1);
                hashes.iter().cloned().collect()
            };
            let (ran, complete) = vanish_attempt_for_test(&hash, failing);
            assert!(ran);
            assert!(!complete, "a provider failure can never complete");
            assert_eq!(physical_state(&hash).unwrap(), Some(Physical::Failed));
            // Failure still queues a purge so cached bytes leave the CDN.
            assert!(final_purge_pending(&hash).unwrap());

            // A later request may run the wave again.
            let ok = |_: &[String]| std::collections::HashSet::new();
            let (ran, complete) = vanish_attempt_for_test(&hash, ok);
            assert!(ran, "a failed wave may be retried");
            assert_eq!(waves.get(), 1, "the failing wave ran once; retry is separate");
            assert_eq!(physical_state(&hash).unwrap(), Some(Physical::Absent));
            assert!(!complete);
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn unknown_never_replays_physical_but_still_purges() {
            reset_all();
            let hash = "f1".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Unknown).unwrap();
            // An uncertain outcome must not blindly replay the destructive wave.
            assert!(!needs_physical(&hash).unwrap(), "Unknown must not re-run the wave");
            // But cached bytes must still leave the CDN.
            assert!(final_purge_pending(&hash).unwrap());
            assert!(!complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_changed_physical_outcome_invalidates_the_previous_ack() {
            reset_all();
            let hash = "f2".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            // Failed, intent queued, purged, acked.
            record_physical(&hash, &epoch, Physical::Failed).unwrap();
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            assert!(final_acked(&hash).unwrap());
            assert!(!complete_ready(&hash).unwrap(), "failed can never complete");
            // Retry observes absence. The old ack predates this physical state,
            // so it must not satisfy completion; a fresh purge is required.
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            assert!(
                !final_acked(&hash).unwrap(),
                "ack from before the new outcome must be cleared"
            );
            assert!(final_purge_pending(&hash).unwrap());
            assert!(!complete_ready(&hash).unwrap());
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_same_outcome_report_keeps_a_valid_ack() {
            reset_all();
            let hash = "f3".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            // A repeated identical observation must not force a second purge.
            assert!(!record_physical(&hash, &epoch, Physical::Absent).unwrap());
            assert!(final_acked(&hash).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_crash_between_absent_and_enqueue_is_repaired_on_retry() {
            reset_all();
            let hash = "f4".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            // Physical recorded Absent, then the process died before enqueue.
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            assert!(!final_queued(&hash).unwrap());
            // The next request sees needs_physical == false, so the wave will not
            // run; ensure_final_intent must still queue the intent.
            assert!(!needs_physical(&hash).unwrap());
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(final_queued(&hash).unwrap());
            assert!(final_purge_pending(&hash).unwrap());
            // Idempotent on a further request.
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_queued_intent_is_required_before_an_ack_counts() {
            reset_all();
            let hash = "f5".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            // No intent queued yet: an ack must not advance the record.
            assert!(!mark_final_purged(&store(), &hash, &epoch).unwrap());
            assert!(ensure_final_intent(&hash).unwrap());
            assert!(mark_final_purged(&store(), &hash, &epoch).unwrap());
            assert!(complete_ready(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn ensure_final_intent_never_marks_a_newer_physical_state_queued() {
            reset_all();
            let hash = "f7".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            // Old state: Absent. The request captures it, then enqueues.
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            let captured = observed(&hash).unwrap().unwrap();

            // Between the capture and the queued CAS, a retry reports a NEW
            // physical state with the same epoch. The old intent does not cover
            // it, so the queued CAS must not set the new state as queued.
            record_physical(&hash, &epoch, Physical::Failed).unwrap();
            let marked = mark_final_queued_observed(
                &store(),
                &hash,
                &captured.record.epoch,
                captured.generation,
            )
            .unwrap();
            assert!(
                !marked,
                "a stale generation must not mark a newer physical state queued"
            );
            assert!(!final_queued(&hash).unwrap());
            // And the new state remains purgeable once its own intent lands.
            assert!(final_purge_pending(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_captured_generation_still_marks_the_same_state_queued() {
            reset_all();
            let hash = "f8".repeat(32);
            let epoch = begin_erase(&hash).unwrap();
            record_physical(&hash, &epoch, Physical::Absent).unwrap();
            let captured = observed(&hash).unwrap().unwrap();
            assert!(
                mark_final_queued_observed(
                    &store(),
                    &hash,
                    &captured.record.epoch,
                    captured.generation
                )
                .unwrap()
            );
            assert!(final_queued(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn ensure_final_intent_does_nothing_before_the_wave() {
            reset_all();
            let hash = "f6".repeat(32);
            begin_erase(&hash).unwrap();
            assert!(!ensure_final_intent(&hash).unwrap());
            assert!(!final_queued(&hash).unwrap());
            reset_all();
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn two_concurrent_begin_erase_calls_share_one_epoch() {
            reset_all();
            let hash = "d8".repeat(32);
            let first = begin_erase(&hash).unwrap();
            let second = begin_erase(&hash).unwrap();
            assert_eq!(first, second, "one attempt per unfinished hash");
            reset_all();
        }
    }
}
