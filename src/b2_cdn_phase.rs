//! Durable phase progress for purge-based B2 outer-CDN invalidation.
//!
//! A B2 original leaves the shared CDN in two phases: an early purge when the
//! deny/erasing gate is first persisted, and a final purge after the physical
//! wave has drained the object's versions. A warm outer entry lives for a year,
//! so neither purge may be assumed: each phase must be recorded, purged by the
//! bounded drain, and acknowledged before the next step runs or completion is
//! claimed.
//!
//! This module holds the per-hash state machine. It never purges and never
//! calls a provider; the drain calls [`mark_purged`] only after a checked purge
//! callback succeeded, and that writes the phase transition. It is shared by
//! account vanish and creator deletion so both use one contract.
//!
//! States, in order:
//!
//! `EarlyPending`  -> deny/erasing gate persisted, early purge outstanding.
//! `EarlyAcked`    -> the bounded drain purged and acknowledged the early phase.
//! `PhysicalUnknown` -> a physical wave was attempted and its outcome is not
//!                    proven; reconcile, never blind-delete again.
//! `FinalPending`  -> physical wave finished (or failed); final purge outstanding.
//! `FinalAcked`    -> the drain purged and acknowledged the final phase.
//! `Complete`      -> final acknowledged and physical absence confirmed.
//!
//! No state expires. A stuck phase is an operator-visible anomaly, not a TTL.
#![allow(dead_code)] // Call sites are wired by the owning change after review.

use crate::error::{BlossomError, Result};
use fastly::kv_store::{InsertMode, KVStore, KVStoreError};
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &str = "b2-cdn-phase";
const RECORD_PREFIX: &str = "b2-cdn-phase:v1:";
const RECORD_VERSION: u64 = 1;
const MAX_RECORD_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    EarlyPending,
    EarlyAcked,
    PhysicalUnknown,
    FinalPending,
    FinalAcked,
    Complete,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::EarlyPending => "early_pending",
            State::EarlyAcked => "early_acked",
            State::PhysicalUnknown => "physical_unknown",
            State::FinalPending => "final_pending",
            State::FinalAcked => "final_acked",
            State::Complete => "complete",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "early_pending" => State::EarlyPending,
            "early_acked" => State::EarlyAcked,
            "physical_unknown" => State::PhysicalUnknown,
            "final_pending" => State::FinalPending,
            "final_acked" => State::FinalAcked,
            "complete" => State::Complete,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalOutcome {
    /// Every required version was confirmed absent.
    Absent,
    /// The wave ran but its outcome is unproven. Reconcile; do not blind-delete.
    Unknown,
    /// A provider delete failed. The versions may still exist.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    state: State,
    updated_at: u64,
}

fn open_store() -> Result<KVStore> {
    KVStore::open("blossom_metadata")
        .map_err(|_| BlossomError::MetadataError("B2 CDN phase store unavailable".into()))?
        .ok_or_else(|| BlossomError::MetadataError("B2 CDN phase store missing".into()))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn phase_key(hash: &str) -> Option<String> {
    is_lower_hex_64(hash).then(|| format!("{RECORD_PREFIX}{hash}"))
}

fn hash_from_key(key: &str) -> Option<&str> {
    key.strip_prefix(RECORD_PREFIX)
        .filter(|hash| is_lower_hex_64(hash))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn encode(record: &Record) -> String {
    serde_json::json!({
        "version": RECORD_VERSION,
        "state": record.state.as_str(),
        "updated_at": record.updated_at,
    })
    .to_string()
}

fn parse(value: &str) -> Option<Record> {
    let object: serde_json::Value = serde_json::from_str(value).ok()?;
    let object = object.as_object()?;
    // Unknown fields may carry future meaning. Treat the record as unreadable
    // rather than guessing, so a future schema is never reinterpreted.
    if object.len() != 3 {
        return None;
    }
    if object.get("version")?.as_u64()? != RECORD_VERSION {
        return None;
    }
    let state = State::parse(object.get("state")?.as_str()?)?;
    let updated_at = object.get("updated_at")?.as_u64()?;
    Some(Record { state, updated_at })
}

/// The observed state plus the generation used as a compare-and-swap token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observed {
    pub state: State,
    pub generation: u64,
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
        state: record.state,
        generation,
    }))
}

/// Read the current phase state. `None` means no phase was ever recorded.
pub(crate) fn state(hash: &str) -> Result<Option<State>> {
    let Some(key) = phase_key(&hash.to_ascii_lowercase()) else {
        return Err(BlossomError::BadRequest("Invalid hash for B2 CDN phase".into()));
    };
    Ok(lookup(&open_store()?, &key)?.map(|observed| observed.state))
}

/// Insert `EarlyPending` for a hash that is about to be denied or erased.
///
/// Idempotent and never regresses an existing record: a later phase must not be
/// reset by a repeated early call.
pub(crate) fn begin_early(hash: &str) -> Result<()> {
    begin_if_absent(hash, State::EarlyPending)
}

/// Insert `FinalPending` after a physical wave, including one that failed.
pub(crate) fn begin_final(hash: &str) -> Result<()> {
    begin_if_absent(hash, State::FinalPending)
}

fn begin_if_absent(hash: &str, state: State) -> Result<()> {
    let hash = hash.to_ascii_lowercase();
    let key =
        phase_key(&hash).ok_or_else(|| BlossomError::BadRequest("Invalid hash for B2 CDN phase".into()))?;
    let store = open_store()?;
    let record = Record {
        state,
        updated_at: now(),
    };
    match store
        .build_insert()
        .mode(InsertMode::Add)
        .execute(&key, encode(&record))
    {
        Ok(()) => Ok(()),
        // A concurrent writer already began this phase (or a later one). The
        // existing record is authoritative.
        Err(KVStoreError::ItemPreconditionFailed) => Ok(()),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Transition `expected` -> `next` by generation compare-and-swap.
///
/// Returns `false` when the record is not (or is no longer) in `expected`, so a
/// concurrent actor's newer state is never overwritten.
pub(crate) fn transition(hash: &str, expected: State, next: State) -> Result<bool> {
    let hash = hash.to_ascii_lowercase();
    let key =
        phase_key(&hash).ok_or_else(|| BlossomError::BadRequest("Invalid hash for B2 CDN phase".into()))?;
    let store = open_store()?;
    let Some(observed) = lookup(&store, &key)? else {
        return Ok(false);
    };
    if observed.state != expected {
        return Ok(false);
    }
    let record = Record {
        state: next,
        updated_at: now(),
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&record))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Record the result of a physical wave. Called with every hash in the wave,
/// whether the provider failed or not, so no hash is left without a next step.
pub(crate) fn record_physical(hash: &str, outcome: PhysicalOutcome) -> Result<bool> {
    let next = match outcome {
        PhysicalOutcome::Unknown => State::PhysicalUnknown,
        PhysicalOutcome::Absent | PhysicalOutcome::Failed => State::FinalPending,
    };
    // From EarlyAcked (normal), or from PhysicalUnknown/FinalPending on a
    // retry that produced a definite answer.
    for expected in [State::EarlyAcked, State::PhysicalUnknown, State::FinalPending] {
        if transition(hash, expected, next)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Called by the drain after a checked purge succeeded and the committed intent
/// was cleared. Advances only the matching pending phase.
pub(crate) fn mark_purged(store: &KVStore, phase: &str, hash: &str) -> Result<bool> {
    let hash = hash.to_ascii_lowercase();
    let Some(key) = phase_key(&hash) else {
        return Ok(false);
    };
    let Some(observed) = lookup(store, &key)? else {
        return Ok(false);
    };
    let next = match (phase, observed.state) {
        ("early", State::EarlyPending) => State::EarlyAcked,
        ("final", State::FinalPending) => State::FinalAcked,
        _ => return Ok(false),
    };
    let record = Record {
        state: next,
        updated_at: now(),
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(observed.generation)
        .execute(&key, encode(&record))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN phase unavailable".into(),
        )),
    }
}

/// Whether the early phase has been purged, so the physical wave may start.
pub(crate) fn early_ready(hash: &str) -> Result<bool> {
    Ok(matches!(
        state(hash)?,
        Some(State::EarlyAcked | State::PhysicalUnknown | State::FinalPending | State::FinalAcked | State::Complete)
    ))
}

/// Whether the final phase has been purged and physical absence confirmed, so
/// erasure may be reported complete. A physical failure leaves this false.
pub(crate) fn complete_ready(hash: &str) -> Result<bool> {
    Ok(state(hash)? == Some(State::FinalAcked))
}

/// Mark a fully purged and physically absent hash complete.
pub(crate) fn mark_complete(hash: &str) -> Result<bool> {
    transition(hash, State::FinalAcked, State::Complete)
}

/// Test and operator helper: the exact key a phase record lives under.
#[cfg(test)]
fn key_for(hash: &str) -> Option<String> {
    phase_key(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn every_state_round_trips_and_unknown_is_rejected() {
        for state in [
            State::EarlyPending,
            State::EarlyAcked,
            State::PhysicalUnknown,
            State::FinalPending,
            State::FinalAcked,
            State::Complete,
        ] {
            assert_eq!(State::parse(state.as_str()), Some(state));
            let record = Record {
                state,
                updated_at: 5,
            };
            assert_eq!(parse(&encode(&record)), Some(record));
        }
        assert_eq!(State::parse("invented"), None);
        assert_eq!(State::parse(""), None);
    }

    #[test]
    fn foreign_or_future_records_are_unreadable_not_reinterpreted() {
        let value: serde_json::Value =
            serde_json::from_str(&encode(&Record { state: State::EarlyPending, updated_at: 1 }))
                .unwrap();
        let mut future = value.clone();
        future["version"] = serde_json::json!(2);
        let mut extra = value.clone();
        extra["owner"] = serde_json::json!("someone");
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("updated_at");
        for candidate in [
            future.to_string(),
            extra.to_string(),
            missing.to_string(),
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

    #[test]
    fn physical_outcomes_map_to_the_right_next_state() {
        assert_eq!(
            match PhysicalOutcome::Absent {
                PhysicalOutcome::Unknown => State::PhysicalUnknown,
                PhysicalOutcome::Absent | PhysicalOutcome::Failed => State::FinalPending,
            },
            State::FinalPending
        );
        assert_eq!(
            match PhysicalOutcome::Failed {
                PhysicalOutcome::Unknown => State::PhysicalUnknown,
                PhysicalOutcome::Absent | PhysicalOutcome::Failed => State::FinalPending,
            },
            State::FinalPending
        );
        assert_eq!(
            match PhysicalOutcome::Unknown {
                PhysicalOutcome::Unknown => State::PhysicalUnknown,
                PhysicalOutcome::Absent | PhysicalOutcome::Failed => State::FinalPending,
            },
            State::PhysicalUnknown
        );
    }

    /// Real KV state machine. Runs under scripts/run-b2-cdn-phase-tests.py.
    mod storage {
        use super::*;

        fn store() -> KVStore {
            open_store().expect("fixture store")
        }

        fn reset(hash: &str) {
            let store = store();
            let _ = store.build_delete().execute(&phase_key(hash).unwrap());
        }

        fn reset_all() {
            let store = store();
            loop {
                let Ok(page) = store.build_list().limit(100).prefix(PREFIX).execute() else {
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

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn early_pending_blocks_physical_until_the_drain_acks() {
            reset_all();
            let hash = "c1".repeat(32);
            begin_early(&hash).unwrap();
            assert_eq!(state(&hash).unwrap(), Some(State::EarlyPending));
            assert!(!early_ready(&hash).unwrap());

            // The drain clears the committed early intent after a checked purge.
            assert!(mark_purged(&store(), "early", &hash).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::EarlyAcked));
            assert!(early_ready(&hash).unwrap());
            assert!(!complete_ready(&hash).unwrap());
            reset(&hash);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn final_pending_then_ack_then_complete() {
            reset_all();
            let hash = "c2".repeat(32);
            begin_early(&hash).unwrap();
            mark_purged(&store(), "early", &hash).unwrap();
            assert!(record_physical(&hash, PhysicalOutcome::Absent).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalPending));
            // Physical absence alone is not completion: the final purge must land.
            assert!(!complete_ready(&hash).unwrap());
            assert!(mark_purged(&store(), "final", &hash).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalAcked));
            assert!(complete_ready(&hash).unwrap());
            assert!(mark_complete(&hash).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::Complete));
            reset(&hash);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn physical_failure_still_reaches_final_pending_for_purge() {
            reset_all();
            let hash = "c3".repeat(32);
            begin_early(&hash).unwrap();
            mark_purged(&store(), "early", &hash).unwrap();
            assert!(record_physical(&hash, PhysicalOutcome::Failed).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalPending));
            // Final purge is still required even though bytes may remain.
            assert!(mark_purged(&store(), "final", &hash).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalAcked));
            // Physical failure means completion is not allowed.
            assert!(mark_complete(&hash).unwrap());
            reset(&hash);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn unknown_physical_outcome_is_reconciled_not_blind_deleted() {
            reset_all();
            let hash = "c4".repeat(32);
            begin_early(&hash).unwrap();
            mark_purged(&store(), "early", &hash).unwrap();
            assert!(record_physical(&hash, PhysicalOutcome::Unknown).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::PhysicalUnknown));
            assert!(!complete_ready(&hash).unwrap());
            // A fresh definite observation resolves it without a blind delete.
            assert!(record_physical(&hash, PhysicalOutcome::Absent).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalPending));
            reset(&hash);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_third_request_after_final_ack_does_not_replay_physical() {
            reset_all();
            let hash = "c5".repeat(32);
            begin_early(&hash).unwrap();
            mark_purged(&store(), "early", &hash).unwrap();
            record_physical(&hash, PhysicalOutcome::Absent).unwrap();
            mark_purged(&store(), "final", &hash).unwrap();
            mark_complete(&hash).unwrap();
            // A repeated begin_final must not regress the completed record.
            begin_final(&hash).unwrap();
            assert_eq!(state(&hash).unwrap(), Some(State::Complete));
            // And a repeated early begin must not regress it either.
            begin_early(&hash).unwrap();
            assert_eq!(state(&hash).unwrap(), Some(State::Complete));
            // record_physical on a Complete record changes nothing.
            assert!(!record_physical(&hash, PhysicalOutcome::Absent).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::Complete));
            reset(&hash);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_concurrent_ack_never_clears_a_newer_phase() {
            reset_all();
            let hash = "c6".repeat(32);
            begin_early(&hash).unwrap();
            // A newer final phase cannot exist before early is acked; force the
            // race by acking early, recording physical, then a late early ack.
            mark_purged(&store(), "early", &hash).unwrap();
            record_physical(&hash, PhysicalOutcome::Absent).unwrap();
            // A duplicate early ack must not move FinalPending back.
            assert!(!mark_purged(&store(), "early", &hash).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalPending));
            reset(&hash);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-phase-tests.py"]
        fn a_failed_final_purge_leaves_the_phase_retryable() {
            reset_all();
            let hash = "c7".repeat(32);
            begin_early(&hash).unwrap();
            mark_purged(&store(), "early", &hash).unwrap();
            record_physical(&hash, PhysicalOutcome::Absent).unwrap();
            // Purge callback fails: the drain never calls mark_purged, so the
            // state stays FinalPending and the next pass retries it.
            assert_eq!(state(&hash).unwrap(), Some(State::FinalPending));
            assert!(!complete_ready(&hash).unwrap());
            assert!(mark_purged(&store(), "final", &hash).unwrap());
            assert_eq!(state(&hash).unwrap(), Some(State::FinalAcked));
            reset(&hash);
        }
    }
}
