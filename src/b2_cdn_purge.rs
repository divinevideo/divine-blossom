//! Durable outbox for purge-based B2 outer-CDN invalidation.
//!
//! Warm outer-CDN entries live for a year. A policy or erasure change must
//! therefore record a durable intent *before* the mutation, and the cache must
//! be purged before the intent may be cleared. This module owns that record,
//! the bounded authenticated drain, and the generation compare-and-swap that
//! prevents a drain from clearing a record it did not read.
//!
//! Lifecycle:
//!
//! 1. `begin(hash)` writes one `prepared` record under a **per-attempt** key.
//!    Concurrent mutations of the same hash therefore never overwrite each
//!    other's intent, so no writer can lose its retry record. The mutation may
//!    not have happened yet, so a drainer must never clear a prepared record.
//! 2. The caller performs the policy or gate mutation.
//! 3. `commit(token)` transitions that exact record to `committed`.
//! 4. A drainer purges committed records and only then clears them, by
//!    generation compare-and-swap.
//!
//! A crash between steps 1 and 3 leaves a `prepared` record. It is retained and
//! reported so an operator sees the anomaly; it is never cleared on age alone.
//! Purge is idempotent, so a prepared record is safe to purge as a precaution,
//! but it stays outstanding until explicitly resolved.
//!
//! Multiple attempts for one hash are retained, so a drain may purge the same
//! hash more than once. That is deliberate: correctness beats deduplication,
//! and the drain limit bounds the subrequests per call.
//!
//! Scope: storage and drain mechanics only. Callers decide when an intent is
//! required and supply the checked purge callback. No provider call is made by
//! this module except through that callback.
#![allow(dead_code)] // Call sites are wired by the owning change after review.

use crate::error::{BlossomError, Result};
use fastly::http::Method;
use fastly::kv_store::{InsertMode, KVStore, KVStoreError};
use fastly::{Request, Response};
use std::time::{SystemTime, UNIX_EPOCH};

/// Durable queue records: `b2-cdn-purge:v1:{64 lowercase hex}:{32 lowercase hex}`.
///
/// The list prefix deliberately carries no colon. The control-plane listing API
/// rejects colon prefixes, and keeping the shape identical here means the same
/// queue can be inspected by the existing worker tooling.
const PREFIX: &str = "b2-cdn-purge";
const RECORD_PREFIX: &str = "b2-cdn-purge:v1:";
/// Kept outside `PREFIX` so a cursor row is never mistaken for an intent.
const CURSOR_KEY: &str = "b2-cdn-drain-cursor";
const RECORD_VERSION: u64 = 1;
/// Bounded so one drain call cannot spend the whole subrequest budget.
/// Each hash costs up to two URL purges and two key purges per round, twice,
/// so two hashes is 16 purge subrequests before KV listing, cursor and
/// conditional metadata calls. The independent budget audit set this ceiling.
const DEFAULT_DRAIN_LIMIT: usize = 2;
const MAX_DRAIN_LIMIT: usize = 2;
const MAX_RECORD_BYTES: usize = 4096;
const MAX_LIST_LIMIT: u32 = 100;
/// Durable purge acknowledgement receipts, keyed by operation phase and the
/// exact attempt. A receipt is evidence that a specific attempt's double purge
/// completed. It is never inferred from a missing queue record, and it is bound
/// to the attempt so an old completion cannot answer for a new operation.
/// Deliberately outside `PREFIX`: receipts are retained forever, and sharing
/// the queue prefix would make the drain spend its scan budget on them.
const RECEIPT_PREFIX: &str = "b2-cdn-ack";
const RECEIPT_BODY_MAX: usize = 2048;
/// Phases a caller may name. Anything else is refused rather than stored, so a
/// typo cannot silently create an unrecognised receipt namespace.
const PHASES: &[&str] = &["early", "final", "policy", "single"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordState {
    /// Intent recorded, mutation may not have landed. Never cleared by a drain.
    Prepared,
    /// Mutation committed. A drain may purge and then clear.
    Committed,
    /// Purged and cleared.
    Cleared,
}

/// Which revocation an intent belongs to.
///
/// `Single` is a policy or gate change with no physical wave. `Final` is the
/// blocking purge after a bounded physical erase: when its checked purge
/// succeeds the drain advances the hash's phase record and writes the receipt.
/// An early eviction is opportunistic and deliberately not a phase, so it can
/// never gate progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Single,
    Final,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Single => "single",
            Phase::Final => "final",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "single" => Phase::Single,
            "final" => Phase::Final,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    attempt: String,
    phase: Phase,
    requested_at: u64,
    committed_at: Option<u64>,
    cleared_at: Option<u64>,
    attempts: u32,
    state: RecordState,
}

/// Opaque handle returned by [`begin`] and consumed by [`commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    key: String,
    hash: String,
    attempt: String,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitOutcome {
    Committed,
    /// The record is gone or no longer this attempt. Nothing was written.
    Superseded,
}

/// One queue entry as the drain sees it: key plus the generation it was read at.
/// The generation is the compare-and-swap token for the later clear.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    key: String,
    hash: String,
    record: Record,
    generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Intent(Record),
    /// Unknown schema, future version, unknown state, malformed field type, or
    /// trailing fields. Retained and skipped, never deleted.
    Foreign,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DrainOutcome {
    /// Intents this pass purged and cleared.
    pub result: usize,
    /// Intents still outstanding: purge failures and superseded intents.
    pub pending: usize,
    /// Purge or completion failures.
    pub errors: usize,
    /// Prepared intents retained because the mutation is unproven. Reported so
    /// an operator can alert; never cleared here.
    pub unknown: usize,
}

/// Whether the outbox is in service.
///
/// True when admission is on *or* the purge host set exists. Invalidation must
/// survive a rollback that sets `b2_cdn_enabled` off, otherwise warm entries
/// lose their only eviction path. A missing credential is a drain-time failure,
/// never a reason to pretend the queue is disabled.
pub(crate) fn configured() -> bool {
    // Only successful reads proving BOTH keys absent can select the legacy
    // default. A store outage must not disable durable revocation while old
    // outer objects may still be serving. Checked purging then reports the
    // unavailable configuration and retains the intent instead of acknowledging.
    let Ok(store) = fastly::config_store::ConfigStore::try_open("blossom_config") else {
        return true;
    };
    let (Ok(flag), Ok(hosts)) = (
        store.try_get("b2_cdn_enabled"),
        store.try_get("b2_cdn_purge_hosts"),
    ) else {
        return true;
    };
    configured_from(flag.as_deref(), hosts.as_deref())
}

/// Pure core of [`configured`].
///
/// A *present* purge host set enables the outbox even when the value is empty:
/// an empty retained configuration is an error the drain must surface, never a
/// silent disable. Only an absent flag and absent host key mean "not in
/// service". A missing credential is likewise a drain-time failure.
fn configured_from(flag: Option<&str>, hosts: Option<&str>) -> bool {
    flag == Some("true") || hosts.is_some()
}

fn open_store() -> Result<KVStore> {
    KVStore::open("blossom_metadata")
        .map_err(|_| BlossomError::MetadataError("B2 CDN outbox store unavailable".into()))?
        .ok_or_else(|| BlossomError::MetadataError("B2 CDN outbox store missing".into()))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_hex_64(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn queue_key(hash: &str, attempt: &str) -> Option<String> {
    (is_lower_hex_64(hash) && is_lower_hex(attempt, 32))
        .then(|| format!("{RECORD_PREFIX}{hash}:{attempt}"))
}

/// Split a queue key into `(hash, attempt)`. Anything else is not ours.
fn queue_parts(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix(RECORD_PREFIX)?;
    let (hash, attempt) = rest.split_once(':')?;
    (is_lower_hex_64(hash) && is_lower_hex(attempt, 32)).then_some((hash, attempt))
}

fn requested_at() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn attempt_nonce() -> Result<String> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| BlossomError::Internal("B2 CDN outbox entropy unavailable".into()))?;
    Ok(hex::encode(random))
}

fn encode(record: &Record) -> String {
    serde_json::json!({
        "version": RECORD_VERSION,
        "state": match record.state {
            RecordState::Prepared => "prepared",
            RecordState::Committed => "committed",
            RecordState::Cleared => "cleared",
        },
        "attempt": record.attempt,
        "phase": record.phase.as_str(),
        "requested_at": record.requested_at,
        "committed_at": record.committed_at,
        "cleared_at": record.cleared_at,
        "attempts": record.attempts,
    })
    .to_string()
}

fn parse(value: &str) -> Parsed {
    let Ok(object) = serde_json::from_str::<serde_json::Value>(value) else {
        return Parsed::Foreign;
    };
    let Some(object) = object.as_object() else {
        return Parsed::Foreign;
    };
    // A record with any key we do not own may be a newer schema with different
    // meaning. Leave it for a reader that understands it.
    if object.len() != 8 {
        return Parsed::Foreign;
    }
    let version = object.get("version").and_then(|value| value.as_u64());
    let state = object.get("state").and_then(|value| value.as_str());
    let attempt = object.get("attempt").and_then(|value| value.as_str());
    let phase = object
        .get("phase")
        .and_then(|value| value.as_str())
        .and_then(Phase::parse);
    let requested_at = object.get("requested_at").and_then(|value| value.as_u64());
    let attempts = object.get("attempts").and_then(|value| value.as_u64());
    let timestamp = |name: &str| match object.get(name) {
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::Number(number)) => number.as_u64().map(Some),
        _ => None,
    };
    let (Some(committed_at), Some(cleared_at)) =
        (timestamp("committed_at"), timestamp("cleared_at"))
    else {
        return Parsed::Foreign;
    };
    let (Some(version), Some(state), Some(attempt), Some(phase), Some(requested_at), Some(attempts)) =
        (version, state, attempt, phase, requested_at, attempts)
    else {
        return Parsed::Foreign;
    };
    let state = match state {
        "prepared" => RecordState::Prepared,
        "committed" => RecordState::Committed,
        "cleared" => RecordState::Cleared,
        _ => return Parsed::Foreign,
    };
    if version != RECORD_VERSION || attempts > u64::from(u32::MAX) || !is_lower_hex(attempt, 32) {
        return Parsed::Foreign;
    }
    // A state and its timestamps must agree, or the record is not one we wrote.
    let consistent = match state {
        RecordState::Prepared => committed_at.is_none() && cleared_at.is_none(),
        RecordState::Committed => committed_at.is_some() && cleared_at.is_none(),
        RecordState::Cleared => cleared_at.is_some(),
    };
    if !consistent {
        return Parsed::Foreign;
    }
    Parsed::Intent(Record {
        attempt: attempt.to_string(),
        phase,
        requested_at,
        committed_at,
        cleared_at,
        attempts: attempts as u32,
        state,
    })
}

fn parse_drain_limit(raw: Option<&str>) -> Result<usize> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_DRAIN_LIMIT);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BlossomError::BadRequest("Invalid drain limit".into()));
    }
    let value: usize = trimmed
        .parse()
        .map_err(|_| BlossomError::BadRequest("Invalid drain limit".into()))?;
    if value == 0 || value > MAX_DRAIN_LIMIT {
        return Err(BlossomError::BadRequest("Invalid drain limit".into()));
    }
    Ok(value)
}

fn lookup(store: &KVStore, key: &str) -> Result<Option<Snapshot>> {
    let mut response = match store.build_lookup().execute(key) {
        Ok(response) => response,
        Err(KVStoreError::ItemNotFound) => return Ok(None),
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "B2 CDN purge record unavailable".into(),
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
    let Parsed::Intent(record) = parse(value) else {
        return Ok(None);
    };
    let Some((hash, attempt)) = queue_parts(key) else {
        return Ok(None);
    };
    // The body must describe the key it is stored under, or it is not coherent.
    if attempt != record.attempt {
        return Ok(None);
    }
    Ok(Some(Snapshot {
        key: key.to_string(),
        hash: hash.to_string(),
        record,
        generation,
    }))
}

/// Write the durable pre-mutation intent under a fresh per-attempt key.
///
/// Uses `Add` so two concurrent writers can never overwrite each other, then
/// re-reads the key to bind the token to the attempt actually stored. A token
/// is therefore only usable by the writer that created it.
pub(crate) fn begin(hash: &str) -> Result<Token> {
    begin_phase(hash, Phase::Single)
}

/// Begin an intent for a specific phase. `Early` and `Final` let the drain
/// advance the matching phase state machine after a checked purge.
pub(crate) fn begin_phase(hash: &str, phase: Phase) -> Result<Token> {
    let hash = hash.to_ascii_lowercase();
    if !is_lower_hex_64(&hash) {
        return Err(BlossomError::BadRequest(
            "Invalid hash for purge outbox".into(),
        ));
    }
    let attempt = attempt_nonce()?;
    let key = queue_key(&hash, &attempt)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash for purge outbox".into()))?;
    let record = Record {
        attempt: attempt.clone(),
        phase,
        requested_at: requested_at(),
        committed_at: None,
        cleared_at: None,
        attempts: 0,
        state: RecordState::Prepared,
    };
    let store = open_store()?;
    store
        .build_insert()
        .mode(InsertMode::Add)
        .execute(&key, encode(&record))
        .map_err(|_| BlossomError::MetadataError("B2 CDN purge intent unavailable".into()))?;

    let snapshot = lookup(&store, &key)?
        .ok_or_else(|| BlossomError::MetadataError("B2 CDN purge intent unavailable".into()))?;
    if snapshot.record.attempt != attempt || snapshot.record.state != RecordState::Prepared {
        return Err(BlossomError::MetadataError(
            "B2 CDN purge intent unavailable".into(),
        ));
    }
    Ok(Token {
        key,
        hash,
        attempt,
        generation: snapshot.generation,
    })
}

/// Begin and commit an intent in one step for a caller that already persisted
/// its policy or gate mutation. Returns the token so the caller can read the
/// phase receipt later.
///
/// Fails closed when the commit does not land, matching [`execute`]: a lost
/// intent is missing durability, not a benign supersede.
pub(crate) fn enqueue(hash: &str, phase: Phase) -> Result<Token> {
    let token = begin_phase(hash, phase)?;
    let store = open_store()?;
    match commit(&store, &token)? {
        CommitOutcome::Committed => Ok(token),
        CommitOutcome::Superseded => Err(BlossomError::MetadataError(
            "B2 CDN purge intent lost before commit; retry required".into(),
        )),
    }
}

/// Mark the exact prepared record committed, by generation compare-and-swap.
///
/// Returns [`CommitOutcome::Superseded`] when the record is gone or is no longer
/// this attempt. A later writer's intent is never touched.
pub(crate) fn commit(store: &KVStore, token: &Token) -> Result<CommitOutcome> {
    let Some(snapshot) = lookup(store, &token.key)? else {
        return Ok(CommitOutcome::Superseded);
    };
    if snapshot.generation != token.generation || snapshot.record.attempt != token.attempt {
        return Ok(CommitOutcome::Superseded);
    }
    if snapshot.record.state == RecordState::Committed {
        return Ok(CommitOutcome::Committed);
    }
    if snapshot.record.state != RecordState::Prepared {
        return Ok(CommitOutcome::Superseded);
    }
    let committed = Record {
        committed_at: Some(requested_at()),
        state: RecordState::Committed,
        ..snapshot.record
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(snapshot.generation)
        .execute(&snapshot.key, encode(&committed))
    {
        Ok(()) => Ok(CommitOutcome::Committed),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(CommitOutcome::Superseded),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN purge commit unavailable".into(),
        )),
    }
}

/// Compare-and-swap clear. Fails closed when the record changed since the
/// snapshot, so a record is never cleared at a generation it was not read at.
fn complete_observed(store: &KVStore, snapshot: &Snapshot) -> Result<bool> {
    let cleared = Record {
        cleared_at: Some(requested_at()),
        state: RecordState::Cleared,
        ..snapshot.record.clone()
    };
    match store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .if_generation_match(snapshot.generation)
        .execute(&snapshot.key, encode(&cleared))
    {
        Ok(()) => Ok(true),
        Err(KVStoreError::ItemPreconditionFailed) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "B2 CDN purge completion unavailable".into(),
        )),
    }
}


/// One durable receipt: `b2-cdn-purge-ack:v1:{phase}:{hash}:{attempt}`.
fn receipt_key(phase: &str, hash: &str, attempt: &str) -> Option<String> {
    (PHASES.contains(&phase) && is_lower_hex_64(hash) && is_lower_hex(attempt, 32))
        .then(|| format!("{RECEIPT_PREFIX}:v1:{phase}:{hash}:{attempt}"))
}

/// Split a receipt key into `(phase, hash, attempt)`.
fn receipt_parts(key: &str) -> Option<(&str, &str, &str)> {
    let rest = key.strip_prefix(RECEIPT_PREFIX)?.strip_prefix(":v1:")?;
    let mut parts = rest.split(':');
    let (phase, hash, attempt) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    (PHASES.contains(&phase) && is_lower_hex_64(hash) && is_lower_hex(attempt, 32))
        .then_some((phase, hash, attempt))
}

/// Store a durable acknowledgement that `phase`'s checked double purge
/// completed for this exact attempt. Call only after the purge callback
/// succeeded. Never write a receipt for a purge that did not succeed, and never
/// infer one from an absent queue record.
pub(crate) fn ack(token: &Token, phase: &str) -> Result<()> {
    ack_with_store(&open_store()?, token, phase)
}

fn ack_with_store(store: &KVStore, token: &Token, phase: &str) -> Result<()> {
    let key = receipt_key(phase, &token.hash, &token.attempt)
        .ok_or_else(|| BlossomError::BadRequest("Invalid purge acknowledgement".into()))?;
    let body = serde_json::json!({
        "version": RECORD_VERSION,
        "phase": phase,
        "hash": token.hash,
        "attempt": token.attempt,
        "acknowledged_at": requested_at(),
    })
    .to_string();
    if body.len() > RECEIPT_BODY_MAX {
        return Err(BlossomError::Internal(
            "Purge acknowledgement too large".into(),
        ));
    }
    store
        .build_insert()
        .mode(InsertMode::Overwrite)
        .execute(&key, body)
        .map_err(|_| BlossomError::MetadataError("Purge acknowledgement unavailable".into()))
}

/// Whether this exact attempt recorded a completed `phase` acknowledgement.
/// `false` means no receipt exists. It never means "assume purged".
pub(crate) fn acknowledged(store: &KVStore, token: &Token, phase: &str) -> Result<bool> {
    let key = receipt_key(phase, &token.hash, &token.attempt)
        .ok_or_else(|| BlossomError::BadRequest("Invalid purge acknowledgement".into()))?;
    match store.build_lookup().execute(&key) {
        Ok(mut response) => {
            let body = response.take_body_bytes();
            Ok(serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|value| {
                value.get("version").and_then(|v| v.as_u64()) == Some(RECORD_VERSION)
                    && value.get("phase").and_then(|v| v.as_str()) == Some(phase)
                    && value.get("hash").and_then(|v| v.as_str()) == Some(token.hash.as_str())
                    && value.get("attempt").and_then(|v| v.as_str())
                        == Some(token.attempt.as_str())
            }))
        }
        Err(KVStoreError::ItemNotFound) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "Purge acknowledgement unavailable".into(),
        )),
    }
}

/// Convenience wrapper: `begin`, run the mutation, then `commit`.
///
/// A mutation error leaves the prepared intent outstanding on purpose. The
/// mutation may have partially landed, so the record must keep the anomaly
/// visible rather than pretending the cache is safe.
pub(crate) fn execute<T>(hash: &str, mutation: impl FnOnce() -> Result<T>) -> Result<T> {
    let token = begin(hash)?;
    let value = mutation()?;
    let store = open_store()?;
    match commit(&store, &token)? {
        CommitOutcome::Committed => Ok(value),
        // Attempts have unique keys and a prepared record is never drained, so
        // a missing or mismatched record means the durable intent was lost.
        // The mutation already landed; returning Ok would hide that there is no
        // retry record, so fail closed and let the caller retry or reconcile.
        CommitOutcome::Superseded => Err(BlossomError::MetadataError(
            "B2 CDN purge intent lost before commit; retry required".into(),
        )),
    }
}

/// Durable drain progress: a provider page token plus the last queue key
/// handled inside that page.
///
/// Persisting the page token is what lets a drain skip retained cleared history
/// without rescanning it from the start. The within-page key makes a pass that
/// stops mid-page resume exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Progress {
    /// Provider page token to resume listing at, or `None` to start over.
    page: Option<String>,
    /// Last queue key handled in the current pass, used to skip within a page
    /// after a mid-page stop.
    after: Option<String>,
}

impl Progress {
    fn encode(&self) -> String {
        serde_json::json!({
            "version": 1,
            "page": self.page,
            "after": self.after,
        })
        .to_string()
    }

    /// Parse persisted progress. A malformed cursor is an error, never a silent
    /// reset: a blind restart would rescan retained history forever.
    fn parse(value: &str) -> Result<Self> {
        let object: serde_json::Value = serde_json::from_str(value)
            .map_err(|_| BlossomError::MetadataError("B2 CDN outbox cursor invalid".into()))?;
        let object = object
            .as_object()
            .ok_or_else(|| BlossomError::MetadataError("B2 CDN outbox cursor invalid".into()))?;
        if object.len() != 3 || object.get("version").and_then(|v| v.as_u64()) != Some(1) {
            return Err(BlossomError::MetadataError(
                "B2 CDN outbox cursor invalid".into(),
            ));
        }
        let field = |name: &str| -> Result<Option<String>> {
            match object.get(name) {
                Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(value)) if value.len() <= 4096 => {
                    Ok(Some(value.clone()))
                }
                _ => Err(BlossomError::MetadataError(
                    "B2 CDN outbox cursor invalid".into(),
                )),
            }
        };
        Ok(Progress {
            page: field("page")?,
            after: field("after")?,
        })
    }
}

fn cursor(store: &KVStore) -> Result<Progress> {
    let mut response = match store.build_lookup().execute(CURSOR_KEY) {
        Ok(response) => response,
        Err(KVStoreError::ItemNotFound) => return Ok(Progress::default()),
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "B2 CDN outbox cursor unavailable".into(),
            ))
        }
    };
    let body = response.take_body_bytes();
    let value = std::str::from_utf8(&body)
        .map_err(|_| BlossomError::MetadataError("B2 CDN outbox cursor invalid".into()))?;
    Progress::parse(value)
}

fn save_cursor(store: &KVStore, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => store
            .build_insert()
            .mode(InsertMode::Overwrite)
            .execute(CURSOR_KEY, value)
            .map_err(|_| {
                BlossomError::MetadataError("B2 CDN outbox cursor unavailable".into())
            }),
        None => match store.build_delete().execute(CURSOR_KEY) {
            Ok(()) | Err(KVStoreError::ItemNotFound) => Ok(()),
            Err(_) => Err(BlossomError::MetadataError(
                "B2 CDN outbox cursor unavailable".into(),
            )),
        },
    }
}

/// Process at most `limit` outstanding intents starting after the saved cursor.
///
/// Committed intents are purged then cleared. Prepared intents are purged as a
/// precaution and retained: the mutation is unproven, so clearing them could
/// hide a crash between intent and commit. Malformed, foreign, unknown and
/// cleared records are skipped but never deleted, and they advance the cursor
/// so they cannot starve records that sort after them.
///
/// Cleared records are retained as durable evidence. Pruning them is an
/// explicit operator action, not an automatic expiry.
fn drain(
    store: &KVStore,
    limit: usize,
    purge: impl Fn(&[String]) -> Result<()>,
) -> Result<DrainOutcome> {
    let mut outcome = DrainOutcome::default();
    // Resume at the persisted provider page and within-page key. This is what
    // lets a drain skip retained cleared history without rescanning it from the
    // start on every pass. A missing or malformed cursor fails closed rather
    // than silently restarting.
    let start = cursor(store)?;
    let mut page_token = start.page.clone();
    let after = start.after.clone();
    let mut processed = 0usize;
    let mut scanned = 0usize;
    let mut last_key: Option<String> = None;
    // Bounded so one call cannot walk unbounded retained history.
    const MAX_SCAN: usize = MAX_LIST_LIMIT as usize * 16;

    loop {
        let mut builder = store.build_list().limit(MAX_LIST_LIMIT).prefix(PREFIX);
        if let Some(token) = page_token.as_deref() {
            builder = builder.cursor(token);
        }
        let page = builder
            .execute()
            .map_err(|_| BlossomError::MetadataError("B2 CDN outbox listing unavailable".into()))?;
        let next_page = page.next_cursor();

        for key in page.keys() {
            scanned += 1;
            // Skip rows already handled in an earlier pass of this same page.
            if after.as_deref().is_some_and(|after| key.as_str() <= after) {
                continue;
            }
            if key == CURSOR_KEY || queue_parts(key).is_none() {
                // Not our row, but it is safely passed: advance past it.
                last_key = Some(key.clone());
                continue;
            }
            if processed >= limit {
                // Stop before handling this key, and resume AFTER the last key
                // actually handled. Recording this unprocessed key as done
                // would silently skip it.
                save_cursor(
                    store,
                    Some(
                        &Progress {
                            page: page_token.clone(),
                            after: last_key.clone(),
                        }
                        .encode(),
                    ),
                )?;
                return Ok(outcome);
            }
            last_key = Some(key.clone());
            let Some(snapshot) = lookup(store, key)? else {
                // Missing, oversized, malformed or foreign: retained and
                // skipped, but progress still advances past it.
                continue;
            };
            match snapshot.record.state {
                RecordState::Cleared => continue,
                RecordState::Prepared => {
                    // Safe to purge, never safe to clear: the mutation may not
                    // have landed. Retain and report for operator attention.
                    // Never rewrite it: the live writer still holds a token
                    // bound to this generation and must be able to commit.
                    processed += 1;
                    if purge(&[snapshot.hash.clone()]).is_err() {
                        outcome.errors += 1;
                    }
                    outcome.unknown += 1;
                    outcome.pending += 1;
                }
                RecordState::Committed => {
                    processed += 1;
                    // Capture the exact phase state BEFORE the purge callback.
                    // The physical outcome can change mid-purge, and a stale
                    // callback must never acknowledge the new state.
                    //
                    // A malformed or unreadable phase must not abort the whole
                    // pass: that would clear no cursor and starve every healthy
                    // row after it. Contain it to this row.
                    let phase_token = if snapshot.record.phase == Phase::Final {
                        match crate::b2_cdn_phase::purge_token(&snapshot.hash) {
                            Ok(token) => token,
                            Err(_) => {
                                // A malformed phase still owes a cache eviction:
                                // cached bytes must leave even when the physical
                                // state cannot be acknowledged. Purge as a
                                // precaution, then retain the intent and report
                                // the phase error. Never ack or clear.
                                let _ = purge(&[snapshot.hash.clone()]);
                                // Count this failed intent even when eviction
                                // succeeds: its phase is still unreadable.
                                outcome.errors += 1;
                                outcome.pending += 1;
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    match purge(&[snapshot.hash.clone()]) {
                        Ok(()) => {
                            if let Some(token) = phase_token {
                                if !crate::b2_cdn_phase::mark_final_purged_observed(store, &token)? {
                                    // The physical state changed while this purge
                                    // was in flight. The new state needs its own
                                    // purge, so leave the intent outstanding
                                    // instead of clearing it.
                                    outcome.pending += 1;
                                    continue;
                                }
                                let receipt = Token {
                                    key: snapshot.key.clone(),
                                    hash: snapshot.hash.clone(),
                                    attempt: snapshot.record.attempt.clone(),
                                    generation: snapshot.generation,
                                };
                                ack_with_store(store, &receipt, "final")?;
                            }
                            match complete_observed(store, &snapshot)? {
                                true => outcome.result += 1,
                                // The record changed while the purge was in
                                // flight. It needs its own pass.
                                false => outcome.pending += 1,
                            }
                        }
                        Err(_) => {
                            outcome.errors += 1;
                            outcome.pending += 1;
                        }
                    }
                }
            }
        }

        if scanned >= MAX_SCAN {
            // Scan budget spent: resume at the same page after the last key we
            // actually looked at, so no page is silently skipped.
            save_cursor(
                store,
                Some(
                    &Progress {
                        page: page_token.clone(),
                        after: last_key.clone(),
                    }
                    .encode(),
                ),
            )?;
            return Ok(outcome);
        }
        match next_page.as_deref() {
            Some(next) => page_token = Some(next.to_string()),
            None => break,
        }
    }

    // Reached the end: the next pass starts over so blocked rows retry.
    save_cursor(store, None)?;
    Ok(outcome)
}

/// `POST /admin/api/b2-cdn-purges/drain`.
///
/// `purge` is the caller's checked URL/key double purge. Any error from it
/// leaves the record outstanding; this function never deletes a failed intent.
pub(crate) fn handle_drain(
    req: Request,
    purge: impl Fn(&[String]) -> Result<()>,
) -> Result<Response> {
    crate::admin::validate_b2_cdn_purge_drain_auth(&req)?;
    if req.get_method() != Method::POST {
        return Err(BlossomError::BadRequest("POST required".into()));
    }
    let limit = parse_drain_limit(req.get_query_parameter("max"))?;
    let store = open_store()?;
    let outcome = drain(&store, limit, purge)?;
    let body = serde_json::json!({
        "result": outcome.result,
        "pending": outcome.pending,
        "errors": outcome.errors,
        "unknown": outcome.unknown,
    });
    let mut response = Response::from_status(fastly::http::StatusCode::OK);
    response.set_header("Content-Type", "application/json");
    response.set_header("Cache-Control", "no-store");
    response.set_body(body.to_string());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";

    fn prepared() -> Record {
        Record {
            attempt: ATTEMPT.into(),
            phase: Phase::Single,
            requested_at: 7,
            committed_at: None,
            cleared_at: None,
            attempts: 0,
            state: RecordState::Prepared,
        }
    }

    #[test]
    fn queue_key_requires_a_lowercase_hash_and_attempt() {
        assert_eq!(
            queue_key(HASH, ATTEMPT),
            Some(format!("b2-cdn-purge:v1:{HASH}:{ATTEMPT}"))
        );
        for bad_hash in [
            HASH.to_uppercase(),
            "a".repeat(63),
            "a".repeat(65),
            format!("{HASH}.mp4"),
            String::new(),
        ] {
            assert_eq!(queue_key(&bad_hash, ATTEMPT), None, "{bad_hash}");
        }
        for bad_attempt in ["", "abc", &"a".repeat(31), &"a".repeat(33), &"A".repeat(32)] {
            assert_eq!(queue_key(HASH, bad_attempt), None, "{bad_attempt}");
        }
        assert_eq!(
            queue_parts(&format!("b2-cdn-purge:v1:{HASH}:{ATTEMPT}")),
            Some((HASH, ATTEMPT))
        );
        assert_eq!(queue_parts(&format!("b2-cdn-purge:v1:{HASH}")), None);
        assert_eq!(queue_parts("b2-cdn-drain-cursor"), None);
        assert_eq!(queue_parts(&format!("b2-cdn-purge:v2:{HASH}:{ATTEMPT}")), None);
    }

    #[test]
    fn drain_limit_defaults_to_two_and_refuses_out_of_range() {
        assert_eq!(parse_drain_limit(None).unwrap(), 2);
        assert_eq!(parse_drain_limit(Some("1")).unwrap(), 1);
        assert_eq!(parse_drain_limit(Some("2")).unwrap(), 2);
        // Two is the hard ceiling: four hashes cost 32 purge subrequests
        // (4 * (2 URL + 2 key) * 2 rounds) before KV and metadata calls.
        for bad in ["", "0", "3", "4", "5", "17", "1000", "-1", "1.5", "abc", " 1 1"] {
            assert!(parse_drain_limit(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_present_but_empty_purge_host_set_enables_invalidation_not_disable() {
        // A retained empty purge host set is a configuration error the drain
        // must surface. It must not look like "feature off" and silently skip
        // eviction while warm entries keep serving.
        assert!(configured_from(Some("true"), None));
        assert!(configured_from(Some("true"), Some("")));
        assert!(configured_from(None, Some("")));
        assert!(configured_from(Some("false"), Some("")));
        assert!(configured_from(None, Some("media-b2-cdn.divine.video")));
        assert!(!configured_from(None, None));
        assert!(!configured_from(Some("false"), None));
        assert!(!configured_from(Some("TRUE"), None));
        assert!(!configured_from(Some(""), None));
    }

    #[test]
    fn lifecycle_round_trips_and_states_stay_distinct() {
        let prepared = prepared();
        assert_eq!(parse(&encode(&prepared)), Parsed::Intent(prepared.clone()));

        let committed = Record {
            committed_at: Some(8),
            state: RecordState::Committed,
            ..prepared.clone()
        };
        assert_eq!(
            parse(&encode(&committed)),
            Parsed::Intent(committed.clone())
        );

        let cleared = Record {
            cleared_at: Some(9),
            state: RecordState::Cleared,
            ..committed
        };
        assert_eq!(parse(&encode(&cleared)), Parsed::Intent(cleared));
    }

    #[test]
    fn prepared_is_never_encoded_as_any_terminal_state() {
        // The drain decides "never clear prepared" from this exact string.
        let value: serde_json::Value = serde_json::from_str(&encode(&prepared())).unwrap();
        assert_eq!(value["state"], "prepared");
        assert!(value["committed_at"].is_null());
        assert!(value["cleared_at"].is_null());
    }

    #[test]
    fn a_state_that_disagrees_with_its_timestamps_is_foreign() {
        let prepared = prepared();
        for mutate in [
            |record: &mut Record| {
                record.state = RecordState::Committed;
            },
            |record: &mut Record| {
                record.state = RecordState::Cleared;
            },
            |record: &mut Record| {
                record.committed_at = Some(8);
            },
            |record: &mut Record| {
                record.cleared_at = Some(9);
            },
        ] {
            let mut record = prepared.clone();
            mutate(&mut record);
            assert_eq!(parse(&encode(&record)), Parsed::Foreign);
        }
    }

    #[test]
    fn foreign_or_future_records_are_retained_not_reinterpreted() {
        let value: serde_json::Value = serde_json::from_str(&encode(&prepared())).unwrap();
        let mut future = value.clone();
        future["version"] = serde_json::json!(2);
        let mut extra = value.clone();
        extra["owner"] = serde_json::json!("someone");
        let mut unknown_state = value.clone();
        unknown_state["state"] = serde_json::json!("cancelled");
        let mut future_type = value.clone();
        future_type["requested_at"] = serde_json::json!("seven");
        let mut overflow = value.clone();
        overflow["attempts"] = serde_json::json!(u64::from(u32::MAX) + 1);
        let mut short_attempt = value.clone();
        short_attempt["attempt"] = serde_json::json!("abcd");

        for candidate in [
            future.to_string(),
            extra.to_string(),
            unknown_state.to_string(),
            future_type.to_string(),
            overflow.to_string(),
            short_attempt.to_string(),
            String::new(),
            "null".into(),
            "[]".into(),
            "{".into(),
            "x".repeat(MAX_RECORD_BYTES + 1),
        ] {
            assert_eq!(
                parse(&candidate),
                Parsed::Foreign,
                "foreign record must not be read as an intent: {candidate}"
            );
        }
    }

    #[test]
    fn concurrent_writers_get_distinct_keys_so_none_loses_its_intent() {
        // The defect this guards: a per-hash key let a second `begin` overwrite
        // the first writer's prepared intent, so a late mutation had no retry
        // record. Distinct attempts keep both.
        let first = queue_key(HASH, ATTEMPT).unwrap();
        let second = queue_key(HASH, "fedcba9876543210fedcba9876543210").unwrap();
        assert_ne!(first, second);
        assert_eq!(queue_parts(&first).unwrap().0, queue_parts(&second).unwrap().0);
        assert_ne!(queue_parts(&first).unwrap().1, queue_parts(&second).unwrap().1);
    }

    #[test]
    fn a_token_only_matches_the_attempt_it_was_created_for() {
        let token = Token {
            key: queue_key(HASH, ATTEMPT).unwrap(),
            hash: HASH.into(),
            attempt: ATTEMPT.into(),
            generation: 41,
        };
        let other = Snapshot {
            key: queue_key(HASH, "fedcba9876543210fedcba9876543210").unwrap(),
            hash: HASH.into(),
            record: Record {
                attempt: "fedcba9876543210fedcba9876543210".into(),
                requested_at: 11,
                ..prepared()
            },
            generation: 41,
        };
        assert_ne!(token.key, other.key);
        assert_ne!(token.attempt, other.record.attempt);

        // Same key, newer generation: a record re-written since the token.
        let newer_generation = Snapshot {
            generation: token.generation + 1,
            ..other.clone()
        };
        assert_ne!(token.generation, newer_generation.generation);
    }

    #[test]
    fn receipts_bind_to_one_attempt_so_old_completion_cannot_answer_a_new_one() {
        let current = Token {
            key: queue_key(HASH, ATTEMPT).unwrap(),
            hash: HASH.into(),
            attempt: ATTEMPT.into(),
            generation: 41,
        };
        let next = Token {
            attempt: "fedcba9876543210fedcba9876543210".into(),
            key: queue_key(HASH, "fedcba9876543210fedcba9876543210").unwrap(),
            ..current.clone()
        };
        assert_ne!(
            receipt_key("final", &current.hash, &current.attempt),
            receipt_key("final", &next.hash, &next.attempt)
        );
        assert_eq!(
            receipt_parts(&format!("{RECEIPT_PREFIX}:v1:final:{HASH}:{ATTEMPT}")),
            Some(("final", HASH, ATTEMPT))
        );
        assert_eq!(
            receipt_parts(&format!("{RECEIPT_PREFIX}:v1:final:{HASH}")),
            None
        );
    }
    /// Real KV lifecycle tests. These run only under the fixture runner
    /// `scripts/run-b2-cdn-purge-outbox-tests.py`, which supplies a local
    /// `blossom_metadata` store. The purge callback is a pure function.
    mod storage {
        use super::*;

        fn store() -> KVStore {
            open_store().expect("fixture store")
        }

        fn purge_ok(_: &[String]) -> Result<()> {
            Ok(())
        }

        fn purge_fail(_: &[String]) -> Result<()> {
            Err(BlossomError::StorageError("synthetic purge failure".into()))
        }

        fn snapshot_for(store: &KVStore, token: &Token) -> Snapshot {
            lookup(store, &token.key).expect("lookup").expect("record present")
        }

        /// Every outbox test shares one local KV file, so a pass must start
        /// from an empty queue. Drain counters are global, not per hash.
        fn reset_all(store: &KVStore) {
            loop {
                let Ok(page) = store
                    .build_list()
                    .limit(MAX_LIST_LIMIT)
                    .prefix("b2-cdn")
                    .execute()
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
            let _ = store.build_delete().execute(CURSOR_KEY);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn begin_writes_prepared_and_drain_never_clears_it() {
            let store = store();
            reset_all(&store);
            let hash = "b1".repeat(32);
            let token = begin(&hash).unwrap();
            let snapshot = snapshot_for(&store, &token);
            assert_eq!(snapshot.record.state, RecordState::Prepared);
            assert_eq!(snapshot.record.attempt, token.attempt);

            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(outcome.result, 0);
            assert_eq!(outcome.unknown, 1);
            assert_eq!(outcome.pending, 1);
            // Prepared survives the drain: the mutation may never have landed.
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Prepared
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn commit_then_drain_purges_and_clears() {
            let store = store();
            reset_all(&store);
            let hash = "b2".repeat(32);
            let token = begin(&hash).unwrap();
            assert_eq!(commit(&store, &token).unwrap(), CommitOutcome::Committed);
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Committed
            );

            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(outcome.result, 1);
            assert_eq!(outcome.errors, 0);
            // Cleared records are retained as evidence, not deleted.
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Cleared
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn purge_failure_retains_committed_record_for_retry() {
            let store = store();
            reset_all(&store);
            let hash = "b3".repeat(32);
            let token = begin(&hash).unwrap();
            commit(&store, &token).unwrap();

            let outcome = drain(&store, 2, purge_fail).unwrap();
            assert_eq!(outcome.result, 0);
            assert_eq!(outcome.errors, 1);
            assert_eq!(outcome.pending, 1);
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Committed
            );

            // A later successful pass clears it. No age-based clearing.
            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(outcome.result, 1);
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Cleared
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn two_concurrent_writers_both_keep_a_retry_record() {
            let store = store();
            reset_all(&store);
            let hash = "b4".repeat(32);
            // The defect this guards: a per-hash key let the second begin
            // overwrite the first prepared intent.
            let first = begin(&hash).unwrap();
            let second = begin(&hash).unwrap();
            assert_ne!(first.key, second.key);
            assert_eq!(
                snapshot_for(&store, &first).record.state,
                RecordState::Prepared
            );
            assert_eq!(
                snapshot_for(&store, &second).record.state,
                RecordState::Prepared
            );

            // Each writer commits its own attempt independently.
            assert_eq!(commit(&store, &first).unwrap(), CommitOutcome::Committed);
            assert_eq!(commit(&store, &second).unwrap(), CommitOutcome::Committed);
            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(outcome.result, 2);
            assert_eq!(
                snapshot_for(&store, &first).record.state,
                RecordState::Cleared
            );
            assert_eq!(
                snapshot_for(&store, &second).record.state,
                RecordState::Cleared
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn a_stale_token_never_commits_a_newer_attempt() {
            let store = store();
            reset_all(&store);
            let hash = "b5".repeat(32);
            let first = begin(&hash).unwrap();
            let second = begin(&hash).unwrap();
            // Simulate the first token's view going stale by pointing it at the
            // second record's key with the first attempt.
            let stale = Token {
                key: second.key.clone(),
                attempt: first.attempt.clone(),
                ..first.clone()
            };
            assert_eq!(commit(&store, &stale).unwrap(), CommitOutcome::Superseded);
            assert_eq!(
                snapshot_for(&store, &second).record.state,
                RecordState::Prepared
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn execute_retains_prepared_when_the_mutation_fails() {
            let store = store();
            reset_all(&store);
            let hash = "b6".repeat(32);
            let result = execute(&hash, || -> Result<()> {
                Err(BlossomError::StorageError(
                    "synthetic mutation failure".into(),
                ))
            });
            assert!(result.is_err());
            let mut found = false;
            for key in plan_keys(&store) {
                let snapshot = lookup(&store, &key).unwrap().unwrap();
                assert_eq!(snapshot.record.state, RecordState::Prepared);
                found = true;
            }
            assert!(found, "a failed mutation must keep its intent visible");
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn execute_commits_after_successful_mutation_and_drains() {
            let store = store();
            reset_all(&store);
            let hash = "b7".repeat(32);
            let value = execute(&hash, || Ok(7u8)).unwrap();
            assert_eq!(value, 7);
            let keys = plan_keys(&store);
            assert_eq!(keys.len(), 1);
            assert_eq!(
                lookup(&store, &keys[0]).unwrap().unwrap().record.state,
                RecordState::Committed
            );
            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(outcome.result, 1);
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn drain_limit_bounds_one_pass_and_cursor_advances() {
            let store = store();
            reset_all(&store);
            for i in 0..5 {
                let hash = format!("{:02x}", 0xc0 + i).repeat(32);
                let token = begin(&hash).unwrap();
                commit(&store, &token).unwrap();
            }
            let first = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(first.result, 2, "limit must bound one pass");
            let second = drain(&store, 2, purge_ok).unwrap();
            assert!(second.result > 0, "cursor must advance to new records");
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn foreign_records_are_retained_and_do_not_starve_healthy_suffix() {
            let store = store();
            reset_all(&store);
            let foreign_key = format!("{RECORD_PREFIX}{}:{}", "d0".repeat(32), "0".repeat(32));
            let healthy = "d1".repeat(32);
            store
                .build_insert()
                .mode(InsertMode::Overwrite)
                .execute(&foreign_key, r#"{"version":9,"state":"future"}"#)
                .unwrap();
            let token = begin(&healthy).unwrap();
            commit(&store, &token).unwrap();

            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert!(
                outcome.result >= 1,
                "healthy record after foreign must drain"
            );
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Cleared
            );
            let mut response = store.build_lookup().execute(&foreign_key).unwrap();
            assert_eq!(
                String::from_utf8(response.take_body_bytes()).unwrap(),
                r#"{"version":9,"state":"future"}"#
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn execute_fails_closed_when_the_prepared_record_disappears_before_commit() {
            let store = store();
            reset_all(&store);
            let hash = "bb".repeat(32);
            let mut mutation_applied = false;
            let result = execute(&hash, || -> Result<()> {
                // The mutation lands, then the durable intent vanishes before
                // commit. Per-attempt keys make this lost durability, not a
                // benign supersede by another writer.
                for key in plan_keys(&store) {
                    let _ = store.build_delete().execute(&key);
                }
                mutation_applied = true;
                Ok(())
            });
            assert!(mutation_applied, "mutation must have run");
            let error = result.expect_err("lost intent must fail closed");
            assert_eq!(error.kind(), "metadata_error");
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn execute_fails_closed_when_the_record_no_longer_describes_the_attempt() {
            let store = store();
            reset_all(&store);
            let hash = "bc".repeat(32);
            let result = execute(&hash, || -> Result<()> {
                let keys = plan_keys(&store);
                assert_eq!(keys.len(), 1);
                // Another attempt's body under this key is not this intent.
                store
                    .build_insert()
                    .mode(InsertMode::Overwrite)
                    .execute(
                        &keys[0],
                        r#"{"version":1,"state":"prepared","attempt":"00000000000000000000000000000000","requested_at":1,"committed_at":null,"cleared_at":null,"attempts":0}"#,
                    )
                    .unwrap();
                Ok(())
            });
            let error = result.expect_err("mismatched record must fail closed");
            assert_eq!(error.kind(), "metadata_error");
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn invalid_purge_configuration_is_an_error_and_retains_the_record() {
            let store = store();
            reset_all(&store);
            let hash = "ba".repeat(32);
            let token = begin(&hash).unwrap();
            commit(&store, &token).unwrap();

            // A present-but-empty host set must fail the purge callback, not
            // pretend the queue is disabled. The committed record is retained.
            let invalid_config = |_: &[String]| -> Result<()> {
                Err(BlossomError::StorageError(
                    "B2 CDN purge configuration invalid".into(),
                ))
            };
            let outcome = drain(&store, 2, invalid_config).unwrap();
            assert_eq!(outcome.result, 0, "invalid config must not report success");
            assert_eq!(outcome.errors, 1);
            assert_eq!(outcome.pending, 1);
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Committed
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn one_poison_phase_does_not_stall_the_whole_drain() {
            let store = store();
            reset_all(&store);
            // A valid Final intent whose phase record is malformed sorts before
            // a healthy Single intent. The malformed phase must not abort the
            // pass before the cursor is persisted or starve the healthy suffix.
            let poison = "e8".repeat(32);
            let healthy = "e9".repeat(32);
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{poison}"));
            store
                .build_insert()
                .mode(InsertMode::Overwrite)
                .execute(
                    &format!("b2-cdn-phase:v1:{poison}"),
                    r#"{"version":99,"physical":"future"}"#,
                )
                .unwrap();
            let poison_token = begin_phase(&poison, Phase::Final).unwrap();
            assert_eq!(
                commit(&store, &poison_token).unwrap(),
                CommitOutcome::Committed
            );
            let poison_snapshot = snapshot_for(&store, &poison_token);
            assert_eq!(poison_snapshot.record.phase, Phase::Final);
            assert_eq!(poison_snapshot.record.state, RecordState::Committed);
            assert!(crate::b2_cdn_phase::purge_token(&poison).is_err());
            let healthy_token = begin(&healthy).unwrap();
            assert_eq!(
                commit(&store, &healthy_token).unwrap(),
                CommitOutcome::Committed
            );

            // Track which hashes the checked purge actually attempted.
            let attempted = std::cell::RefCell::new(Vec::<String>::new());
            let recording_purge = |batch: &[String]| -> Result<()> {
                attempted.borrow_mut().extend(batch.iter().cloned());
                Ok(())
            };
            let first = drain(&store, 2, recording_purge).unwrap();
            // The poison row still owes a cache eviction, so purge was attempted
            // even though the phase cannot be acknowledged.
            assert!(
                attempted.borrow().iter().any(|h| h == &poison),
                "poison phase must still be purged for cache eviction"
            );
            // It is retained and reported, never acked or cleared.
            assert_eq!(first.errors, 1, "poison phase is an error");
            assert_eq!(first.pending, 1);
            assert!(!acknowledged(&store, &poison_token, "final").unwrap());
            assert_eq!(
                snapshot_for(&store, &poison_token).record.state,
                RecordState::Committed,
                "a poison phase intent must stay outstanding"
            );
            // The healthy row must still drain in this or a following pass.
            let mut drained = first.result;
            for _ in 0..4 {
                if drained >= 1 {
                    break;
                }
                drained += drain(&store, 2, recording_purge).unwrap().result;
            }
            assert_eq!(drained, 1, "healthy suffix must not be starved");
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{poison}"));
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn long_cleared_history_does_not_starve_a_healthy_suffix() {
            let store = store();
            reset_all(&store);
            // 1,650 cleared records sort before one healthy committed record.
            // A drain that only scans the first 1,600 keys from the start would
            // never reach the healthy row.
            for i in 0..1650u32 {
                let attempt = format!("{i:032x}");
                let key = format!("{RECORD_PREFIX}{}:{attempt}", "a".repeat(64));
                store
                    .build_insert()
                    .mode(InsertMode::Overwrite)
                    .execute(&key, {
                        let now = requested_at();
                        let record = Record {
                            attempt,
                            phase: Phase::Single,
                            requested_at: now,
                            committed_at: Some(now),
                            cleared_at: Some(now),
                            attempts: 0,
                            state: RecordState::Cleared,
                        };
                        encode(&record)
                    })
                    .unwrap();
            }
            let healthy = "f".repeat(64);
            let token = begin(&healthy).unwrap();
            commit(&store, &token).unwrap();

            // Repeated bounded passes must eventually reach and clear the
            // healthy record, not scan the same 1,600-key prefix forever.
            let mut drained = 0;
            for _ in 0..40 {
                let outcome = drain(&store, 2, purge_ok).unwrap();
                drained += outcome.result;
                if drained > 0 {
                    break;
                }
            }
            assert_eq!(
                drained, 1,
                "a healthy record after long cleared history must drain"
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn receipts_do_not_share_the_queue_list_prefix() {
            // Receipts are retained forever; if they shared the queue prefix the
            // drain would burn its scan budget on them. They must sort outside.
            let hash = "aa".repeat(32);
            let attempt = "0".repeat(32);
            let receipt = receipt_key("final", &hash, &attempt).unwrap();
            assert!(
                !receipt.starts_with(PREFIX),
                "receipt {receipt} must not match queue prefix {PREFIX}"
            );
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn a_partial_pass_does_not_starve_healthy_rows_behind_blocked_ones() {
            let store = store();
            reset_all(&store);
            // Five committed rows that share a hash prefix so page order is
            // stable. The first two have purge failures; the remaining three
            // must still drain across passes.
            let hashes: Vec<String> = (0..5)
                .map(|i| format!("{:02x}", i).repeat(32))
                .collect();
            for hash in &hashes {
                let token = begin(hash).unwrap();
                commit(&store, &token).unwrap();
            }
            let blocked: std::collections::HashSet<String> =
                hashes.iter().take(2).cloned().collect();
            let purge = |batch: &[String]| -> Result<()> {
                if batch.iter().any(|hash| blocked.contains(hash)) {
                    Err(BlossomError::StorageError("synthetic failure".into()))
                } else {
                    Ok(())
                }
            };
            // Limit 2 processes the two blocked rows and stores a within-page
            // position. The next calls must reach the healthy suffix rather
            // than resetting to the first page forever.
            let first = drain(&store, 2, purge).unwrap();
            assert_eq!(first.result, 0);
            assert_eq!(first.errors, 2);
            let mut drained = 0;
            // With exact mid-page resume a blocked row is not retried until the
            // cursor wraps, so allow several passes.
            for _ in 0..20 {
                let outcome = drain(&store, 2, purge).unwrap();
                drained += outcome.result;
                if drained == 3 {
                    break;
                }
            }
            assert_eq!(
                drained, 3,
                "healthy rows after two failing rows must eventually drain"
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn a_precautionary_drain_does_not_break_a_live_writers_commit() {
            let store = store();
            reset_all(&store);
            let hash = "e4".repeat(32);
            // A writer begins, a drain runs and purges the prepared record as a
            // precaution, then the writer's mutation finishes and it commits.
            let token = begin(&hash).unwrap();
            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert_eq!(outcome.unknown, 1);
            assert_eq!(
                commit(&store, &token).unwrap(),
                CommitOutcome::Committed,
                "a precautionary purge must not invalidate the live token"
            );
            assert_eq!(
                snapshot_for(&store, &token).record.state,
                RecordState::Committed
            );
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn a_stale_purge_callback_cannot_ack_a_physical_state_change() {
            use crate::b2_cdn_phase::{self, Physical};
            let store = store();
            reset_all(&store);
            let hash = "bf".repeat(32);
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{hash}"));

            // Physical failed, intent queued: the drain may purge it.
            let phase_epoch = b2_cdn_phase::begin_erase(&hash).unwrap();
            b2_cdn_phase::record_physical(&hash, &phase_epoch, Physical::Failed).unwrap();
            b2_cdn_phase::ensure_final_intent(&hash).unwrap();
            let token = begin_phase(&hash, Phase::Final).unwrap();
            commit(&store, &token).unwrap();

            // The purge "succeeds" but, mid-flight, the physical outcome changes
            // to Absent. That is a new state needing its own purge.
            let racing_purge = |_: &[String]| -> Result<()> {
                b2_cdn_phase::record_physical(&hash, &phase_epoch, Physical::Absent).unwrap();
                Ok(())
            };
            let outcome = drain(&store, 2, racing_purge).unwrap();
            assert_eq!(outcome.result, 0, "stale callback must not finish the row");
            assert!(
                !acknowledged(&store, &token, "final").unwrap(),
                "a stale purge must not write a final receipt"
            );
            assert!(
                !b2_cdn_phase::complete_ready(&hash).unwrap(),
                "new Absent state still needs its own purge"
            );

            // The new Absent state cleared its queued flag, so a fresh durable
            // intent is required before it can be acknowledged.
            b2_cdn_phase::ensure_final_intent(&hash).unwrap();
            assert!(crate::b2_cdn_phase::final_queued(&hash).unwrap());

            // The next pass continues after the row it already attempted. A
            // subsequent full pass (cursor wrapped) sees the new state and can
            // acknowledge it.
            let _ = drain(&store, 2, purge_ok).unwrap();
            let mut outcome = drain(&store, 2, purge_ok).unwrap();
            for _ in 0..4 {
                if outcome.result == 1 {
                    break;
                }
                outcome = drain(&store, 2, purge_ok).unwrap();
            }
            assert_eq!(outcome.result, 1);
            assert!(b2_cdn_phase::complete_ready(&hash).unwrap());
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{hash}"));
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn final_drain_advances_the_phase_and_writes_the_receipt() {
            use crate::b2_cdn_phase::{self, Physical};
            let store = store();
            reset_all(&store);
            let hash = "bd".repeat(32);
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{hash}"));

            // Physical wave confirms absence, then the final intent is queued.
            let epoch = b2_cdn_phase::begin_erase(&hash).unwrap();
            b2_cdn_phase::record_physical(&hash, &epoch, Physical::Absent).unwrap();
            assert!(b2_cdn_phase::final_purge_pending(&hash).unwrap());
            // The production flow queues a durable final intent, then the drain
            // wrote it. A queued intent is required before an ack counts.
            // ensure_final_intent already queued the durable intent this drain
            // consumes, so the drain finishes the phase for that attempt.
            b2_cdn_phase::ensure_final_intent(&hash).unwrap();

            let outcome = drain(&store, 2, purge_ok).unwrap();
            assert!(outcome.result >= 1, "the queued final intent must drain");
            assert!(b2_cdn_phase::complete_ready(&hash).unwrap());
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{hash}"));
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn a_failed_final_purge_never_acks_or_completes() {
            use crate::b2_cdn_phase::{self, Physical};
            let store = store();
            reset_all(&store);
            let hash = "be".repeat(32);
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{hash}"));
            let epoch = b2_cdn_phase::begin_erase(&hash).unwrap();
            b2_cdn_phase::record_physical(&hash, &epoch, Physical::Absent).unwrap();
            let token = begin_phase(&hash, Phase::Final).unwrap();
            commit(&store, &token).unwrap();

            let outcome = drain(&store, 2, purge_fail).unwrap();
            assert_eq!(outcome.result, 0);
            assert_eq!(outcome.errors, 1);
            assert!(!acknowledged(&store, &token, "final").unwrap());
            assert!(!b2_cdn_phase::complete_ready(&hash).unwrap());
            let _ = store
                .build_delete()
                .execute(&format!("b2-cdn-phase:v1:{hash}"));
            reset_all(&store);
        }

        #[test]
        #[ignore = "requires local KV fixture; scripts/run-b2-cdn-purge-outbox-tests.py"]
        fn receipts_bind_to_one_attempt_and_never_imply_from_absence() {
            let store = store();
            reset_all(&store);
            let hash = "b8".repeat(32);
            let token = begin(&hash).unwrap();
            assert!(!acknowledged(&store, &token, "early").unwrap());
            ack(&token, "early").unwrap();
            assert!(acknowledged(&store, &token, "early").unwrap());
            // A different phase is independent evidence.
            assert!(!acknowledged(&store, &token, "final").unwrap());

            // A new operation for the same hash cannot reuse the old receipt.
            let next = begin(&hash).unwrap();
            assert!(!acknowledged(&store, &next, "early").unwrap());
            ack(&next, "early").unwrap();
            assert!(acknowledged(&store, &next, "early").unwrap());
            assert!(acknowledged(&store, &token, "early").unwrap());

            for phase in ["", "EARLY", "unknown"] {
                assert!(ack(&token, phase).is_err(), "{phase}");
                assert!(acknowledged(&store, &token, phase).is_err(), "{phase}");
            }
            reset_all(&store);
        }

        fn plan_keys(store: &KVStore) -> Vec<String> {
            let mut keys = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let mut builder = store.build_list().limit(MAX_LIST_LIMIT).prefix(PREFIX);
                if let Some(value) = cursor.as_deref() {
                    builder = builder.cursor(value);
                }
                let page = builder.execute().unwrap();
                keys.extend(page.keys().iter().cloned());
                match page.next_cursor() {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            keys
        }
    }

}
