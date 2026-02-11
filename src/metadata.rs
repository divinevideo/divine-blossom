// ABOUTME: Fastly KV store operations for blob metadata
// ABOUTME: Handles blob metadata and per-user blob lists

use crate::blossom::{BlobMetadata, BlobStatus, GlobalStats, RecentIndex, SubtitleJob, UserIndex};
use crate::error::{BlossomError, Result};
use fastly::kv_store::{KVStore, KVStoreError};

/// KV store name (must match fastly.toml)
const KV_STORE_NAME: &str = "blossom_metadata";

/// Key prefix for blob metadata
const BLOB_PREFIX: &str = "blob:";

/// Key prefix for user blob lists
const LIST_PREFIX: &str = "list:";

/// Key for global statistics
const STATS_KEY: &str = "stats:global";

/// Key for recent uploads index
const RECENT_INDEX_KEY: &str = "index:recent";

/// Key for user index (list of all uploaders)
const USER_INDEX_KEY: &str = "index:users";

/// Key prefix for subtitle jobs
const SUBTITLE_JOB_PREFIX: &str = "subtitle_job:";

/// Key prefix for hash -> subtitle job id mapping
const SUBTITLE_HASH_PREFIX: &str = "subtitle_hash:";

/// Open the metadata KV store
fn open_store() -> Result<KVStore> {
    KVStore::open(KV_STORE_NAME)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to open KV store: {}", e)))?
        .ok_or_else(|| BlossomError::MetadataError("KV store not found".into()))
}

/// Get blob metadata by hash
pub fn get_blob_metadata(hash: &str) -> Result<Option<BlobMetadata>> {
    let store = open_store()?;
    let key = format!("{}{}", BLOB_PREFIX, hash.to_lowercase());

    match store.lookup(&key) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();

            let metadata: BlobMetadata = serde_json::from_str(&body).map_err(|e| {
                BlossomError::MetadataError(format!("Failed to parse metadata: {}", e))
            })?;

            Ok(Some(metadata))
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup metadata: {}",
            e
        ))),
    }
}

/// Store blob metadata
pub fn put_blob_metadata(metadata: &BlobMetadata) -> Result<()> {
    let store = open_store()?;
    let key = format!("{}{}", BLOB_PREFIX, metadata.sha256.to_lowercase());

    let json = serde_json::to_string(metadata)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to serialize metadata: {}", e)))?;

    store
        .insert(&key, json)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to store metadata: {}", e)))?;

    Ok(())
}

/// Delete blob metadata
pub fn delete_blob_metadata(hash: &str) -> Result<()> {
    let store = open_store()?;
    let key = format!("{}{}", BLOB_PREFIX, hash.to_lowercase());

    store
        .delete(&key)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to delete metadata: {}", e)))?;

    Ok(())
}

/// Get list of blob hashes for a user
pub fn get_user_blobs(pubkey: &str) -> Result<Vec<String>> {
    let store = open_store()?;
    let key = format!("{}{}", LIST_PREFIX, pubkey.to_lowercase());

    match store.lookup(&key) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();

            let hashes: Vec<String> = serde_json::from_str(&body)
                .map_err(|e| BlossomError::MetadataError(format!("Failed to parse list: {}", e)))?;

            Ok(hashes)
        }
        Err(KVStoreError::ItemNotFound) => Ok(Vec::new()),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup list: {}",
            e
        ))),
    }
}

/// Add a blob hash to user's list with retry for concurrent writes
pub fn add_to_user_list(pubkey: &str, hash: &str) -> Result<()> {
    let hash_lower = hash.to_lowercase();

    // Retry up to 5 times with increasing delay for concurrent write conflicts
    for attempt in 0..5 {
        let mut hashes = get_user_blobs(pubkey)?;

        if hashes.contains(&hash_lower) {
            // Already in list, nothing to do
            return Ok(());
        }

        hashes.push(hash_lower.clone());

        match put_user_list(pubkey, &hashes) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                // Log retry and continue
                eprintln!("[KV] Retry {} for user list update: {}", attempt + 1, e);
                // Small delay before retry (10ms, 20ms, 40ms, 80ms)
                // Note: Fastly Compute doesn't have sleep, so we just retry immediately
                // The re-read of the list should pick up concurrent writes
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    // Should never reach here, but just in case
    Err(BlossomError::MetadataError(
        "Max retries exceeded for list update".into(),
    ))
}

/// Remove a blob hash from user's list with retry for concurrent writes
pub fn remove_from_user_list(pubkey: &str, hash: &str) -> Result<()> {
    let hash_lower = hash.to_lowercase();

    // Retry up to 5 times for concurrent write conflicts
    for attempt in 0..5 {
        let mut hashes = get_user_blobs(pubkey)?;

        if !hashes.contains(&hash_lower) {
            // Not in list, nothing to do
            return Ok(());
        }

        hashes.retain(|h| h != &hash_lower);

        match put_user_list(pubkey, &hashes) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for user list removal: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(BlossomError::MetadataError(
        "Max retries exceeded for list removal".into(),
    ))
}

/// Store user's blob list
fn put_user_list(pubkey: &str, hashes: &[String]) -> Result<()> {
    let store = open_store()?;
    let key = format!("{}{}", LIST_PREFIX, pubkey.to_lowercase());

    let json = serde_json::to_string(hashes)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to serialize list: {}", e)))?;

    store
        .insert(&key, json)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to store list: {}", e)))?;

    Ok(())
}

/// Update blob status (for moderation)
pub fn update_blob_status(hash: &str, status: BlobStatus) -> Result<()> {
    let mut metadata =
        get_blob_metadata(hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.status = status;
    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Update transcode status for a video blob
pub fn update_transcode_status(hash: &str, status: crate::blossom::TranscodeStatus) -> Result<()> {
    let mut metadata =
        get_blob_metadata(hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.transcode_status = Some(status);
    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Update transcript status for an audio/video blob
pub fn update_transcript_status(
    hash: &str,
    status: crate::blossom::TranscriptStatus,
) -> Result<()> {
    let mut metadata =
        get_blob_metadata(hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.transcript_status = Some(status);
    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Get subtitle job by job id
pub fn get_subtitle_job(job_id: &str) -> Result<Option<SubtitleJob>> {
    let store = open_store()?;
    let key = format!("{}{}", SUBTITLE_JOB_PREFIX, job_id);

    match store.lookup(&key) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();
            let job: SubtitleJob = serde_json::from_str(&body).map_err(|e| {
                BlossomError::MetadataError(format!("Failed to parse subtitle job: {}", e))
            })?;
            Ok(Some(job))
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup subtitle job: {}",
            e
        ))),
    }
}

/// Store subtitle job by id
pub fn put_subtitle_job(job: &SubtitleJob) -> Result<()> {
    let store = open_store()?;
    let key = format!("{}{}", SUBTITLE_JOB_PREFIX, job.job_id);
    let json = serde_json::to_string(job)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to serialize subtitle job: {}", e)))?;

    store
        .insert(&key, json)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to store subtitle job: {}", e)))?;

    Ok(())
}

/// Get subtitle job id by media hash
pub fn get_subtitle_job_id_by_hash(hash: &str) -> Result<Option<String>> {
    let store = open_store()?;
    let key = format!("{}{}", SUBTITLE_HASH_PREFIX, hash.to_lowercase());

    match store.lookup(&key) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();
            let job_id = body.trim().to_string();
            if job_id.is_empty() {
                Ok(None)
            } else {
                Ok(Some(job_id))
            }
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup subtitle job by hash: {}",
            e
        ))),
    }
}

/// Set subtitle job id mapping for a media hash
pub fn set_subtitle_job_id_for_hash(hash: &str, job_id: &str) -> Result<()> {
    let store = open_store()?;
    let key = format!("{}{}", SUBTITLE_HASH_PREFIX, hash.to_lowercase());
    store
        .insert(&key, job_id.to_string())
        .map_err(|e| {
            BlossomError::MetadataError(format!("Failed to store subtitle hash mapping: {}", e))
        })?;
    Ok(())
}

/// Get subtitle job by media hash
pub fn get_subtitle_job_by_hash(hash: &str) -> Result<Option<SubtitleJob>> {
    if let Some(job_id) = get_subtitle_job_id_by_hash(hash)? {
        return get_subtitle_job(&job_id);
    }
    Ok(None)
}

/// Update transcode status and optionally the file size and dimensions for a video blob
/// The new_size is provided when faststart optimization replaces the original file
/// The dim is provided by the transcoder's ffprobe as "WIDTHxHEIGHT" (display dimensions)
pub fn update_transcode_status_with_size(
    hash: &str,
    status: crate::blossom::TranscodeStatus,
    new_size: Option<u64>,
    dim: Option<String>,
) -> Result<()> {
    let mut metadata =
        get_blob_metadata(hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.transcode_status = Some(status);

    // Update size if provided (faststart optimization replaced the original file)
    if let Some(size) = new_size {
        metadata.size = size;
    }

    // Update display dimensions if provided by transcoder
    if let Some(d) = dim {
        metadata.dim = Some(d);
    }

    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Check if user owns the blob
pub fn check_ownership(hash: &str, pubkey: &str) -> Result<bool> {
    let metadata =
        get_blob_metadata(hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    Ok(metadata.owner.to_lowercase() == pubkey.to_lowercase())
}

/// Get blobs for listing with optional status filtering
pub fn list_blobs_with_metadata(
    pubkey: &str,
    include_restricted: bool,
) -> Result<Vec<BlobMetadata>> {
    let hashes = get_user_blobs(pubkey)?;
    let mut results = Vec::new();

    for hash in hashes {
        if let Some(metadata) = get_blob_metadata(&hash)? {
            // Include if active, or if include_restricted is true
            if metadata.status == BlobStatus::Active || include_restricted {
                results.push(metadata);
            }
        }
    }

    Ok(results)
}

// ============================================================================
// Admin Dashboard: Global Stats
// ============================================================================

/// Get global statistics
pub fn get_global_stats() -> Result<GlobalStats> {
    let store = open_store()?;

    match store.lookup(STATS_KEY) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();
            let stats: GlobalStats = serde_json::from_str(&body).map_err(|e| {
                BlossomError::MetadataError(format!("Failed to parse stats: {}", e))
            })?;
            Ok(stats)
        }
        Err(KVStoreError::ItemNotFound) => Ok(GlobalStats::new()),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup stats: {}",
            e
        ))),
    }
}

/// Store global statistics
fn put_global_stats(stats: &GlobalStats) -> Result<()> {
    let store = open_store()?;
    let json = serde_json::to_string(stats)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to serialize stats: {}", e)))?;

    store
        .insert(STATS_KEY, json)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to store stats: {}", e)))?;

    Ok(())
}

/// Update global stats when a blob is added (with retry for concurrent writes)
pub fn update_stats_on_add(metadata: &BlobMetadata) -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_global_stats()?;
        stats.add_blob(metadata);

        match put_global_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for stats add: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for stats update".into(),
    ))
}

/// Update global stats when a blob is removed (with retry for concurrent writes)
pub fn update_stats_on_remove(metadata: &BlobMetadata) -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_global_stats()?;
        stats.remove_blob(metadata);

        match put_global_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for stats remove: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for stats update".into(),
    ))
}

/// Update global stats when blob status changes (with retry for concurrent writes)
pub fn update_stats_on_status_change(old_status: BlobStatus, new_status: BlobStatus) -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_global_stats()?;
        stats.update_status(old_status, new_status);

        match put_global_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for status change: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for stats update".into(),
    ))
}

/// Increment unique uploaders count (with retry for concurrent writes)
pub fn increment_unique_uploaders() -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_global_stats()?;
        stats.unique_uploaders += 1;

        match put_global_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for uploaders increment: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for stats update".into(),
    ))
}

/// Replace global stats entirely (used for backfill)
pub fn replace_global_stats(stats: &GlobalStats) -> Result<()> {
    put_global_stats(stats)
}

// ============================================================================
// Admin Dashboard: Recent Index
// ============================================================================

/// Get the recent uploads index
pub fn get_recent_index() -> Result<RecentIndex> {
    let store = open_store()?;

    match store.lookup(RECENT_INDEX_KEY) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();
            let index: RecentIndex = serde_json::from_str(&body).map_err(|e| {
                BlossomError::MetadataError(format!("Failed to parse recent index: {}", e))
            })?;
            Ok(index)
        }
        Err(KVStoreError::ItemNotFound) => Ok(RecentIndex::new()),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup recent index: {}",
            e
        ))),
    }
}

/// Store the recent uploads index
fn put_recent_index(index: &RecentIndex) -> Result<()> {
    let store = open_store()?;
    let json = serde_json::to_string(index).map_err(|e| {
        BlossomError::MetadataError(format!("Failed to serialize recent index: {}", e))
    })?;

    store
        .insert(RECENT_INDEX_KEY, json)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to store recent index: {}", e)))?;

    Ok(())
}

/// Add a hash to the recent index (with retry for concurrent writes)
pub fn add_to_recent_index(hash: &str) -> Result<()> {
    let hash_lower = hash.to_lowercase();

    for attempt in 0..5 {
        let mut index = get_recent_index()?;
        index.add(hash_lower.clone());

        match put_recent_index(&index) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for recent index add: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for recent index update".into(),
    ))
}

/// Remove a hash from the recent index (with retry for concurrent writes)
pub fn remove_from_recent_index(hash: &str) -> Result<()> {
    let hash_lower = hash.to_lowercase();

    for attempt in 0..5 {
        let mut index = get_recent_index()?;
        index.remove(&hash_lower);

        match put_recent_index(&index) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for recent index remove: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for recent index update".into(),
    ))
}

/// Replace recent index entirely (used for backfill)
pub fn replace_recent_index(index: &RecentIndex) -> Result<()> {
    put_recent_index(index)
}

// ============================================================================
// Admin Dashboard: User Index
// ============================================================================

/// Get the user index (list of all uploaders)
pub fn get_user_index() -> Result<UserIndex> {
    let store = open_store()?;

    match store.lookup(USER_INDEX_KEY) {
        Ok(mut lookup_result) => {
            let body = lookup_result.take_body().into_string();
            let index: UserIndex = serde_json::from_str(&body).map_err(|e| {
                BlossomError::MetadataError(format!("Failed to parse user index: {}", e))
            })?;
            Ok(index)
        }
        Err(KVStoreError::ItemNotFound) => Ok(UserIndex::new()),
        Err(e) => Err(BlossomError::MetadataError(format!(
            "Failed to lookup user index: {}",
            e
        ))),
    }
}

/// Store the user index
fn put_user_index(index: &UserIndex) -> Result<()> {
    let store = open_store()?;
    let json = serde_json::to_string(index).map_err(|e| {
        BlossomError::MetadataError(format!("Failed to serialize user index: {}", e))
    })?;

    store
        .insert(USER_INDEX_KEY, json)
        .map_err(|e| BlossomError::MetadataError(format!("Failed to store user index: {}", e)))?;

    Ok(())
}

/// Add a pubkey to the user index (with retry for concurrent writes)
/// Returns true if this is a new user
pub fn add_to_user_index(pubkey: &str) -> Result<bool> {
    let pubkey_lower = pubkey.to_lowercase();

    for attempt in 0..5 {
        let mut index = get_user_index()?;

        // Check if already present
        if index.contains(&pubkey_lower) {
            return Ok(false);
        }

        index.add(pubkey_lower.clone());

        match put_user_index(&index) {
            Ok(()) => return Ok(true),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for user index add: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(BlossomError::MetadataError(
        "Max retries exceeded for user index update".into(),
    ))
}

/// Replace user index entirely (used for backfill)
pub fn replace_user_index(index: &UserIndex) -> Result<()> {
    put_user_index(index)
}
