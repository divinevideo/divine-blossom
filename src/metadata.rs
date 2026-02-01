// ABOUTME: Fastly KV store operations for blob metadata
// ABOUTME: Handles blob metadata and per-user blob lists

use crate::blossom::{BlobMetadata, BlobStatus};
use crate::error::{BlossomError, Result};
use fastly::kv_store::{KVStore, KVStoreError};

/// KV store name (must match fastly.toml)
const KV_STORE_NAME: &str = "blossom_metadata";

/// Key prefix for blob metadata
const BLOB_PREFIX: &str = "blob:";

/// Key prefix for user blob lists
const LIST_PREFIX: &str = "list:";

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

            let metadata: BlobMetadata = serde_json::from_str(&body)
                .map_err(|e| BlossomError::MetadataError(format!("Failed to parse metadata: {}", e)))?;

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
    Err(BlossomError::MetadataError("Max retries exceeded for list update".into()))
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

    Err(BlossomError::MetadataError("Max retries exceeded for list removal".into()))
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
    let mut metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.status = status;
    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Update transcode status for a video blob
pub fn update_transcode_status(hash: &str, status: crate::blossom::TranscodeStatus) -> Result<()> {
    let mut metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.transcode_status = Some(status);
    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Update transcode status and optionally the file size for a video blob
/// The new_size is provided when faststart optimization replaces the original file
pub fn update_transcode_status_with_size(
    hash: &str,
    status: crate::blossom::TranscodeStatus,
    new_size: Option<u64>,
) -> Result<()> {
    let mut metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    metadata.transcode_status = Some(status);

    // Update size if provided (faststart optimization replaced the original file)
    if let Some(size) = new_size {
        metadata.size = size;
    }

    put_blob_metadata(&metadata)?;

    Ok(())
}

/// Check if user owns the blob
pub fn check_ownership(hash: &str, pubkey: &str) -> Result<bool> {
    let metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    Ok(metadata.owner.to_lowercase() == pubkey.to_lowercase())
}

/// Get blobs for listing with optional status filtering
pub fn list_blobs_with_metadata(pubkey: &str, include_restricted: bool) -> Result<Vec<BlobMetadata>> {
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
