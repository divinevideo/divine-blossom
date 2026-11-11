pub use blossom_core::delete_policy::*;

use crate::blossom::BlobMetadata;
use crate::blossom::BlobStatus;
use crate::error::Result;
use crate::metadata::{
    add_to_recent_index, add_to_user_list, get_blob_metadata_uncached, get_blob_refs,
    put_tombstone, remove_from_recent_index, remove_from_recent_index_batch, remove_from_user_list,
    update_blob_status, update_stats_on_remove_batch, update_stats_on_status_change,
    update_user_list_for_vanish,
};
use fastly::kv_store::{KVStore, PendingDeleteHandle, PendingInsertHandle, PendingLookupHandle};
use std::collections::HashMap;

pub fn soft_delete_blob(
    hash: &str,
    metadata: &BlobMetadata,
    reason: &str,
    legal_hold: bool,
) -> Result<()> {
    soft_delete_blob_metadata(hash, metadata, reason, legal_hold)?;
    crate::storage::purge_policy_cache(hash)
}

// Physical CDN erasure uses a separate bounded purge drain. Persist denial and
// indexes here without spending purge subrequests before its physical wave.
fn soft_delete_blob_metadata(
    hash: &str,
    metadata: &BlobMetadata,
    reason: &str,
    legal_hold: bool,
) -> Result<()> {
    if metadata.status != BlobStatus::Deleted {
        update_blob_status(hash, BlobStatus::Deleted)?;
        let _ = update_stats_on_status_change(metadata.status, BlobStatus::Deleted);
    }

    let _ = remove_from_user_list(&metadata.owner, hash);
    if let Ok(refs) = get_blob_refs(hash) {
        for pubkey in &refs {
            let _ = remove_from_user_list(pubkey, hash);
        }
    }
    let _ = remove_from_recent_index(hash);

    if legal_hold {
        let _ = put_tombstone(hash, reason);
    }

    Ok(())
}

pub(crate) struct DefaultCreatorDeleteOps;

impl BlobErasureOps for DefaultCreatorDeleteOps {
    fn cleanup_derived_audio(&self, hash: &str) -> Result<()> {
        crate::cleanup_derived_audio_for_source(hash)
    }
    fn delete_blob_from_gcs(&self, hash: &str) -> Result<()> {
        crate::storage::delete_blob(hash)
    }
    fn delete_blob_from_replica(&self, hash: &str) -> Result<()> {
        crate::storage::delete_blob_from_fos(hash)?;
        crate::storage::erase_b2_creator_replica(hash)
    }
    fn delete_blob_gcs_artifacts(&self, hash: &str) -> Result<()> {
        crate::delete_blob_gcs_artifacts(hash)
    }
    fn purge_vcl_cache(&self, hash: &str) {
        crate::purge_edge_cache(hash);
    }
}

impl CreatorDeleteOps for DefaultCreatorDeleteOps {
    fn soft_delete(&self, hash: &str, metadata: &BlobMetadata, reason: &str) -> Result<()> {
        soft_delete_blob(hash, metadata, reason, false)
    }
}

impl VanishBlobOps for DefaultCreatorDeleteOps {
    fn get_blob_metadata(&self, hash: &str) -> Result<Option<BlobMetadata>> {
        crate::metadata::get_blob_metadata(hash)
    }

    fn remove_from_blob_refs(&self, hash: &str, pubkey: &str) -> Result<Vec<String>> {
        crate::metadata::remove_from_blob_refs(hash, pubkey)
    }

    fn put_blob_metadata(&self, metadata: &BlobMetadata) -> Result<()> {
        crate::metadata::put_blob_metadata(metadata)
    }
}

pub(crate) struct PrefetchedVanishOps<'a> {
    metadata: &'a HashMap<String, Option<BlobMetadata>>,
}

impl<'a> PrefetchedVanishOps<'a> {
    pub(crate) fn new(metadata: &'a HashMap<String, Option<BlobMetadata>>) -> Self {
        Self { metadata }
    }
}

impl BlobErasureOps for PrefetchedVanishOps<'_> {
    fn cleanup_derived_audio(&self, hash: &str) -> Result<()> {
        DefaultCreatorDeleteOps.cleanup_derived_audio(hash)
    }
    fn delete_blob_from_gcs(&self, hash: &str) -> Result<()> {
        DefaultCreatorDeleteOps.delete_blob_from_gcs(hash)
    }
    fn delete_blob_from_replica(&self, hash: &str) -> Result<()> {
        DefaultCreatorDeleteOps.delete_blob_from_replica(hash)
    }
    fn delete_blob_gcs_artifacts(&self, hash: &str) -> Result<()> {
        DefaultCreatorDeleteOps.delete_blob_gcs_artifacts(hash)
    }
    fn purge_vcl_cache(&self, hash: &str) {
        DefaultCreatorDeleteOps.purge_vcl_cache(hash);
    }
}

impl VanishBlobOps for PrefetchedVanishOps<'_> {
    fn get_blob_metadata(&self, hash: &str) -> Result<Option<BlobMetadata>> {
        match self.metadata.get(&hash.to_lowercase()) {
            Some(metadata) => Ok(metadata.clone()),
            None => get_blob_metadata_uncached(hash),
        }
    }

    fn remove_from_blob_refs(&self, hash: &str, pubkey: &str) -> Result<Vec<String>> {
        DefaultCreatorDeleteOps.remove_from_blob_refs(hash, pubkey)
    }

    fn put_blob_metadata(&self, metadata: &BlobMetadata) -> Result<()> {
        DefaultCreatorDeleteOps.put_blob_metadata(metadata)
    }
}

pub(crate) struct DefaultVanishWaveOps {
    store: KVStore,
}

impl DefaultVanishWaveOps {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            store: crate::metadata::open_store()?,
        })
    }
}

impl VanishWaveOps for DefaultVanishWaveOps {
    type EvidenceHandle = PendingInsertHandle;
    type MetadataHandle = PendingInsertHandle;
    type ArtifactHandle = PendingDeleteHandle;
    type SubtitleLookupHandle = PendingLookupHandle;

    fn start_evidence(&self, hash: &str) -> Result<Self::EvidenceHandle> {
        crate::metadata::start_vanish_erasure_evidence(&self.store, hash)
    }

    fn finish_evidence(&self, handle: Self::EvidenceHandle) -> Result<()> {
        crate::metadata::finish_vanish_erasure_evidence(&self.store, handle)
    }

    fn start_metadata_delete(&self, hash: &str) -> Result<Self::MetadataHandle> {
        crate::metadata::start_vanish_metadata_delete(&self.store, hash)
    }

    fn finish_metadata_delete(&self, hash: &str, handle: Self::MetadataHandle) -> Result<()> {
        crate::metadata::finish_vanish_metadata_delete(&self.store, hash, handle)
    }

    fn start_artifact_deletes(&self, hash: &str) -> Vec<(String, Result<Self::ArtifactHandle>)> {
        crate::metadata::vanish_blob_artifact_delete_keys(hash)
            .into_iter()
            .map(|key| {
                let pending = crate::metadata::start_vanish_best_effort_delete(&self.store, &key);
                (key, pending)
            })
            .collect()
    }

    fn finish_artifact_delete(&self, handle: Self::ArtifactHandle) -> Result<()> {
        crate::metadata::finish_vanish_best_effort_delete(&self.store, handle)
    }

    fn start_subtitle_lookup(&self, hash: &str) -> Result<Self::SubtitleLookupHandle> {
        crate::metadata::start_vanish_subtitle_job_lookup(&self.store, hash)
    }

    fn finish_subtitle_lookup(&self, handle: Self::SubtitleLookupHandle) -> Result<Option<String>> {
        crate::metadata::finish_vanish_subtitle_job_lookup(&self.store, handle)
    }

    fn start_subtitle_deletes(
        &self,
        hash: &str,
        job_id: &str,
    ) -> Vec<(String, Result<Self::ArtifactHandle>)> {
        crate::metadata::vanish_subtitle_delete_keys(hash, job_id)
            .into_iter()
            .map(|key| {
                let pending = crate::metadata::start_vanish_best_effort_delete(&self.store, &key);
                (key, pending)
            })
            .collect()
    }
}

pub(crate) struct DefaultVanishSharedKeyOps<'a> {
    pubkey: &'a str,
}

impl<'a> DefaultVanishSharedKeyOps<'a> {
    pub(crate) fn new(pubkey: &'a str) -> Self {
        Self { pubkey }
    }
}

impl VanishSharedKeyOps for DefaultVanishSharedKeyOps<'_> {
    fn update_stats_on_remove_batch(&self, metadata: &[BlobMetadata]) {
        if let Err(error) = update_stats_on_remove_batch(metadata) {
            eprintln!(
                "[VANISH] pubkey={} failed to update global stats batch count={}: {error}",
                self.pubkey,
                metadata.len()
            );
        }
    }

    fn remove_from_recent_index_batch(&self, hashes: &[String]) {
        if let Err(error) = remove_from_recent_index_batch(hashes) {
            eprintln!(
                "[VANISH] pubkey={} failed to update recent index batch count={}: {error}",
                self.pubkey,
                hashes.len()
            );
        }
    }

    fn update_user_list_for_vanish(
        &self,
        pubkey: &str,
        removals: &[String],
        retry_hashes: &[String],
    ) -> Result<bool> {
        update_user_list_for_vanish(pubkey, removals, retry_hashes)
    }
}

pub fn handle_creator_delete(
    hash: &str,
    metadata: &BlobMetadata,
    reason: &str,
    physical_delete_enabled: bool,
    req_id: &str,
) -> Result<CreatorDeleteOutcome> {
    if physical_delete_enabled && crate::storage::cdn_invalidation_configured() {
        return handle_phased_creator_delete(hash, metadata, reason);
    }
    handle_creator_delete_with_ops(
        hash,
        metadata,
        reason,
        physical_delete_enabled,
        req_id,
        &DefaultCreatorDeleteOps,
    )
}

fn handle_phased_creator_delete(
    hash: &str,
    metadata: &BlobMetadata,
    reason: &str,
) -> Result<CreatorDeleteOutcome> {
    use crate::error::BlossomError;
    use std::collections::HashMap;

    // Retain the source->audio mapping until BOTH hashes have proven physical
    // absence and a final eviction receipt. Otherwise retries lose discovery.
    let audio = crate::prepare_derived_audio_cleanup(hash)?;
    let mut hashes = vec![hash.to_ascii_lowercase()];
    if let Some(plan) = &audio {
        if !hashes.contains(&plan.audio_hash) {
            hashes.push(plan.audio_hash.clone());
        }
    }
    // A creator source and its one derived audio fit the same two-hash physical
    // request budget as vanish. Purging runs in a SEPARATE drain, never inline.
    if hashes.len() > crate::storage::B2_VANISH_MAX_HASHES_PER_WAVE {
        return Err(BlossomError::StorageError("Creator erasure exceeds bounded wave".into()));
    }
    let mut epochs = HashMap::new();
    for candidate in &hashes {
        let epoch = crate::storage::begin_vanish_phase(candidate)?
            .ok_or_else(|| BlossomError::MetadataError("Creator erasure phase unavailable".into()))?;
        epochs.insert(candidate.clone(), epoch);
    }
    soft_delete_blob_metadata(hash, metadata, reason, false)?;
    let mut physical = Vec::new();
    for candidate in &hashes {
        if crate::storage::vanish_needs_physical(candidate)? {
            physical.push(candidate.clone());
        }
    }
    if !physical.is_empty() {
        let result = crate::storage::erase_vanish_batch(&physical);
        for candidate in &physical {
            crate::storage::finish_vanish_phase(
                candidate, &epochs[candidate], &result.failed_hashes, &result.remaining_hashes,
            )?;
        }
    }
    // A crash after recording absence but before enqueue must remain retryable.
    for candidate in &hashes {
        crate::b2_cdn_phase::ensure_final_intent(candidate)?;
    }
    if hashes.iter().any(|candidate| !crate::storage::vanish_complete(candidate)) {
        return Err(BlossomError::Conflict(
            "Creator erasure pending physical confirmation and final CDN purge; retry required".into(),
        ));
    }
    if let Some(plan) = &audio {
        crate::finalize_derived_audio_cleanup(plan)?;
    }
    for candidate in &hashes {
        if !crate::b2_cdn_phase::mark_complete(candidate)? {
            return Err(BlossomError::Conflict("Creator erasure completion changed; retry required".into()));
        }
    }
    Ok(CreatorDeleteOutcome {
        old_status: metadata.status,
        physical_delete_enabled: true,
        physical_deleted: true,
    })
}

pub fn restore_soft_deleted_blob(
    hash: &str,
    metadata: &BlobMetadata,
    new_status: BlobStatus,
) -> Result<()> {
    if new_status == BlobStatus::Deleted {
        return Err(crate::error::BlossomError::BadRequest(
            "Restore target status cannot be deleted".into(),
        ));
    }

    update_blob_status(hash, new_status)?;
    let _ = update_stats_on_status_change(metadata.status, new_status);

    let _ = add_to_user_list(&metadata.owner, hash);
    if let Ok(refs) = get_blob_refs(hash) {
        for pubkey in &refs {
            let _ = add_to_user_list(pubkey, hash);
        }
    }
    let _ = add_to_recent_index(hash);
    crate::storage::purge_policy_cache(hash)?;

    Ok(())
}
