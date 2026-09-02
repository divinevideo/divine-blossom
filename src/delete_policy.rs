pub use blossom_core::delete_policy::*;

use crate::blossom::BlobMetadata;
use crate::blossom::BlobStatus;
use crate::error::Result;
use crate::metadata::{
    add_to_recent_index, add_to_user_list, get_blob_refs, put_tombstone,
    remove_from_blob_refs_from, remove_from_recent_index, remove_from_recent_index_batch,
    remove_from_user_list, update_blob_status, update_stats_on_remove_batch,
    update_stats_on_status_change, update_user_list_for_vanish,
};
use std::collections::HashMap;

pub fn soft_delete_blob(
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

    crate::purge_edge_cache(hash);
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
        crate::storage::delete_blob_from_fos(hash)
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

    fn put_erasure_evidence(&self, hash: &str) -> Result<()> {
        crate::metadata::put_erasure_evidence(hash)
    }

    fn delete_blob_metadata(&self, hash: &str) -> Result<()> {
        crate::metadata::delete_blob_metadata(hash)
    }

    fn delete_blob_kv_artifacts(&self, hash: &str) {
        crate::delete_blob_kv_artifacts(hash);
    }

    fn put_blob_metadata(&self, metadata: &BlobMetadata) -> Result<()> {
        crate::metadata::put_blob_metadata(metadata)
    }
}

pub(crate) struct PrefetchedVanishOps<'a> {
    metadata: &'a HashMap<String, Option<BlobMetadata>>,
    refs: &'a HashMap<String, Vec<String>>,
}

impl<'a> PrefetchedVanishOps<'a> {
    pub(crate) fn new(
        metadata: &'a HashMap<String, Option<BlobMetadata>>,
        refs: &'a HashMap<String, Vec<String>>,
    ) -> Self {
        Self { metadata, refs }
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
            None => DefaultCreatorDeleteOps.get_blob_metadata(hash),
        }
    }

    fn remove_from_blob_refs(&self, hash: &str, pubkey: &str) -> Result<Vec<String>> {
        remove_from_blob_refs_from(hash, pubkey, self.refs.get(&hash.to_lowercase()).cloned())
    }

    fn put_erasure_evidence(&self, hash: &str) -> Result<()> {
        DefaultCreatorDeleteOps.put_erasure_evidence(hash)
    }

    fn delete_blob_metadata(&self, hash: &str) -> Result<()> {
        DefaultCreatorDeleteOps.delete_blob_metadata(hash)
    }

    fn delete_blob_kv_artifacts(&self, hash: &str) {
        DefaultCreatorDeleteOps.delete_blob_kv_artifacts(hash);
    }

    fn put_blob_metadata(&self, metadata: &BlobMetadata) -> Result<()> {
        DefaultCreatorDeleteOps.put_blob_metadata(metadata)
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
    handle_creator_delete_with_ops(
        hash,
        metadata,
        reason,
        physical_delete_enabled,
        req_id,
        &DefaultCreatorDeleteOps,
    )
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
    crate::purge_edge_cache(hash);

    Ok(())
}
