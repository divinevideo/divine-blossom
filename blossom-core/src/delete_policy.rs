use crate::error::{BlossomError, Result};
use crate::types::{BlobMetadata, BlobStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletePlan {
    SoftDelete,
    UnlinkOnly,
}

/// A vanish request is complete only when no discovered blob needs retry.
pub fn vanish_is_complete(errors: u32) -> bool {
    errors == 0
}

/// Validates that a SHA-256 string is exactly 64 hex characters.
/// Used by both `/admin/moderate` and `/admin/api/moderate` before any
/// metadata lookup.
pub fn validate_sha256_format(sha256: &str) -> Result<()> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }
    Ok(())
}

/// Maps an action string from `/admin/api/moderate` to a `BlobStatus`.
/// Accepts: BAN, BLOCK, RESTRICT, AGE_RESTRICT, AGE_RESTRICTED, APPROVE,
/// ACTIVE, PENDING. DELETE is handled by callers before reaching this.
pub fn map_admin_api_action(action: &str) -> Result<BlobStatus> {
    match action.to_uppercase().as_str() {
        "BAN" | "BLOCK" => Ok(BlobStatus::Banned),
        "RESTRICT" => Ok(BlobStatus::Restricted),
        "AGE_RESTRICT" | "AGE_RESTRICTED" => Ok(BlobStatus::AgeRestricted),
        "APPROVE" | "ACTIVE" => Ok(BlobStatus::Active),
        "PENDING" => Ok(BlobStatus::Pending),
        _ => Err(BlossomError::BadRequest(format!(
            "Unknown action: {}",
            action
        ))),
    }
}

/// Maps an action string from `/admin/moderate` (webhook) to a `BlobStatus`.
/// Accepts: BLOCK, BAN, PERMANENT_BAN, AGE_RESTRICTED, AGE_RESTRICT,
/// RESTRICT, QUARANTINE, APPROVE, SAFE. DELETE is handled by callers
/// before reaching this.
pub fn map_webhook_moderate_action(action: &str) -> Result<BlobStatus> {
    match action.to_uppercase().as_str() {
        "BLOCK" | "BAN" | "PERMANENT_BAN" => Ok(BlobStatus::Banned),
        "AGE_RESTRICTED" | "AGE_RESTRICT" => Ok(BlobStatus::AgeRestricted),
        "RESTRICT" | "QUARANTINE" => Ok(BlobStatus::Restricted),
        "APPROVE" | "SAFE" => Ok(BlobStatus::Active),
        _ => Err(BlossomError::BadRequest(format!(
            "Unknown action: {}. Expected BLOCK, RESTRICT, QUARANTINE, AGE_RESTRICTED, or APPROVE",
            action
        ))),
    }
}

pub fn plan_user_delete(is_owner: bool) -> DeletePlan {
    if is_owner {
        DeletePlan::SoftDelete
    } else {
        DeletePlan::UnlinkOnly
    }
}

pub fn parse_restore_status(status: Option<&str>) -> Result<BlobStatus> {
    match status.unwrap_or("active").to_uppercase().as_str() {
        "APPROVE" | "ACTIVE" => Ok(BlobStatus::Active),
        "PENDING" => Ok(BlobStatus::Pending),
        "RESTRICT" | "RESTRICTED" => Ok(BlobStatus::Restricted),
        "AGE_RESTRICT" | "AGE_RESTRICTED" => Ok(BlobStatus::AgeRestricted),
        "DELETED" => Err(BlossomError::BadRequest(
            "Restore target status cannot be deleted".into(),
        )),
        other => Err(BlossomError::BadRequest(format!(
            "Unknown restore status: {}",
            other
        ))),
    }
}

/// Outcome of a successful creator-initiated delete.
#[derive(Debug, Clone)]
pub struct CreatorDeleteOutcome {
    pub old_status: BlobStatus,
    pub physical_delete_enabled: bool,
    pub physical_deleted: bool,
}

/// Physical-erasure side effects shared by creator deletion and account vanish.
pub trait BlobErasureOps {
    fn cleanup_derived_audio(&self, hash: &str) -> Result<()>;
    fn delete_blob_from_gcs(&self, hash: &str) -> Result<()>;
    fn delete_blob_from_replica(&self, hash: &str) -> Result<()>;
    fn delete_blob_gcs_artifacts(&self, hash: &str) -> Result<()>;
    fn purge_vcl_cache(&self, hash: &str);
}

/// Result of completing one account-vanish list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VanishBlobOutcome {
    /// Every required main and derivative object was confirmed deleted or absent.
    FullyDeleted,
    Unlinked,
}

/// A vanish entry whose bytes must be erased before metadata finalization.
#[derive(Debug)]
pub struct PreparedVanishBlob {
    pub hash: String,
    pub metadata: Option<BlobMetadata>,
}

/// Result of applying the reference and ownership policy to a vanish entry.
#[derive(Debug)]
pub enum PreparedVanishBlobOrOutcome {
    Erase(Box<PreparedVanishBlob>),
    Completed(VanishBlobOutcome),
}

/// Metadata and list side effects needed to vanish one blob.
pub trait VanishBlobOps: BlobErasureOps {
    fn get_blob_metadata(&self, hash: &str) -> Result<Option<BlobMetadata>>;
    fn remove_from_blob_refs(&self, hash: &str, pubkey: &str) -> Result<Vec<String>>;
    fn put_erasure_evidence(&self, hash: &str) -> Result<()>;
    fn delete_blob_metadata(&self, hash: &str) -> Result<()>;
    fn delete_blob_kv_artifacts(&self, hash: &str);
    fn update_stats_on_remove(&self, metadata: &BlobMetadata);
    fn remove_from_recent_index(&self, hash: &str);
    fn put_blob_metadata(&self, metadata: &BlobMetadata) -> Result<()>;
    fn remove_from_user_list(&self, pubkey: &str, hash: &str) -> Result<()>;
}

/// Apply reference and ownership policy before a vanish storage erasure.
pub fn prepare_vanish_blob_with_ops<O: VanishBlobOps>(
    hash: &str,
    pubkey: &str,
    ops: &O,
) -> Result<PreparedVanishBlobOrOutcome> {
    let metadata = ops.get_blob_metadata(hash)?;
    let remaining_refs = ops.remove_from_blob_refs(hash, pubkey)?;
    let other_refs: Vec<String> = remaining_refs
        .into_iter()
        .filter(|reference| !reference.eq_ignore_ascii_case(pubkey))
        .collect();

    match metadata {
        None if !other_refs.is_empty() => {
            ops.remove_from_user_list(pubkey, hash)?;
            Ok(PreparedVanishBlobOrOutcome::Completed(
                VanishBlobOutcome::Unlinked,
            ))
        }
        None => Ok(PreparedVanishBlobOrOutcome::Erase(Box::new(
            PreparedVanishBlob {
                hash: hash.to_string(),
                metadata: None,
            },
        ))),
        Some(metadata) if metadata.owner.eq_ignore_ascii_case(pubkey) && other_refs.is_empty() => {
            Ok(PreparedVanishBlobOrOutcome::Erase(Box::new(
                PreparedVanishBlob {
                    hash: hash.to_string(),
                    metadata: Some(metadata),
                },
            )))
        }
        Some(mut metadata) if metadata.owner.eq_ignore_ascii_case(pubkey) => {
            metadata.owner = other_refs[0].clone();
            ops.put_blob_metadata(&metadata)?;
            ops.remove_from_user_list(pubkey, hash)?;
            Ok(PreparedVanishBlobOrOutcome::Completed(
                VanishBlobOutcome::Unlinked,
            ))
        }
        Some(_) => {
            ops.remove_from_user_list(pubkey, hash)?;
            Ok(PreparedVanishBlobOrOutcome::Completed(
                VanishBlobOutcome::Unlinked,
            ))
        }
    }
}

/// Finalize metadata and list state after storage erasure succeeds.
pub fn finalize_erased_vanish_blob_with_ops<O: VanishBlobOps>(
    blob: &PreparedVanishBlob,
    pubkey: &str,
    ops: &O,
) -> Result<()> {
    ops.put_erasure_evidence(&blob.hash)?;
    if let Some(metadata) = &blob.metadata {
        ops.delete_blob_metadata(&blob.hash)?;
        ops.delete_blob_kv_artifacts(&blob.hash);
        ops.update_stats_on_remove(metadata);
    } else {
        ops.delete_blob_kv_artifacts(&blob.hash);
    }
    ops.remove_from_recent_index(&blob.hash);
    ops.remove_from_user_list(pubkey, &blob.hash)
}

/// Erase a blob from every required origin before invalidating edge caches.
///
/// Both origin DELETEs are idempotent, so a failure can safely be retried after
/// an earlier origin has already confirmed deletion.
pub fn erase_blob_with_ops<O: BlobErasureOps>(hash: &str, req_id: &str, ops: &O) -> Result<()> {
    ops.cleanup_derived_audio(hash)?;
    ops.delete_blob_from_gcs(hash).map_err(|e| {
        eprintln!(
            "[req={}] [ERASURE] GCS delete failed for {}: {}",
            req_id, hash, e
        );
        e
    })?;
    ops.delete_blob_from_replica(hash).map_err(|e| {
        eprintln!(
            "[req={}] [ERASURE] FOS delete failed for {}: {}. GCS may already be deleted; retry is safe.",
            req_id, hash, e
        );
        e
    })?;
    let derivative_result = ops.delete_blob_gcs_artifacts(hash).map_err(|e| {
        eprintln!(
            "[req={}] [ERASURE] derivative delete failed for {}: {}. Retry state preserved.",
            req_id, hash, e
        );
        e
    });
    // Origins are already erased at this point. Purge even when derivative
    // cleanup failed so cached personal media does not survive until retry.
    ops.purge_vcl_cache(hash);
    derivative_result?;
    Ok(())
}

/// Complete one blob entry from an account-vanish request.
pub fn handle_vanish_blob_with_ops<O: VanishBlobOps>(
    hash: &str,
    pubkey: &str,
    req_id: &str,
    ops: &O,
) -> Result<VanishBlobOutcome> {
    match prepare_vanish_blob_with_ops(hash, pubkey, ops)? {
        PreparedVanishBlobOrOutcome::Completed(outcome) => Ok(outcome),
        PreparedVanishBlobOrOutcome::Erase(blob) => {
            erase_blob_with_ops(&blob.hash, req_id, ops)?;
            finalize_erased_vanish_blob_with_ops(&blob, pubkey, ops)?;
            Ok(VanishBlobOutcome::FullyDeleted)
        }
    }
}

/// Side-effects used by `handle_creator_delete_with_ops`. The binary crate
/// provides `DefaultCreatorDeleteOps` (forwards to Fastly KV / GCS / VCL).
/// Tests substitute a mock so the policy logic can run natively.
pub trait CreatorDeleteOps: BlobErasureOps {
    fn soft_delete(&self, hash: &str, metadata: &BlobMetadata, reason: &str) -> Result<()>;
}

/// Core creator-delete policy. Runs the delete steps against an injectable
/// `CreatorDeleteOps`. The binary crate wraps this with
/// `DefaultCreatorDeleteOps` for production use.
pub fn handle_creator_delete_with_ops<O: CreatorDeleteOps>(
    hash: &str,
    metadata: &BlobMetadata,
    reason: &str,
    physical_delete_enabled: bool,
    req_id: &str,
    ops: &O,
) -> Result<CreatorDeleteOutcome> {
    let old_status = metadata.status;

    ops.soft_delete(hash, metadata, reason)?;

    let physical_deleted = if physical_delete_enabled {
        erase_blob_with_ops(hash, req_id, ops)?;
        true
    } else {
        false
    };

    Ok(CreatorDeleteOutcome {
        old_status,
        physical_delete_enabled,
        physical_deleted,
    })
}

/// Build the JSON response body for a successful creator-delete. Both the
/// `/admin/moderate` and `/admin/api/moderate` handlers delegate to this so
/// their response contracts stay identical.
pub fn build_creator_delete_response(
    sha256: &str,
    outcome: &CreatorDeleteOutcome,
) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "sha256": sha256,
        "old_status": outcome.old_status.as_api_str(),
        "new_status": "deleted",
        "physical_deleted": outcome.physical_deleted,
        "physical_delete_skipped": !outcome.physical_delete_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ModerationResult;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct MockOps {
        soft_delete_err: Option<BlossomError>,
        delete_gcs_err: Option<BlossomError>,
        delete_replica_err: Option<BlossomError>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl BlobErasureOps for MockOps {
        fn cleanup_derived_audio(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("cleanup_derived_audio");
            Ok(())
        }
        fn delete_blob_from_gcs(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_from_gcs");
            match &self.delete_gcs_err {
                Some(e) => Err(clone_error(e)),
                None => Ok(()),
            }
        }
        fn delete_blob_from_replica(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_from_replica");
            match &self.delete_replica_err {
                Some(e) => Err(clone_error(e)),
                None => Ok(()),
            }
        }
        fn delete_blob_gcs_artifacts(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_gcs_artifacts");
            Ok(())
        }
        fn purge_vcl_cache(&self, _hash: &str) {
            self.calls.borrow_mut().push("purge_vcl_cache");
        }
    }

    impl CreatorDeleteOps for MockOps {
        fn soft_delete(&self, _hash: &str, _metadata: &BlobMetadata, _reason: &str) -> Result<()> {
            self.calls.borrow_mut().push("soft_delete");
            match &self.soft_delete_err {
                Some(e) => Err(clone_error(e)),
                None => Ok(()),
            }
        }
    }

    fn clone_error(e: &BlossomError) -> BlossomError {
        match e {
            BlossomError::StorageError(m) => BlossomError::StorageError(m.clone()),
            BlossomError::MetadataError(m) => BlossomError::MetadataError(m.clone()),
            BlossomError::Internal(m) => BlossomError::Internal(m.clone()),
            other => BlossomError::Internal(format!("cloned: {:?}", other)),
        }
    }

    fn sample_metadata(status: BlobStatus) -> BlobMetadata {
        BlobMetadata {
            sha256: "0".repeat(64),
            size: 123,
            mime_type: "video/mp4".into(),
            uploaded: "2026-04-22T00:00:00Z".into(),
            owner: "1".repeat(64),
            status,
            thumbnail: None,
            moderation: None::<ModerationResult>,
            transcode_status: None,
            transcode_error_code: None,
            transcode_error_message: None,
            transcode_last_attempt_at: None,
            transcode_retry_after: None,
            transcode_attempt_count: 0,
            transcode_terminal: false,
            transcode_generation: None,
            dim: None,
            transcript_status: None,
            transcript_error_code: None,
            transcript_error_message: None,
            transcript_last_attempt_at: None,
            transcript_retry_after: None,
            transcript_attempt_count: 0,
            transcript_terminal: false,
            transcript_generation: None,
        }
    }

    const HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const REQ_ID: &str = "test-req-id";

    #[derive(Default)]
    struct MockVanishOps {
        metadata: RefCell<Option<BlobMetadata>>,
        refs: RefCell<Vec<String>>,
        cleanup_audio_err: bool,
        delete_replica_err: bool,
        delete_artifacts_err: bool,
        put_erasure_evidence_err: bool,
        delete_metadata_err: bool,
        remove_user_list_err: Cell<bool>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl BlobErasureOps for MockVanishOps {
        fn cleanup_derived_audio(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("cleanup_derived_audio");
            if self.cleanup_audio_err {
                Err(BlossomError::StorageError("audio cleanup failed".into()))
            } else {
                Ok(())
            }
        }
        fn delete_blob_from_gcs(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_from_gcs");
            Ok(())
        }
        fn delete_blob_from_replica(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_from_replica");
            if self.delete_replica_err {
                Err(BlossomError::StorageError("replica failed".into()))
            } else {
                Ok(())
            }
        }
        fn delete_blob_gcs_artifacts(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_gcs_artifacts");
            if self.delete_artifacts_err {
                Err(BlossomError::StorageError("derivative failed".into()))
            } else {
                Ok(())
            }
        }
        fn purge_vcl_cache(&self, _hash: &str) {
            self.calls.borrow_mut().push("purge_vcl_cache");
        }
    }

    impl VanishBlobOps for MockVanishOps {
        fn get_blob_metadata(&self, _hash: &str) -> Result<Option<BlobMetadata>> {
            self.calls.borrow_mut().push("get_blob_metadata");
            Ok(self.metadata.borrow().clone())
        }
        fn remove_from_blob_refs(&self, _hash: &str, pubkey: &str) -> Result<Vec<String>> {
            self.calls.borrow_mut().push("remove_from_blob_refs");
            self.refs
                .borrow_mut()
                .retain(|reference| !reference.eq_ignore_ascii_case(pubkey));
            Ok(self.refs.borrow().clone())
        }
        fn delete_blob_metadata(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob_metadata");
            if self.delete_metadata_err {
                Err(BlossomError::MetadataError("metadata failed".into()))
            } else {
                self.metadata.borrow_mut().take();
                Ok(())
            }
        }
        fn put_erasure_evidence(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("put_erasure_evidence");
            if self.put_erasure_evidence_err {
                Err(BlossomError::MetadataError(
                    "erasure evidence failed".into(),
                ))
            } else {
                Ok(())
            }
        }
        fn delete_blob_kv_artifacts(&self, _hash: &str) {
            self.calls.borrow_mut().push("delete_blob_kv_artifacts");
        }
        fn update_stats_on_remove(&self, _metadata: &BlobMetadata) {
            self.calls.borrow_mut().push("update_stats_on_remove");
        }
        fn remove_from_recent_index(&self, _hash: &str) {
            self.calls.borrow_mut().push("remove_from_recent_index");
        }
        fn put_blob_metadata(&self, metadata: &BlobMetadata) -> Result<()> {
            self.calls.borrow_mut().push("put_blob_metadata");
            *self.metadata.borrow_mut() = Some(metadata.clone());
            Ok(())
        }
        fn remove_from_user_list(&self, _pubkey: &str, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("remove_from_user_list");
            if self.remove_user_list_err.get() {
                Err(BlossomError::MetadataError("user list failed".into()))
            } else {
                Ok(())
            }
        }
    }

    fn vanish_ops_with_owner() -> MockVanishOps {
        MockVanishOps {
            metadata: RefCell::new(Some(sample_metadata(BlobStatus::Active))),
            refs: RefCell::new(vec!["1".repeat(64)]),
            ..Default::default()
        }
    }

    #[test]
    fn vanish_batch_policy_prepares_then_finalizes_a_sole_owner() {
        let ops = vanish_ops_with_owner();

        let blob = match prepare_vanish_blob_with_ops(HASH, &"1".repeat(64), &ops)
            .expect("sole-owner preparation should succeed")
        {
            PreparedVanishBlobOrOutcome::Erase(blob) => blob,
            PreparedVanishBlobOrOutcome::Completed(_) => panic!("sole owner must be erased"),
        };

        assert_eq!(
            *ops.calls.borrow(),
            vec!["get_blob_metadata", "remove_from_blob_refs"]
        );
        finalize_erased_vanish_blob_with_ops(&blob, &"1".repeat(64), &ops)
            .expect("sole-owner finalization should succeed");
        assert_eq!(
            *ops.calls.borrow(),
            vec![
                "get_blob_metadata",
                "remove_from_blob_refs",
                "put_erasure_evidence",
                "delete_blob_metadata",
                "delete_blob_kv_artifacts",
                "update_stats_on_remove",
                "remove_from_recent_index",
                "remove_from_user_list",
            ]
        );
    }

    #[test]
    fn vanish_replica_failure_preserves_metadata_and_list_entry() {
        let ops = MockVanishOps {
            delete_replica_err: true,
            ..vanish_ops_with_owner()
        };

        let result = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops);

        assert!(matches!(result, Err(BlossomError::StorageError(_))));
        assert!(ops.metadata.borrow().is_some());
        assert!(!ops.calls.borrow().contains(&"delete_blob_metadata"));
        assert!(!ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn vanish_audio_cleanup_failure_preserves_metadata_and_list_entry() {
        let ops = MockVanishOps {
            cleanup_audio_err: true,
            ..vanish_ops_with_owner()
        };

        let result = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops);

        assert!(matches!(result, Err(BlossomError::StorageError(_))));
        assert!(ops.metadata.borrow().is_some());
        assert!(!ops.calls.borrow().contains(&"delete_blob_from_gcs"));
        assert!(!ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn vanish_derivative_failure_preserves_metadata_and_list_entry() {
        let ops = MockVanishOps {
            delete_artifacts_err: true,
            ..vanish_ops_with_owner()
        };

        let result = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops);

        assert!(matches!(result, Err(BlossomError::StorageError(_))));
        assert!(ops.metadata.borrow().is_some());
        assert!(ops.calls.borrow().contains(&"purge_vcl_cache"));
        assert!(!ops.calls.borrow().contains(&"delete_blob_metadata"));
        assert!(!ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn vanish_continues_other_hashes_after_a_derivative_failure() {
        let failed = MockVanishOps {
            delete_artifacts_err: true,
            ..vanish_ops_with_owner()
        };
        let completed = vanish_ops_with_owner();

        let first = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &failed);
        let second = handle_vanish_blob_with_ops(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            &"1".repeat(64),
            REQ_ID,
            &completed,
        );

        assert!(first.is_err());
        assert_eq!(
            second.expect("absent derivatives are successful deletes"),
            VanishBlobOutcome::FullyDeleted
        );
        assert!(failed.metadata.borrow().is_some());
        assert!(completed.metadata.borrow().is_none());
    }

    #[test]
    fn vanish_evidence_failure_preserves_metadata_and_list_entry() {
        let ops = MockVanishOps {
            put_erasure_evidence_err: true,
            ..vanish_ops_with_owner()
        };

        let result = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops);

        assert!(matches!(result, Err(BlossomError::MetadataError(_))));
        assert!(ops.metadata.borrow().is_some());
        assert!(!ops.calls.borrow().contains(&"delete_blob_metadata"));
        assert!(!ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn vanish_metadata_failure_does_not_remove_list_entry() {
        let ops = MockVanishOps {
            delete_metadata_err: true,
            ..vanish_ops_with_owner()
        };

        let result = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops);

        assert!(matches!(result, Err(BlossomError::MetadataError(_))));
        assert!(!ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn vanish_list_failure_after_metadata_delete_retries_as_metadata_less_erasure() {
        let first = MockVanishOps {
            remove_user_list_err: Cell::new(true),
            ..vanish_ops_with_owner()
        };

        let first_result = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &first);
        assert!(matches!(first_result, Err(BlossomError::MetadataError(_))));
        assert!(first.metadata.borrow().is_none());
        assert!(first.refs.borrow().is_empty());

        first.remove_user_list_err.set(false);
        first.calls.borrow_mut().clear();
        let retry_outcome = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &first)
            .expect("metadata-less retry should converge");

        assert_eq!(retry_outcome, VanishBlobOutcome::FullyDeleted);
        assert_eq!(
            *first.calls.borrow(),
            vec![
                "get_blob_metadata",
                "remove_from_blob_refs",
                "cleanup_derived_audio",
                "delete_blob_from_gcs",
                "delete_blob_from_replica",
                "delete_blob_gcs_artifacts",
                "purge_vcl_cache",
                "put_erasure_evidence",
                "delete_blob_kv_artifacts",
                "remove_from_recent_index",
                "remove_from_user_list",
            ]
        );
    }

    #[test]
    fn vanish_metadata_less_shared_blob_unlinks_without_erasing() {
        let ops = MockVanishOps {
            metadata: RefCell::new(None),
            refs: RefCell::new(vec!["1".repeat(64), "2".repeat(64)]),
            ..Default::default()
        };

        let outcome = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops)
            .expect("shared metadata-less blob should unlink");

        assert_eq!(outcome, VanishBlobOutcome::Unlinked);
        assert!(!ops.calls.borrow().contains(&"delete_blob_from_gcs"));
        assert!(ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn vanish_owner_transfers_shared_blob_before_removing_list_entry() {
        let ops = MockVanishOps {
            metadata: RefCell::new(Some(sample_metadata(BlobStatus::Active))),
            refs: RefCell::new(vec!["1".repeat(64), "2".repeat(64)]),
            ..Default::default()
        };

        let outcome = handle_vanish_blob_with_ops(HASH, &"1".repeat(64), REQ_ID, &ops)
            .expect("shared owner should transfer the blob");

        assert_eq!(outcome, VanishBlobOutcome::Unlinked);
        assert_eq!(
            ops.metadata.borrow().as_ref().unwrap().owner,
            "2".repeat(64)
        );
        assert_eq!(
            &ops.calls.borrow()[2..],
            &["put_blob_metadata", "remove_from_user_list"]
        );
    }

    #[test]
    fn vanish_non_owner_unlinks_without_changing_metadata() {
        let ops = MockVanishOps {
            metadata: RefCell::new(Some(sample_metadata(BlobStatus::Active))),
            refs: RefCell::new(vec!["1".repeat(64), "2".repeat(64)]),
            ..Default::default()
        };

        let outcome = handle_vanish_blob_with_ops(HASH, &"2".repeat(64), REQ_ID, &ops)
            .expect("non-owner should unlink");

        assert_eq!(outcome, VanishBlobOutcome::Unlinked);
        assert_eq!(
            ops.metadata.borrow().as_ref().unwrap().owner,
            "1".repeat(64)
        );
        assert!(!ops.calls.borrow().contains(&"put_blob_metadata"));
        assert!(ops.calls.borrow().contains(&"remove_from_user_list"));
    }

    #[test]
    fn creator_delete_flag_off_does_soft_delete_only_and_reports_physical_deleted_false() {
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps::default();

        let outcome = handle_creator_delete_with_ops(HASH, &metadata, "user", false, REQ_ID, &ops)
            .expect("flag-off path should succeed");

        assert_eq!(outcome.old_status, BlobStatus::Active);
        assert!(!outcome.physical_delete_enabled);
        assert!(!outcome.physical_deleted);
        assert_eq!(*ops.calls.borrow(), vec!["soft_delete"]);
    }

    #[test]
    fn creator_delete_flag_on_success_does_full_sequence_in_order() {
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps::default();

        let outcome = handle_creator_delete_with_ops(HASH, &metadata, "user", true, REQ_ID, &ops)
            .expect("flag-on success path should succeed");

        assert_eq!(outcome.old_status, BlobStatus::Active);
        assert!(outcome.physical_delete_enabled);
        assert!(outcome.physical_deleted);
        assert_eq!(
            *ops.calls.borrow(),
            vec![
                "soft_delete",
                "cleanup_derived_audio",
                "delete_blob_from_gcs",
                "delete_blob_from_replica",
                "delete_blob_gcs_artifacts",
                "purge_vcl_cache",
            ]
        );
    }

    #[test]
    fn creator_delete_flag_on_byte_delete_failure_returns_err_after_soft_delete_already_applied() {
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps {
            delete_gcs_err: Some(BlossomError::StorageError("simulated GCS 500".into())),
            ..Default::default()
        };

        let result = handle_creator_delete_with_ops(HASH, &metadata, "user", true, REQ_ID, &ops);

        assert!(
            matches!(result, Err(BlossomError::StorageError(ref m)) if m.contains("simulated GCS 500")),
            "expected StorageError propagated from delete_blob, got {:?}",
            result,
        );
        assert_eq!(
            *ops.calls.borrow(),
            vec![
                "soft_delete",
                "cleanup_derived_audio",
                "delete_blob_from_gcs"
            ]
        );
    }

    #[test]
    fn creator_delete_replica_failure_is_retryable_and_does_not_purge() {
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps {
            delete_replica_err: Some(BlossomError::StorageError("simulated FOS 403".into())),
            ..Default::default()
        };

        let result = handle_creator_delete_with_ops(HASH, &metadata, "user", true, REQ_ID, &ops);

        assert!(
            matches!(result, Err(BlossomError::StorageError(ref m)) if m.contains("simulated FOS 403")),
            "expected FOS StorageError to propagate, got {:?}",
            result,
        );
        assert_eq!(
            *ops.calls.borrow(),
            vec![
                "soft_delete",
                "cleanup_derived_audio",
                "delete_blob_from_gcs",
                "delete_blob_from_replica",
            ]
        );
    }

    #[test]
    fn creator_delete_soft_delete_failure_short_circuits_before_any_physical_ops() {
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps {
            soft_delete_err: Some(BlossomError::MetadataError("simulated KV failure".into())),
            ..Default::default()
        };

        let result = handle_creator_delete_with_ops(HASH, &metadata, "user", true, REQ_ID, &ops);

        assert!(
            matches!(result, Err(BlossomError::MetadataError(ref m)) if m.contains("simulated KV failure")),
            "expected MetadataError propagated from soft_delete, got {:?}",
            result,
        );
        assert_eq!(*ops.calls.borrow(), vec!["soft_delete"]);
    }

    #[test]
    fn creator_delete_captures_old_status_from_metadata_not_post_soft_delete_state() {
        for (status, expected) in &[
            (BlobStatus::Active, BlobStatus::Active),
            (BlobStatus::Restricted, BlobStatus::Restricted),
            (BlobStatus::AgeRestricted, BlobStatus::AgeRestricted),
            (BlobStatus::Pending, BlobStatus::Pending),
            (BlobStatus::Banned, BlobStatus::Banned),
            (BlobStatus::Deleted, BlobStatus::Deleted),
        ] {
            let metadata = sample_metadata(*status);
            let ops = MockOps::default();
            let outcome =
                handle_creator_delete_with_ops(HASH, &metadata, "user", false, REQ_ID, &ops)
                    .expect("metadata-only path should succeed");
            assert_eq!(outcome.old_status, *expected);
        }
    }

    #[test]
    fn owner_delete_plan_is_soft_delete_not_hard_delete() {
        assert_eq!(plan_user_delete(true), DeletePlan::SoftDelete);
    }

    #[test]
    fn non_owner_delete_plan_unlinks_only() {
        assert_eq!(plan_user_delete(false), DeletePlan::UnlinkOnly);
    }

    #[test]
    fn vanish_completion_requires_zero_errors() {
        assert!(vanish_is_complete(0));
        assert!(!vanish_is_complete(1));
        assert!(!vanish_is_complete(u32::MAX));
    }

    #[test]
    fn restore_target_rejects_deleted_status() {
        assert!(parse_restore_status(Some("deleted")).is_err());
    }

    #[test]
    fn restore_from_deleted_allows_active_pending_or_restricted() {
        assert_eq!(parse_restore_status(None).unwrap(), BlobStatus::Active);
        assert_eq!(
            parse_restore_status(Some("pending")).unwrap(),
            BlobStatus::Pending
        );
        assert_eq!(
            parse_restore_status(Some("restricted")).unwrap(),
            BlobStatus::Restricted
        );
    }

    #[test]
    fn restore_target_accepts_age_restricted() {
        assert_eq!(
            parse_restore_status(Some("age_restricted")).unwrap(),
            BlobStatus::AgeRestricted
        );
        assert_eq!(
            parse_restore_status(Some("AGE_RESTRICTED")).unwrap(),
            BlobStatus::AgeRestricted
        );
        assert_eq!(
            parse_restore_status(Some("age_restrict")).unwrap(),
            BlobStatus::AgeRestricted
        );
    }

    #[test]
    fn response_builder_active_blob_flag_off() {
        let outcome = CreatorDeleteOutcome {
            old_status: BlobStatus::Active,
            physical_delete_enabled: false,
            physical_deleted: false,
        };
        let body = build_creator_delete_response(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &outcome,
        );
        assert_eq!(body["success"], serde_json::json!(true));
        assert_eq!(
            body["sha256"],
            serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(body["old_status"], serde_json::json!("active"));
        assert_eq!(body["new_status"], serde_json::json!("deleted"));
        assert_eq!(body["physical_deleted"], serde_json::json!(false));
        assert_eq!(body["physical_delete_skipped"], serde_json::json!(true));
    }

    #[test]
    fn response_builder_active_blob_flag_on_physical_success() {
        let outcome = CreatorDeleteOutcome {
            old_status: BlobStatus::Active,
            physical_delete_enabled: true,
            physical_deleted: true,
        };
        let body = build_creator_delete_response(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &outcome,
        );
        assert_eq!(body["physical_deleted"], serde_json::json!(true));
        assert_eq!(body["physical_delete_skipped"], serde_json::json!(false));
        assert_eq!(body["old_status"], serde_json::json!("active"));
        assert_eq!(body["new_status"], serde_json::json!("deleted"));
    }

    #[test]
    fn response_builder_already_deleted_blob_idempotent_retry() {
        let outcome = CreatorDeleteOutcome {
            old_status: BlobStatus::Deleted,
            physical_delete_enabled: true,
            physical_deleted: true,
        };
        let body = build_creator_delete_response(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            &outcome,
        );
        assert_eq!(body["old_status"], serde_json::json!("deleted"));
        assert_eq!(body["new_status"], serde_json::json!("deleted"));
        assert_eq!(body["physical_deleted"], serde_json::json!(true));
        assert_eq!(body["physical_delete_skipped"], serde_json::json!(false));
    }

    // ── validate_sha256_format ────────────────────────────────────────

    #[test]
    fn sha256_valid_lowercase_hex_passes() {
        validate_sha256_format(&"a".repeat(64)).unwrap();
    }

    #[test]
    fn sha256_valid_uppercase_hex_passes() {
        validate_sha256_format(&"A".repeat(64)).unwrap();
    }

    #[test]
    fn sha256_valid_mixed_case_passes() {
        validate_sha256_format("aAbBcCdDeEfF0011223344556677889900112233445566778899aAbBcCdDeEfF")
            .unwrap();
    }

    #[test]
    fn sha256_too_short_returns_bad_request() {
        let result = validate_sha256_format(&"a".repeat(63));
        assert!(matches!(result, Err(BlossomError::BadRequest(_))));
    }

    #[test]
    fn sha256_too_long_returns_bad_request() {
        let result = validate_sha256_format(&"a".repeat(65));
        assert!(matches!(result, Err(BlossomError::BadRequest(_))));
    }

    #[test]
    fn sha256_empty_returns_bad_request() {
        let result = validate_sha256_format("");
        assert!(matches!(result, Err(BlossomError::BadRequest(_))));
    }

    #[test]
    fn sha256_non_hex_chars_return_bad_request() {
        let mut bad = "a".repeat(62);
        bad.push_str("zz");
        let result = validate_sha256_format(&bad);
        assert!(matches!(result, Err(BlossomError::BadRequest(_))));
    }

    #[test]
    fn sha256_with_spaces_returns_bad_request() {
        let result = validate_sha256_format(&format!("{} {}", "a".repeat(32), "b".repeat(31)));
        assert!(matches!(result, Err(BlossomError::BadRequest(_))));
    }

    // ── map_admin_api_action (/admin/api/moderate) ──────────────────

    #[test]
    fn admin_api_ban_aliases_map_to_banned() {
        for action in &["BAN", "BLOCK", "ban", "Block"] {
            assert_eq!(
                map_admin_api_action(action).unwrap(),
                BlobStatus::Banned,
                "{action} should map to Banned"
            );
        }
    }

    #[test]
    fn admin_api_restrict_maps_to_restricted() {
        assert_eq!(
            map_admin_api_action("RESTRICT").unwrap(),
            BlobStatus::Restricted
        );
        assert_eq!(
            map_admin_api_action("restrict").unwrap(),
            BlobStatus::Restricted
        );
    }

    #[test]
    fn admin_api_does_not_accept_quarantine() {
        assert!(matches!(
            map_admin_api_action("QUARANTINE"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn admin_api_does_not_accept_permanent_ban() {
        assert!(matches!(
            map_admin_api_action("PERMANENT_BAN"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn admin_api_does_not_accept_safe() {
        assert!(matches!(
            map_admin_api_action("SAFE"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn admin_api_age_restrict_aliases_map_to_age_restricted() {
        for action in &["AGE_RESTRICT", "AGE_RESTRICTED", "age_restrict"] {
            assert_eq!(
                map_admin_api_action(action).unwrap(),
                BlobStatus::AgeRestricted,
                "{action} should map to AgeRestricted"
            );
        }
    }

    #[test]
    fn admin_api_approve_aliases_map_to_active() {
        for action in &["APPROVE", "ACTIVE", "approve", "Active"] {
            assert_eq!(
                map_admin_api_action(action).unwrap(),
                BlobStatus::Active,
                "{action} should map to Active"
            );
        }
    }

    #[test]
    fn admin_api_pending_maps_to_pending() {
        assert_eq!(
            map_admin_api_action("PENDING").unwrap(),
            BlobStatus::Pending
        );
        assert_eq!(
            map_admin_api_action("pending").unwrap(),
            BlobStatus::Pending
        );
    }

    #[test]
    fn admin_api_unknown_returns_bad_request() {
        let result = map_admin_api_action("OBLITERATE");
        match result {
            Err(BlossomError::BadRequest(msg)) => assert!(
                msg.contains("OBLITERATE"),
                "error should include the unknown action name, got: {msg}"
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn admin_api_delete_is_not_handled() {
        assert!(matches!(
            map_admin_api_action("DELETE"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    // ── map_webhook_moderate_action (/admin/moderate) ─────────────────

    #[test]
    fn webhook_ban_aliases_map_to_banned() {
        for action in &["BLOCK", "BAN", "PERMANENT_BAN", "block", "permanent_ban"] {
            assert_eq!(
                map_webhook_moderate_action(action).unwrap(),
                BlobStatus::Banned,
                "{action} should map to Banned"
            );
        }
    }

    #[test]
    fn webhook_restrict_aliases_map_to_restricted() {
        for action in &["RESTRICT", "QUARANTINE", "restrict", "Quarantine"] {
            assert_eq!(
                map_webhook_moderate_action(action).unwrap(),
                BlobStatus::Restricted,
                "{action} should map to Restricted"
            );
        }
    }

    #[test]
    fn webhook_age_restrict_aliases_map_to_age_restricted() {
        for action in &["AGE_RESTRICTED", "AGE_RESTRICT", "age_restricted"] {
            assert_eq!(
                map_webhook_moderate_action(action).unwrap(),
                BlobStatus::AgeRestricted,
                "{action} should map to AgeRestricted"
            );
        }
    }

    #[test]
    fn webhook_approve_aliases_map_to_active() {
        for action in &["APPROVE", "SAFE", "approve", "safe"] {
            assert_eq!(
                map_webhook_moderate_action(action).unwrap(),
                BlobStatus::Active,
                "{action} should map to Active"
            );
        }
    }

    #[test]
    fn webhook_does_not_accept_active() {
        assert!(matches!(
            map_webhook_moderate_action("ACTIVE"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn webhook_does_not_accept_pending() {
        assert!(matches!(
            map_webhook_moderate_action("PENDING"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn webhook_unknown_returns_specific_error_message() {
        let result = map_webhook_moderate_action("OBLITERATE");
        match result {
            Err(BlossomError::BadRequest(msg)) => {
                assert!(
                    msg.contains("OBLITERATE"),
                    "error should include the unknown action name, got: {msg}"
                );
                assert!(
                    msg.contains(
                        "Expected BLOCK, RESTRICT, QUARANTINE, AGE_RESTRICTED, or APPROVE"
                    ),
                    "webhook error should list expected actions, got: {msg}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn webhook_delete_is_not_handled() {
        assert!(matches!(
            map_webhook_moderate_action("DELETE"),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn admin_api_and_webhook_empty_string_returns_bad_request() {
        assert!(matches!(
            map_admin_api_action(""),
            Err(BlossomError::BadRequest(_))
        ));
        assert!(matches!(
            map_webhook_moderate_action(""),
            Err(BlossomError::BadRequest(_))
        ));
    }

    #[test]
    fn response_builder_old_status_covers_every_blob_status_variant() {
        let cases: &[(BlobStatus, &str)] = &[
            (BlobStatus::Active, "active"),
            (BlobStatus::Restricted, "restricted"),
            (BlobStatus::Pending, "pending"),
            (BlobStatus::Banned, "banned"),
            (BlobStatus::Deleted, "deleted"),
            (BlobStatus::AgeRestricted, "age_restricted"),
        ];
        for (status, expected) in cases {
            let outcome = CreatorDeleteOutcome {
                old_status: *status,
                physical_delete_enabled: false,
                physical_deleted: false,
            };
            let body = build_creator_delete_response(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                &outcome,
            );
            assert_eq!(
                body["old_status"],
                serde_json::json!(expected),
                "BlobStatus::{:?} should render as {:?}",
                status,
                expected
            );
        }
    }
}
