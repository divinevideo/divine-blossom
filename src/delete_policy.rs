use crate::blossom::BlobMetadata;
use crate::blossom::BlobStatus;
use crate::error::{BlossomError, Result};
use crate::metadata::{
    add_to_recent_index, add_to_user_list, get_blob_refs, put_tombstone, remove_from_recent_index,
    remove_from_user_list, update_blob_status, update_stats_on_status_change,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletePlan {
    SoftDelete,
    UnlinkOnly,
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

    crate::purge_vcl_cache(hash);
    Ok(())
}

/// Outcome of a successful creator-initiated delete. Returned only when the
/// full requested operation completed: soft-delete always, and main GCS byte
/// removal when `physical_delete_enabled`.
///
/// Partial states (soft ok, bytes failed) are not represented here. They
/// surface as `Err` from `handle_creator_delete` so callers get a loud
/// failure signal instead of a silent partial success. The validation-window
/// sweep (blossom#90) is the operational safety net for bytes that remain
/// after a soft-delete when retries do not converge.
#[derive(Debug, Clone)]
pub struct CreatorDeleteOutcome {
    pub old_status: BlobStatus,
    pub physical_delete_enabled: bool,
    pub physical_deleted: bool,
}

/// Side-effects used by `handle_creator_delete`. The default impl
/// (`DefaultCreatorDeleteOps`) forwards to the crate-level functions that
/// talk to Fastly KV, GCS, and the VCL cache. Tests substitute a mock so
/// `handle_creator_delete` can be exercised natively without Viceroy.
pub(crate) trait CreatorDeleteOps {
    fn soft_delete(&self, hash: &str, metadata: &BlobMetadata, reason: &str) -> Result<()>;
    fn cleanup_derived_audio(&self, hash: &str);
    fn delete_blob(&self, hash: &str) -> Result<()>;
    fn delete_blob_gcs_artifacts(&self, hash: &str);
    fn purge_vcl_cache(&self, hash: &str);
}

/// Production-side implementation. Forwards to the real Fastly-backed
/// functions. Only used inside `handle_creator_delete`'s default path.
pub(crate) struct DefaultCreatorDeleteOps;

impl CreatorDeleteOps for DefaultCreatorDeleteOps {
    fn soft_delete(&self, hash: &str, metadata: &BlobMetadata, reason: &str) -> Result<()> {
        soft_delete_blob(hash, metadata, reason, false)
    }
    fn cleanup_derived_audio(&self, hash: &str) {
        crate::cleanup_derived_audio_for_source(hash);
    }
    fn delete_blob(&self, hash: &str) -> Result<()> {
        crate::storage::delete_blob(hash)
    }
    fn delete_blob_gcs_artifacts(&self, hash: &str) {
        crate::delete_blob_gcs_artifacts(hash);
    }
    fn purge_vcl_cache(&self, hash: &str) {
        crate::purge_vcl_cache(hash);
    }
}

/// Shared creator-delete policy. Callers (`/admin/moderate` and
/// `/admin/api/moderate`) are thin adapters over this function.
///
/// `req_id` is a correlation ID extracted or generated at the HTTP entry
/// point; it is included in every log line so retries and partial failures
/// can be traced across stderr. See `crate::req_id` for the contract.
///
/// Returns `Err` on any failure, including:
/// - soft-delete failure (no state mutated)
/// - main GCS byte delete failure when `physical_delete_enabled` (soft-delete
///   already applied; content stopped serving; bytes may remain on GCS)
///
/// On `Err` from byte-delete failure, the status flip to `Deleted` is already
/// durable. A retry by the caller converges: `soft_delete_blob` is a no-op on
/// already-`Deleted` state, and `storage::delete_blob` treats a missing
/// object as success.
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

/// Internal core: runs the creator-delete steps against an injectable
/// `CreatorDeleteOps`. The public `handle_creator_delete` is a thin wrapper
/// that picks `DefaultCreatorDeleteOps`. Visible only to this crate so tests
/// can drive it with a mock.
pub(crate) fn handle_creator_delete_with_ops<O: CreatorDeleteOps>(
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
        ops.cleanup_derived_audio(hash);
        ops.delete_blob(hash).map_err(|e| {
            eprintln!(
                "[req={}] [CREATOR-DELETE] storage::delete_blob failed for {}: {}. \
                 Soft delete applied; bytes may remain on GCS.",
                req_id, hash, e
            );
            e
        })?;
        ops.delete_blob_gcs_artifacts(hash);
        ops.purge_vcl_cache(hash);
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

pub fn restore_soft_deleted_blob(
    hash: &str,
    metadata: &BlobMetadata,
    new_status: BlobStatus,
) -> Result<()> {
    if new_status == BlobStatus::Deleted {
        return Err(BlossomError::BadRequest(
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
    crate::purge_vcl_cache(hash);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::ModerationResult;
    use std::cell::RefCell;

    /// In-memory `CreatorDeleteOps` for unit tests. Records the sequence of
    /// calls so ordering can be asserted, and lets tests preset the
    /// fallible operations' outcomes.
    #[derive(Default)]
    struct MockOps {
        soft_delete_err: Option<BlossomError>,
        delete_blob_err: Option<BlossomError>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl CreatorDeleteOps for MockOps {
        fn soft_delete(&self, _hash: &str, _metadata: &BlobMetadata, _reason: &str) -> Result<()> {
            self.calls.borrow_mut().push("soft_delete");
            match &self.soft_delete_err {
                Some(e) => Err(clone_error(e)),
                None => Ok(()),
            }
        }
        fn cleanup_derived_audio(&self, _hash: &str) {
            self.calls.borrow_mut().push("cleanup_derived_audio");
        }
        fn delete_blob(&self, _hash: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_blob");
            match &self.delete_blob_err {
                Some(e) => Err(clone_error(e)),
                None => Ok(()),
            }
        }
        fn delete_blob_gcs_artifacts(&self, _hash: &str) {
            self.calls.borrow_mut().push("delete_blob_gcs_artifacts");
        }
        fn purge_vcl_cache(&self, _hash: &str) {
            self.calls.borrow_mut().push("purge_vcl_cache");
        }
    }

    /// `BlossomError` doesn't implement `Clone`, so reconstruct the relevant
    /// variants by name+message for the test fixtures.
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
            dim: None,
            transcript_status: None,
            transcript_error_code: None,
            transcript_error_message: None,
            transcript_last_attempt_at: None,
            transcript_retry_after: None,
            transcript_attempt_count: 0,
            transcript_terminal: false,
        }
    }

    const HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const REQ_ID: &str = "test-req-id";

    #[test]
    fn creator_delete_flag_off_does_soft_delete_only_and_reports_physical_deleted_false() {
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps::default();

        let outcome = handle_creator_delete_with_ops(HASH, &metadata, "user", false, REQ_ID, &ops)
            .expect("flag-off path should succeed");

        assert_eq!(outcome.old_status, BlobStatus::Active);
        assert!(!outcome.physical_delete_enabled);
        assert!(!outcome.physical_deleted);
        // Only soft_delete is called when the flag is off. No physical-delete
        // ops, no GCS artifact cleanup, no VCL purge.
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
        // Order matters: soft-delete first (so serving stops even if the
        // byte-delete fails later), then the physical-delete cleanup
        // sequence. GCS artifact cleanup and VCL purge run last, after the
        // main blob byte-delete succeeded.
        assert_eq!(
            *ops.calls.borrow(),
            vec![
                "soft_delete",
                "cleanup_derived_audio",
                "delete_blob",
                "delete_blob_gcs_artifacts",
                "purge_vcl_cache",
            ]
        );
    }

    #[test]
    fn creator_delete_flag_on_byte_delete_failure_returns_err_after_soft_delete_already_applied() {
        // This is the partial-state invariant the issue and helper docstring
        // call out: when main-blob byte-delete fails, the soft-delete call
        // already happened (content stopped serving, status flip durable),
        // and the caller gets a loud `Err` rather than a silent partial
        // success.
        let metadata = sample_metadata(BlobStatus::Active);
        let ops = MockOps {
            delete_blob_err: Some(BlossomError::StorageError("simulated GCS 500".into())),
            ..Default::default()
        };

        let result =
            handle_creator_delete_with_ops(HASH, &metadata, "user", true, REQ_ID, &ops);

        assert!(
            matches!(result, Err(BlossomError::StorageError(ref m)) if m.contains("simulated GCS 500")),
            "expected StorageError propagated from delete_blob, got {:?}",
            result,
        );
        // soft_delete and cleanup_derived_audio ran before delete_blob
        // failed; the cleanup ops that come after delete_blob did NOT run.
        assert_eq!(
            *ops.calls.borrow(),
            vec!["soft_delete", "cleanup_derived_audio", "delete_blob"]
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
        // No physical-delete ops should run when soft-delete failed.
        assert_eq!(*ops.calls.borrow(), vec!["soft_delete"]);
    }

    #[test]
    fn creator_delete_captures_old_status_from_metadata_not_post_soft_delete_state() {
        // `old_status` in the outcome is the status AT ENTRY — this is what
        // the response builder surfaces to callers as the pre-delete state.
        // The mock doesn't mutate metadata, so we can exercise each variant.
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
        // Scenario: caller retries DELETE on a blob that was already soft-deleted.
        // handle_creator_delete returned Ok with old_status=Deleted (no change).
        // physical_deleted reflects the retry's byte-delete outcome.
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
