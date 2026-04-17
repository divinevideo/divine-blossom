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
    let old_status = metadata.status;

    soft_delete_blob(hash, metadata, reason, false)?;

    let physical_deleted = if physical_delete_enabled {
        crate::cleanup_derived_audio_for_source(hash);
        crate::storage::delete_blob(hash).map_err(|e| {
            eprintln!(
                "[req={}] [CREATOR-DELETE] storage::delete_blob failed for {}: {}. \
                 Soft delete applied; bytes may remain on GCS.",
                req_id, hash, e
            );
            e
        })?;
        crate::delete_blob_gcs_artifacts(hash);
        crate::purge_vcl_cache(hash);
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
}
