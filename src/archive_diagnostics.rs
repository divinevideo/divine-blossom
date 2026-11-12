//! Static diagnostics scoped to one authenticated archive-control batch item.

use crate::error::Result;
use fastly::kv_store::KVStoreError;
use serde::Serialize;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    #[default]
    Operation,
    AdmissionPaused,
    Policy,
    ArchiveRead,
    OwnerList,
    ParentClaim,
    ParentRelease,
    ArchiveAdmissionCas,
    BlobRead,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KvOperation {
    Open,
    Lookup,
    InsertAdd,
    InsertCas,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum KvErrorClass {
    InvalidKey,
    InvalidStoreHandle,
    InvalidStoreOptions,
    ItemBadRequest,
    ItemNotFound,
    ItemPreconditionFailed,
    ItemPayloadTooLarge,
    StoreNotFound,
    TooManyRequests,
    Unexpected,
    Unknown,
}
impl From<&KVStoreError> for KvErrorClass {
    fn from(error: &KVStoreError) -> Self {
        match error {
            KVStoreError::InvalidKey => Self::InvalidKey,
            KVStoreError::InvalidStoreHandle => Self::InvalidStoreHandle,
            KVStoreError::InvalidStoreOptions => Self::InvalidStoreOptions,
            KVStoreError::ItemBadRequest => Self::ItemBadRequest,
            KVStoreError::ItemNotFound => Self::ItemNotFound,
            KVStoreError::ItemPreconditionFailed => Self::ItemPreconditionFailed,
            KVStoreError::ItemPayloadTooLarge => Self::ItemPayloadTooLarge,
            KVStoreError::StoreNotFound(_) => Self::StoreNotFound,
            KVStoreError::TooManyRequests => Self::TooManyRequests,
            KVStoreError::Unexpected(_) => Self::Unexpected,
            _ => Self::Unknown,
        }
    }
}
/// Fixed explanation of why a stage failed, recorded at the deciding branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    /// The parent gate is copying under a different attempt.
    HeldByOtherAttempt,
    /// The parent gate is reserved for erasure.
    Erasing,
    /// The parent gate was already released.
    Released,
    /// A released gate's recorded generation could not be parsed.
    ReleasedGenerationInvalid,
    /// This attempt's own gate write could not be read back.
    MissingAfterWrite,
    /// The gate is absent when this attempt expected to hold it.
    GateMissing,
    /// This attempt holds the gate, but under a different generation.
    GenerationChanged,
    /// A gate record exists but reports no generation.
    GateGenerationMissing,
    /// A gate record exists but is not a valid gate.
    GateRecordInvalid,
    /// Retries re-read the same generation the failed write used.
    CasStaleRead,
    /// Another writer changed the value between retries.
    CasContended,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Diagnostic {
    stage: Stage,
    #[serde(skip_serializing_if = "Option::is_none")]
    kv_operation: Option<KvOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kv_error: Option<KvErrorClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
}
#[derive(Default)]
struct Context {
    stage: Stage,
    diagnostic: Option<Diagnostic>,
}
thread_local! { static ACTIVE: RefCell<Option<Context>> = const { RefCell::new(None) }; }
struct ItemScope(Option<Context>);
impl Drop for ItemScope {
    fn drop(&mut self) {
        ACTIVE.with(|state| *state.borrow_mut() = self.0.take());
    }
}
struct StageScope(Option<Stage>);
impl Drop for StageScope {
    fn drop(&mut self) {
        ACTIVE.with(|state| {
            if let (Some(context), Some(stage)) = (state.borrow_mut().as_mut(), self.0) {
                context.stage = stage;
            }
        });
    }
}
/// Called only after the existing archive token/method/body checks, once per item.
pub(crate) fn item<T>(work: impl FnOnce() -> Result<T>) -> (Result<T>, Option<Diagnostic>) {
    let scope = ItemScope(ACTIVE.with(|state| state.replace(Some(Context::default()))));
    let result = work();
    let diagnostic = if result.is_err() {
        ACTIVE
            .with(|state| {
                state
                    .borrow()
                    .as_ref()
                    .and_then(|context| context.diagnostic)
            })
            .or(Some(Diagnostic {
                stage: Stage::Operation,
                kv_operation: None,
                kv_error: None,
                reason: None,
            }))
    } else {
        None
    };
    drop(scope);
    (result, diagnostic)
}
pub(crate) fn with_stage<T>(stage: Stage, work: impl FnOnce() -> Result<T>) -> Result<T> {
    let previous = ACTIVE.with(|state| {
        state.borrow_mut().as_mut().map(|context| {
            let previous = (context.stage, context.diagnostic);
            context.stage = stage;
            context.diagnostic = None;
            previous
        })
    });
    let scope = StageScope(previous.map(|(stage, _)| stage));
    let result = work();
    ACTIVE.with(|state| {
        if let Some(context) = state.borrow_mut().as_mut() {
            if result.is_ok() {
                context.diagnostic = previous.and_then(|(_, diagnostic)| diagnostic);
            } else if context.diagnostic.is_none() {
                context.diagnostic = Some(Diagnostic {
                    stage,
                    kv_operation: None,
                    kv_error: None,
                    reason: None,
                });
            }
        }
    });
    drop(scope);
    result
}
/// Record why the current stage is failing. Call after its last KV operation;
/// outside an archive item scope this does nothing.
pub(crate) fn note(reason: Reason) {
    ACTIVE.with(|state| {
        if let Some(context) = state.borrow_mut().as_mut() {
            let stage = context.stage;
            context
                .diagnostic
                .get_or_insert(Diagnostic {
                    stage,
                    kv_operation: None,
                    kv_error: None,
                    reason: None,
                })
                .reason = Some(reason);
        }
    });
}
/// Observe the typed provider result at the actual I/O boundary, then return it unchanged.
/// No key, owner, source, token, body, generation, or raw error text enters this state.
pub(crate) fn observe_kv<T>(
    operation: KvOperation,
    result: std::result::Result<T, KVStoreError>,
) -> std::result::Result<T, KVStoreError> {
    ACTIVE.with(|state| {
        if let Some(context) = state.borrow_mut().as_mut() {
            context.diagnostic = match &result {
                Ok(_) | Err(KVStoreError::ItemNotFound) => None,
                Err(error) => Some(Diagnostic {
                    stage: context.stage,
                    kv_operation: Some(operation),
                    kv_error: Some(error.into()),
                    reason: None,
                }),
            };
        }
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BlossomError;
    use fastly::kv_store::KVStoreError;

    fn failing(stage: Stage, operation: KvOperation, error: KVStoreError) -> serde_json::Value {
        let (result, diagnostic) = item(|| {
            with_stage(stage, || {
                observe_kv::<()>(operation, Err(error)).map_err(|_| {
                    BlossomError::MetadataError("synthetic-private-source-token-generation".into())
                })
            })
        });
        assert!(matches!(result, Err(BlossomError::MetadataError(_))));
        serde_json::to_value(diagnostic.unwrap()).unwrap()
    }

    #[test]
    fn archive_diagnostics_simulated_owner_list_and_parent_create_failures_are_static() {
        assert_eq!(
            failing(
                Stage::OwnerList,
                KvOperation::InsertCas,
                KVStoreError::ItemBadRequest
            ),
            serde_json::json!({"stage":"owner_list","kv_operation":"insert_cas","kv_error":"item_bad_request"})
        );
        assert_eq!(
            failing(
                Stage::ParentClaim,
                KvOperation::InsertAdd,
                KVStoreError::TooManyRequests
            ),
            serde_json::json!({"stage":"parent_claim","kv_operation":"insert_add","kv_error":"too_many_requests"})
        );
        let secret = "synthetic-private-source-token-generation";
        let value = failing(
            Stage::ArchiveAdmissionCas,
            KvOperation::Open,
            KVStoreError::StoreNotFound(secret.into()),
        );
        assert_eq!(
            value,
            serde_json::json!({"stage":"archive_admission_cas","kv_operation":"open","kv_error":"store_not_found"})
        );
        assert!(!value.to_string().contains(secret));
    }

    #[test]
    fn archive_diagnostics_preserve_typed_errors_and_clear_between_items() {
        let original = KVStoreError::ItemPreconditionFailed;
        let (result, diagnostic) = item(|| {
            with_stage(Stage::ParentClaim, || {
                assert_eq!(
                    observe_kv::<()>(KvOperation::InsertAdd, Err(original.clone())),
                    Err(original.clone())
                );
                Err::<(), _>(BlossomError::StorageError("private details".into()))
            })
        });
        assert!(matches!(result, Err(BlossomError::StorageError(_))));
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap()["kv_error"],
            "item_precondition_failed"
        );
        let (_, next) = item(|| Err::<(), _>(BlossomError::BadRequest("private input".into())));
        assert_eq!(
            serde_json::to_value(next).unwrap(),
            serde_json::json!({"stage":"operation"})
        );
        let (_, success) = item(|| Ok(()));
        assert!(success.is_none());
        assert!(observe_kv::<()>(KvOperation::Lookup, Err(original)).is_err());
        let (_, clean) = item(|| Err::<(), _>(BlossomError::Forbidden("private policy".into())));
        assert_eq!(
            serde_json::to_value(clean).unwrap(),
            serde_json::json!({"stage":"operation"})
        );
    }

    #[test]
    fn archive_diagnostics_reasons_are_static_labels_attached_to_the_failing_stage() {
        let (_, diagnostic) = item(|| {
            with_stage(Stage::ParentClaim, || {
                let _ = observe_kv::<()>(KvOperation::Lookup, Ok(()));
                note(Reason::HeldByOtherAttempt);
                Err::<(), _>(BlossomError::StorageError("private gate state".into()))
            })
        });
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap(),
            serde_json::json!({"stage":"parent_claim","reason":"held_by_other_attempt"})
        );
        let (_, diagnostic) = item(|| {
            with_stage(Stage::OwnerList, || {
                let _ = observe_kv::<()>(
                    KvOperation::InsertCas,
                    Err(KVStoreError::ItemPreconditionFailed),
                );
                note(Reason::CasStaleRead);
                Err::<(), _>(BlossomError::MetadataError("private list".into()))
            })
        });
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap(),
            serde_json::json!({"stage":"owner_list","kv_operation":"insert_cas","kv_error":"item_precondition_failed","reason":"cas_stale_read"})
        );
        // Outside an archive item, notes are ignored, and they never leak into the next item.
        note(Reason::GateRecordInvalid);
        let (_, clean) = item(|| Err::<(), _>(BlossomError::BadRequest("private input".into())));
        assert_eq!(
            serde_json::to_value(clean).unwrap(),
            serde_json::json!({"stage":"operation"})
        );
    }

    #[test]
    fn archive_diagnostics_recovered_conflicts_do_not_taint_later_failure_or_success() {
        let (_, diagnostic) = item(|| {
            with_stage(Stage::OwnerList, || {
                let _ = observe_kv::<()>(
                    KvOperation::InsertCas,
                    Err(KVStoreError::ItemPreconditionFailed),
                );
                Ok(())
            })?;
            with_stage(Stage::ParentClaim, || {
                Err::<(), _>(BlossomError::StorageError("private gate state".into()))
            })
        });
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap(),
            serde_json::json!({"stage":"parent_claim"})
        );
    }
}
