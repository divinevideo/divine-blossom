use blossom_core::conditional_update::{
    update_json_conditionally_with_io, ConditionalJsonMutation,
};
use blossom_core::quarantine::{mutate_holds, QuarantineAction, QuarantineHolds};
use blossom_core::types::{BlobAccess, BlobMetadata, BlobStatus};
use std::cell::{Cell, RefCell};

fn metadata(status: BlobStatus) -> BlobMetadata {
    serde_json::from_value(serde_json::json!({
        "sha256": "a".repeat(64), "size": 10, "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z", "owner": "b".repeat(64), "status": status
    }))
    .unwrap()
}

fn apply(current: Option<QuarantineHolds>, id: &str, action: QuarantineAction) -> QuarantineHolds {
    match mutate_holds(
        current,
        id,
        match action {
            QuarantineAction::Hold => 1,
            QuarantineAction::Release => 2,
        },
        action,
    )
    .unwrap()
    {
        ConditionalJsonMutation::Complete(holds) => holds,
        ConditionalJsonMutation::Write {
            value,
            time_to_live,
            ..
        } => {
            assert!(time_to_live.is_none(), "holds must not expire");
            value
        }
    }
}

#[test]
fn releasing_one_hold_preserves_other_holds_and_is_idempotent() {
    let holds = apply(None, "review:first", QuarantineAction::Hold);
    let holds = apply(Some(holds), "review:second", QuarantineAction::Hold);
    let holds = apply(Some(holds), "review:first", QuarantineAction::Release);
    assert_eq!(holds.active_ids(), vec!["review:second"]);
    let holds = apply(Some(holds), "review:first", QuarantineAction::Release);
    assert_eq!(holds.active_ids().len(), 1);
    let holds = apply(Some(holds), "review:second", QuarantineAction::Release);
    assert!(holds.active_ids().is_empty());
}

#[test]
fn holds_deny_anonymous_owner_and_other_viewers_but_allow_admin_review() {
    for status in [
        BlobStatus::Active,
        BlobStatus::Pending,
        BlobStatus::Restricted,
        BlobStatus::AgeRestricted,
        BlobStatus::Banned,
        BlobStatus::Deleted,
    ] {
        let mut meta = metadata(status);
        meta.quarantine_hold_ids = vec!["review:review".into()];
        assert_eq!(meta.access_for(None, false), BlobAccess::NotFound);
        assert_eq!(
            meta.access_for(Some(&"b".repeat(64)), false),
            BlobAccess::NotFound
        );
        assert_eq!(
            meta.access_for(Some(&"c".repeat(64)), false),
            BlobAccess::NotFound
        );
        assert_eq!(meta.access_for(None, true), BlobAccess::Allowed);
        assert_eq!(meta.status, status, "overlay must preserve the base status");
        meta.quarantine_hold_ids.clear();
        assert_eq!(
            meta.access_for(None, false),
            metadata(status).access_for(None, false)
        );
    }
}

#[test]
fn ordinary_metadata_writes_never_persist_or_accept_hold_overlay() {
    let mut meta = metadata(BlobStatus::AgeRestricted);
    meta.quarantine_hold_ids = vec!["review:review".into()];
    let json = serde_json::to_value(meta).unwrap();
    assert_eq!(json["status"], "age_restricted");
    assert!(json.get("quarantine_hold_ids").is_none());
    let mut forged = json;
    forged["quarantine_hold_ids"] = serde_json::json!(["untrusted"]);
    let decoded: BlobMetadata = serde_json::from_value(forged).unwrap();
    assert!(decoded.quarantine_hold_ids.is_empty());
}

#[test]
fn retrying_a_racing_hold_preserves_the_concurrent_hold() {
    let reads = Cell::new(0);
    let written = RefCell::new(None);
    let result = update_json_conditionally_with_io(
        3,
        "quarantine holds",
        |current| mutate_holds(current, "review:first", 1, QuarantineAction::Hold),
        || {
            let attempt = reads.get();
            reads.set(attempt + 1);
            if attempt == 0 {
                Ok(None)
            } else {
                Ok(Some((
                    r#"{"version":1,"holds":{"review:second":{"version":1,"active":true}}}"#.into(),
                    2,
                )))
            }
        },
        |value, generation, ttl| {
            assert!(ttl.is_none());
            if generation.is_none() {
                Ok(false)
            } else {
                assert_eq!(generation, Some(2));
                *written.borrow_mut() = Some(value);
                Ok(true)
            }
        },
    )
    .unwrap();
    assert_eq!(reads.get(), 2);
    assert_eq!(result.active_ids().len(), 2);
    let persisted: QuarantineHolds =
        serde_json::from_str(written.borrow().as_ref().unwrap()).unwrap();
    assert_eq!(persisted.active_ids(), result.active_ids());
}

#[test]
fn hold_ids_and_persisted_state_are_validated() {
    for id in ["", "contains space", "../escape", "unicode-é"] {
        assert!(
            mutate_holds(None, id, 1, QuarantineAction::Hold).is_err(),
            "{id}"
        );
    }
    assert!(mutate_holds(None, &"a".repeat(129), 1, QuarantineAction::Hold).is_err());
    for json in [
        r#"{"version":2,"holds":{}}"#,
        r#"{"version":1,"holds":{"":{"version":1,"active":true}}}"#,
        r#"{"version":1,"holds":{"review":{"version":0,"active":true}}}"#,
        r#"{"version":1,"holds":{"review":{"version":1,"active":true,"extra":true}}}"#,
        r#"{"version":1}"#,
        r#"{"version":1,"holds":{},"extra":true}"#,
    ] {
        let result = serde_json::from_str::<QuarantineHolds>(json)
            .map_err(|e| e.to_string())
            .and_then(|holds| {
                mutate_holds(Some(holds), "review", 2, QuarantineAction::Release).map(|_| ())
            });
        assert!(result.is_err(), "malformed state must fail closed: {json}");
    }
}

#[test]
fn storage_read_failure_does_not_become_an_empty_hold_set() {
    let result = update_json_conditionally_with_io::<QuarantineHolds, _, _, _, _>(
        3,
        "quarantine holds",
        |current| mutate_holds(current, "review", 2, QuarantineAction::Release),
        || Err("synthetic unavailable store".into()),
        |_, _, _| panic!("read failure must not write"),
    );
    assert!(result.unwrap_err().contains("unavailable store"));
}

#[test]
fn delayed_hold_cannot_override_a_newer_release_and_equal_versions_cannot_conflict() {
    fn update(
        current: Option<QuarantineHolds>,
        version: u64,
        action: QuarantineAction,
    ) -> QuarantineHolds {
        match mutate_holds(current, "review:ordered", version, action).unwrap() {
            ConditionalJsonMutation::Complete(state) => state,
            ConditionalJsonMutation::Write { value, .. } => value,
        }
    }
    let held = update(None, 3, QuarantineAction::Hold);
    let released = update(Some(held), 4, QuarantineAction::Release);
    let late = update(Some(released), 3, QuarantineAction::Hold);
    assert!(late.active_ids().is_empty());
    assert_eq!(late.holds["review:ordered"].version, 4);
    assert!(!late.holds["review:ordered"].active);
    assert!(mutate_holds(
        Some(late.clone()),
        "review:ordered",
        4,
        QuarantineAction::Hold
    )
    .is_err());
    assert!(update(Some(late), 4, QuarantineAction::Release)
        .active_ids()
        .is_empty());
    // A release arriving before the initial hold still records its ordering tombstone.
    let release_first = update(None, 2, QuarantineAction::Release);
    assert_eq!(release_first.holds["review:ordered"].version, 2);
    assert!(update(Some(release_first), 1, QuarantineAction::Hold)
        .active_ids()
        .is_empty());
}

#[test]
fn mutation_versions_are_positive_javascript_safe_integers() {
    for version in [0, 9_007_199_254_740_992, u64::MAX] {
        assert!(mutate_holds(None, "review", version, QuarantineAction::Hold).is_err());
    }
    assert!(mutate_holds(
        None,
        "review",
        9_007_199_254_740_991,
        QuarantineAction::Hold
    )
    .is_ok());
}
