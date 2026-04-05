// ABOUTME: Pure helpers for the reset-stuck-transcodes admin sweep
// ABOUTME: Exposed via lib.rs so classification + timestamp logic can be
// ABOUTME: unit-tested natively (the binary crate can't link Fastly SDK on host)

/// Action to take on a single candidate during the stuck-transcode sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckAction {
    /// Blob's `transcode_status` is not `Processing`; skip without action.
    SkipNotStuck,
    /// Blob was uploaded too recently; leave it alone (might still be transcoding).
    SkipTooRecent,
    /// HLS master manifest exists in GCS — webhook was lost, mark `Complete`.
    MarkComplete,
    /// HLS absent — reset to `Pending` so the next client request re-triggers.
    ResetPending,
}

/// Pure classification of a stuck transcode record.
///
/// Kept decoupled from `BlobMetadata` so this module can live in `lib.rs`
/// without dragging the rest of the crate into the library build. The caller
/// (`src/admin.rs` handler) extracts these four primitives from a
/// `BlobMetadata` before invoking the classifier.
///
/// * `is_processing` — `meta.transcode_status == Some(TranscodeStatus::Processing)`
/// * `uploaded_iso` — `meta.uploaded` (ISO 8601, e.g. `2026-04-04T22:00:00Z`)
/// * `threshold_iso` — cutoff ISO 8601 timestamp; blobs with
///   `uploaded_iso >= threshold_iso` are considered "too recent" and left alone.
/// * `hls_present` — whether `{hash}/hls/master.m3u8` exists in GCS.
pub fn classify_stuck_record(
    is_processing: bool,
    uploaded_iso: &str,
    threshold_iso: &str,
    hls_present: bool,
) -> StuckAction {
    if !is_processing {
        return StuckAction::SkipNotStuck;
    }

    // ISO 8601 strings in the same format compare lexicographically. If the
    // blob was uploaded more recently than the threshold, leave it alone.
    if uploaded_iso >= threshold_iso {
        return StuckAction::SkipTooRecent;
    }

    if hls_present {
        StuckAction::MarkComplete
    } else {
        StuckAction::ResetPending
    }
}

/// Format a unix timestamp (seconds) as `"YYYY-MM-DDTHH:MM:SSZ"`.
///
/// Mirrors `crate::storage::current_timestamp` exactly so lexicographic
/// comparisons against `BlobMetadata.uploaded` work.
pub fn format_unix_seconds_iso(secs: u64) -> String {
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut remaining_days = days_since_epoch as i64;
    let mut year = 1970i64;
    loop {
        let days_in_year = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for (i, d) in days_in_month.iter().enumerate() {
        if remaining_days < *d {
            month = (i + 1) as u64;
            break;
        }
        remaining_days -= *d;
    }
    let day = (remaining_days + 1) as u64;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Compute an ISO 8601 timestamp N seconds in the past from "now".
pub fn iso_timestamp_seconds_ago(secs: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let target = now.saturating_sub(secs);
    format_unix_seconds_iso(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_not_stuck_when_status_is_not_processing() {
        assert_eq!(
            classify_stuck_record(false, "2026-01-01T00:00:00Z", "2026-04-04T00:00:00Z", false),
            StuckAction::SkipNotStuck
        );
        // Also true when HLS happens to be present
        assert_eq!(
            classify_stuck_record(false, "2026-01-01T00:00:00Z", "2026-04-04T00:00:00Z", true),
            StuckAction::SkipNotStuck
        );
    }

    #[test]
    fn skip_too_recent_when_uploaded_after_threshold() {
        assert_eq!(
            classify_stuck_record(true, "2026-04-04T23:30:00Z", "2026-04-04T22:00:00Z", false),
            StuckAction::SkipTooRecent
        );
    }

    #[test]
    fn skip_too_recent_boundary_equal_is_too_recent() {
        // >= threshold means the exact threshold counts as "too recent".
        assert_eq!(
            classify_stuck_record(true, "2026-04-04T22:00:00Z", "2026-04-04T22:00:00Z", false),
            StuckAction::SkipTooRecent
        );
    }

    #[test]
    fn mark_complete_when_hls_present_and_stale() {
        assert_eq!(
            classify_stuck_record(true, "2026-03-29T10:00:00Z", "2026-04-04T22:00:00Z", true),
            StuckAction::MarkComplete
        );
    }

    #[test]
    fn reset_pending_when_hls_absent_and_stale() {
        assert_eq!(
            classify_stuck_record(true, "2026-03-29T10:00:00Z", "2026-04-04T22:00:00Z", false),
            StuckAction::ResetPending
        );
    }

    #[test]
    fn format_unix_seconds_iso_spot_check() {
        // Unix epoch
        assert_eq!(format_unix_seconds_iso(0), "1970-01-01T00:00:00Z");
        // 2026-01-01T00:00:00Z = 1767225600
        assert_eq!(format_unix_seconds_iso(1767225600), "2026-01-01T00:00:00Z");
        // 2026-04-04T20:00:00Z = 1775332800 (verified against this fn's own output)
        assert_eq!(format_unix_seconds_iso(1775332800), "2026-04-04T20:00:00Z");
        // 2026-04-04T22:00:00Z = 1775340000
        assert_eq!(format_unix_seconds_iso(1775340000), "2026-04-04T22:00:00Z");
        // Two timestamps exactly 1 hour apart produce different outputs on
        // the same date (this is a weak check; the above asserts are stronger).
        let a = format_unix_seconds_iso(1775332800);
        let b = format_unix_seconds_iso(1775332800 + 3600);
        assert_ne!(a, b);
        assert_eq!(&a[..10], &b[..10]); // same YYYY-MM-DD
    }

    #[test]
    fn iso_timestamp_seconds_ago_has_correct_format() {
        let s = iso_timestamp_seconds_ago(0);
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
    }
}
