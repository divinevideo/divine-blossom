# Lossless View Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture every plausible CDN video-byte delivery as raw evidence and derive anonymous display views from that raw stream.

**Architecture:** Add a v2 CDN delivery payload and raw ClickHouse table in `divine-funnelcake`, update the subscriber to classify v1/v2 payloads, and update the refreshable total-view rollup to sum candidate deliveries. Update `divine-blossom-stt` Fastly docs/snippet so production logging emits the v2 payload for all video-byte paths.

**Tech Stack:** Fastly VCL, Google Pub/Sub, Rust subscriber, ClickHouse migrations, existing `cdn-view-subscriber` tests.

---

## File Map

- `divine-funnelcake/bin/cdn-view-subscriber/src/main.rs`: parse v1/v2 Pub/Sub payloads, build raw delivery rows, batch insert both tables.
- `divine-funnelcake/database/migrations/000149_lossless_cdn_view_capture.up.sql`: create raw delivery table, backfill from old counts, recreate `video_total_views_data_mv` to use candidate deliveries.
- `divine-funnelcake/database/migrations/000149_lossless_cdn_view_capture.down.sql`: restore `video_total_views_data_mv` from `cdn_view_counts` while preserving the raw evidence table.
- `divine-blossom-stt/vcl/log_cdn_views.vcl`: equivalent explicit VCL snippet for the v2 payload and broad response condition.
- `divine-blossom-stt/docs/runbooks/cdn-view-counting.md`: operational instructions for the v2 endpoint and smoke checks.

### Task 1: Subscriber v2 Payload Parsing

**Files:**
- Modify: `/Users/rabble/code/divine/divine-funnelcake/bin/cdn-view-subscriber/src/main.rs`

- [x] **Step 1: Write failing tests**

Add tests proving:

```rust
#[test]
fn collect_pending_batch_routes_v2_payload_to_delivery_rows() {
    let sha = "a".repeat(64);
    let pending = collect_pending_batch(vec![valid_message_json(
        "ack-1",
        &serde_json::json!({
            "v": 2,
            "ts": 1779512793,
            "sha256": sha,
            "path": format!("/{}/720p.mp4", sha),
            "status": 206,
            "bytes": 234567,
            "pop": "SJC",
            "cache": "HIT"
        }),
    )]);

    assert!(pending.rows.is_empty());
    assert_eq!(pending.delivery_rows.len(), 1);
    let row = &pending.delivery_rows[0];
    assert_eq!(row.sha256, sha);
    assert_eq!(row.media_path_type, "quality_mp4");
    assert_eq!(row.http_status, 206);
    assert_eq!(row.bytes_sent, 234567);
    assert_eq!(row.cache_state, "HIT");
}

#[test]
fn collect_pending_batch_keeps_v1_payload_on_legacy_table() {
    let pending = collect_pending_batch(vec![valid_message(
        "ack-1",
        CdnViewPayload {
            ts: 1,
            sha256: "a".repeat(64),
            bytes: 123,
            pop: "SFO".to_string(),
        },
    )]);

    assert_eq!(pending.rows.len(), 1);
    assert!(pending.delivery_rows.is_empty());
}
```

- [x] **Step 2: Run tests and confirm failure**

Run:

```bash
cd /Users/rabble/code/divine/divine-funnelcake
cargo test --manifest-path bin/cdn-view-subscriber/Cargo.toml collect_pending_batch_routes_v2_payload_to_delivery_rows collect_pending_batch_keeps_v1_payload_on_legacy_table -- --nocapture
```

Expected: fails because `valid_message_json` and `delivery_rows` do not exist.

- [x] **Step 3: Implement v2 row parsing**

Add `CdnMediaDeliveryRow`, untagged payload parsing, `classify_media_path_type`, and `delivery_rows` on `PendingBatch`. v1 payloads continue populating `rows`; v2 payloads populate `delivery_rows`.

- [x] **Step 4: Run tests and confirm pass**

Run the same test command. Expected: both tests pass.

### Task 2: Subscriber Dual Insert

**Files:**
- Modify: `/Users/rabble/code/divine/divine-funnelcake/bin/cdn-view-subscriber/src/main.rs`

- [x] **Step 1: Write failing test**

Add a unit test that builds a pending batch with one legacy row and one delivery row, marks it inserted, then verifies `PendingBatch::clear()` clears both vectors.

- [x] **Step 2: Run test and confirm failure**

Expected: fails before `delivery_rows` is wired into `clear()` and `has_work()`.

- [x] **Step 3: Implement dual insert**

Update `flush_pending_batch` to insert:

```rust
ch.insert("cdn_view_counts")?;
ch.insert("cdn_media_delivery_events")?;
```

Only mark the batch inserted after all non-empty inserts succeed.

- [x] **Step 4: Run subscriber tests**

Run:

```bash
cd /Users/rabble/code/divine/divine-funnelcake
cargo test --manifest-path bin/cdn-view-subscriber/Cargo.toml
```

Expected: all subscriber tests pass.

### Task 3: ClickHouse Migration

**Files:**
- Create: `/Users/rabble/code/divine/divine-funnelcake/database/migrations/000149_lossless_cdn_view_capture.up.sql`
- Create: `/Users/rabble/code/divine/divine-funnelcake/database/migrations/000149_lossless_cdn_view_capture.down.sql`
- Modify tests if an existing migration smoke test requires migration list updates.

- [x] **Step 1: Write migration files**

The up migration must:

- Create `nostr.cdn_media_delivery_events`.
- Backfill from `nostr.cdn_view_counts` as `media_path_type = 'legacy_v1'`.
- Drop/recreate `nostr.video_total_views_data_mv` so CDN views are sourced from candidate rows in `cdn_media_delivery_events`.
- Keep `nostr.cdn_view_counts` intact.

The down migration must:

- Drop/recreate `nostr.video_total_views_data_mv` using the old `cdn_view_counts` source.
- Preserve `nostr.cdn_media_delivery_events`; raw delivery evidence should not be deleted by a rollback.

- [x] **Step 2: Run migration-oriented checks**

Run:

```bash
cd /Users/rabble/code/divine/divine-funnelcake
rg -n "cdn_media_delivery_events|video_total_views_data_mv|cdn_view_counts" database/migrations/000149_lossless_cdn_view_capture.*
```

Expected: both up/down mention the right objects.

### Task 4: Fastly V2 Logging Docs/Snippet

**Files:**
- Modify: `/Users/rabble/code/divine/divine-blossom-stt/vcl/log_cdn_views.vcl`
- Modify: `/Users/rabble/code/divine/divine-blossom-stt/docs/runbooks/cdn-view-counting.md`

- [x] **Step 1: Update VCL snippet**

Ensure the snippet emits `v`, `path`, `status`, `cache`, normalized `sha256`, and the broad video-byte response condition.

- [x] **Step 2: Update runbook**

Document the production Google Pub/Sub endpoint format and response condition, including v2 payload fields.

- [x] **Step 3: Regex smoke test**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_cdn_view_vcl.py'
```

Expected: `OK`.

The check has to read the pattern out of `vcl/log_cdn_views.vcl` rather than
retype it, because the failure mode is the escaping of the VCL literal itself. A
hand-typed copy in a shell one-liner gets its backslashes processed by the shell
and the host language before the regex engine sees them, so it can pass while
the deployed pattern is broken — which is exactly what happened here. CI runs
this test.

### Task 5: Final Verification

**Files:**
- All touched files.

- [x] **Step 1: Run subscriber tests**

```bash
cd /Users/rabble/code/divine/divine-funnelcake
cargo test --manifest-path bin/cdn-view-subscriber/Cargo.toml
```

- [x] **Step 2: Run Blossom VCL/doc smoke**

Run the regex test from Task 4.

- [x] **Step 3: Review diffs**

```bash
git -C /Users/rabble/code/divine/divine-funnelcake diff -- bin/cdn-view-subscriber/src/main.rs database/migrations/000149_lossless_cdn_view_capture.up.sql database/migrations/000149_lossless_cdn_view_capture.down.sql
git -C /Users/rabble/code/divine/divine-blossom-stt diff -- vcl/log_cdn_views.vcl docs/runbooks/cdn-view-counting.md
```

Confirm no unrelated dirty files are staged.
