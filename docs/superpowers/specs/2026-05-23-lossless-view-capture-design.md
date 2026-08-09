# Lossless view capture design

**Date:** 2026-05-23
**Status:** design approved, implementation pending
**Repos involved:** `divine-blossom-stt`, `divine-funnelcake`, `divine-web`, `divine-mobile`

## Problem

The current anonymous CDN view pipeline undercounts because production Fastly logging only records `GET /{sha256}` responses with `status = 200` and `Content-Type: video/*`. Real playback can use direct MP4 byte ranges, derivative MP4 paths, HLS variant media files, retries, and fallback paths. Those requests can be legitimate playback but never land in `cdn_view_counts`.

The fix should not try to decide "real view" at the CDN edge. The edge should capture every plausible video-byte delivery, then ClickHouse should derive display counts from raw evidence.

## Goals

- Never miss plausible video-byte deliveries from `media.divine.video`.
- Preserve raw evidence so display-view policy can change without changing Fastly again.
- Keep privacy posture: no IP address, no user agent, no cookies, no Authorization values.
- Preserve authenticated app view events as a separate source of truth.
- Make display counts defensible but intentionally downstream of raw capture.
- Allow some deployment/adoption downtime if it simplifies the rollout.

## Non-goals

- Perfect unique-viewer counting for anonymous CDN traffic.
- Bot detection at ingestion time.
- Historical reconstruction for views that were never logged.
- Replacing kind `22236` authenticated view events.

## Current evidence

- Production VCL logging endpoint `cdn-view-logs` exists on Fastly VCL service `ML7R82HKfmTaqTpHExIDVN`.
- The endpoint logs in `vcl_log`, so cache hits are eligible.
- The active response condition is too narrow:
  ```vcl
  req.method == "GET"
  && req.url ~ "^/[0-9a-fA-F]{64}$"
  && resp.status == 200
  && resp.http.Content-Type ~ "^video/"
  ```
- `divine-web` can use HLS URLs derived from `media.divine.video/{sha}/hls/master.m3u8`, variant playlists, and direct media URLs.
- `divine-blossom-stt` serves direct quality variants at `/{sha}/720p`, `/{sha}/480p`, `/{sha}/720p.mp4`, and `/{sha}/480p.mp4`.
- `cloud-run-transcoder` produces HLS media files under `{sha}/hls/stream_720p.*` and `{sha}/hls/stream_480p.*`.

## Architecture

Use a dual-layer model:

1. **Raw capture:** append-only CDN media delivery events. This layer favors overcapture.
2. **Derived counts:** filter, normalize, and join raw events to logical video identity. This layer decides what is displayed.

Authenticated kind `22236` views remain a third input and are combined only at the final total-view layer.

```text
Fastly VCL log endpoint
  -> Pub/Sub cdn-view-logs
  -> cdn-view-subscriber
  -> ClickHouse cdn_media_delivery_events
  -> cdn_view_candidate_events / rollups
  -> video_total_views_data
  -> video_stats / feed APIs

Web/mobile kind 22236
  -> relay view_handler
  -> auth view tables
  -> video_total_views_data
```

## Fastly capture policy

Capture GET responses that deliver video bytes for a SHA-addressed media object.

Included:

- `/{sha}`
- `/{sha}.mp4`
- `/{sha}/720p`
- `/{sha}/480p`
- `/{sha}/720p.mp4`
- `/{sha}/480p.mp4`
- `/{sha}/hls/stream_720p.ts`
- `/{sha}/hls/stream_480p.ts`
- `/{sha}/hls/stream_720p.mp4`
- `/{sha}/hls/stream_480p.mp4`
- successful 2xx responses that delivered video bytes

Excluded from display candidates by default:

- `HEAD`
- thumbnails
- VTT
- audio extraction routes
- HLS manifests and variant playlists
- non-video content types

Optional debug capture can be added later for manifests, but it should not feed display counts.

Proposed response condition:

```vcl
req.method == "GET"
&& req.url ~ "^/[0-9a-fA-F]{64}($|\?|\.mp4(\?|$)|/(720p|480p)(\.mp4)?(\?|$)|/hls/stream_(720p|480p)\.(ts|mp4)(\?|$))"
&& resp.http.Content-Type ~ "^video/"
&& resp.status >= 200
&& resp.status < 300
&& resp.body_bytes_written > 0
```

Regex escapes are single backslashes. VCL string literals do not process
backslash escapes — Fastly uses percent escapes (`%22`) and passes a backslash
through to the regex engine verbatim. Written as `\\?`, the pattern means
"optional literal backslash", which matches the empty string and makes the whole
alternation accept any path beginning with `/{sha}`.

Proposed log payload:

```json
{
  "v": 2,
  "ts": 1779512793,
  "sha256": "full64hex",
  "path": "/full64hex/720p.mp4",
  "status": 206,
  "bytes": 1234567,
  "pop": "SJC",
  "cache": "HIT"
}
```

Do not log IP, user agent, cookies, query strings containing sensitive values, Authorization, or viewer identifiers.

## ClickHouse raw table

Create a new table instead of mutating `cdn_view_counts` in place. This keeps the old table available during rollout and avoids risky production swaps.

```sql
CREATE TABLE IF NOT EXISTS nostr.cdn_media_delivery_events (
    sha256 String,
    delivered_at DateTime,
    ingested_at DateTime DEFAULT now(),
    source LowCardinality(String) DEFAULT 'fastly',
    schema_version UInt8 DEFAULT 2,
    media_path_type LowCardinality(String),
    http_status UInt16,
    bytes_sent UInt64,
    pop LowCardinality(String),
    cache_state LowCardinality(String) DEFAULT '',
    raw_path String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(delivered_at)
ORDER BY (sha256, delivered_at, media_path_type);
```

This follows the ClickHouse rules checked:

- Per `schema-pk-plan-before-creation`, the ORDER BY is chosen before creation because it cannot be changed in place.
- Per `schema-pk-prioritize-filters`, the key starts with `sha256` because attribution and diagnostics filter by media hash, then time.
- Per `schema-partition-lifecycle`, monthly partitioning exists for retention/drop lifecycle, not as a primary query accelerator.
- Per `schema-types-lowcardinality`, repeated strings like POP, cache state, source, and path type use `LowCardinality`.

## Subscriber behavior

The subscriber should accept both v1 and v2 payloads during rollout:

- v1 payloads continue inserting into `cdn_view_counts`.
- v2 payloads insert into `cdn_media_delivery_events`.
- A dual-write option can insert v2 canonical rows into `cdn_view_counts` during transition if readers are not cut over yet.

Batching remains required:

- Per `insert-batch-size`, keep subscriber-side batching and avoid one-row inserts.
- If traffic becomes bursty or the subscriber flushes too often, enable async inserts with `wait_for_async_insert = 1` per `insert-async-small-batches`.

Malformed payloads should be acknowledged only if they are impossible to recover from. ClickHouse insert failures should not be acknowledged.

## Derived counts

Create derived read models in `divine-funnelcake`.

### Candidate events

A view candidate is a raw CDN media delivery that likely represents playback. Initial policy:

- `http_status >= 200 AND http_status < 300`
- `bytes_sent > 0`
- `media_path_type IN ('original', 'original_mp4', 'quality_mp4', 'quality_ts', 'quality_progressive')`

This policy intentionally still overcounts. It is a display candidate filter, not an anti-fraud system.

### Rollup

Build a rollup keyed by SHA and time, then join SHA to logical video identity:

- `sha256`
- `toStartOfHour(delivered_at)` for diagnostics/leaderboards
- `count()` as raw candidate views
- `sum(bytes_sent)` as delivered bytes

For hot display paths, materialize the result into the existing `video_total_views_data` flow. Use incremental materialized views for simple append-only rollups where possible and refreshable materialized views for the SHA-to-logical-video join. This follows `query-mv-incremental` and the architecture advisor's raw-plus-rollup guidance.

## Display total

Keep the final user-visible total as:

```text
display_views = cdn_candidate_views + authenticated_app_views
```

Authenticated app views remain useful because they carry stronger user intent. CDN candidate views remain useful because they include anonymous web embeds, share links, social previews that actually fetch video bytes, and clients that never publish Nostr view events.

Do not subtract authenticated views from CDN views in v1. Without anonymous identity, subtracting creates more risk of undercounting than double counting. If we later introduce privacy-preserving anonymous session buckets, dedupe can become a derived policy.

## Deployment plan

Because short adoption downtime is acceptable, use a simple cutover:

1. Add ClickHouse raw table and derived read models in `divine-funnelcake`.
2. Deploy a subscriber that understands v2 payloads and can optionally dual-write.
3. Clone active Fastly VCL version for `ML7R82HKfmTaqTpHExIDVN`.
4. Update the Google Pub/Sub logging endpoint format and response condition.
5. Activate the Fastly version.
6. Run smoke requests for direct, range, and derivative media paths.
7. Verify rows appear in `cdn_media_delivery_events`.
8. Switch display rollups from `cdn_view_counts` to the new derived count.
9. Leave `cdn_view_counts` intact for rollback and comparison.

Rollback is simple: activate the previous Fastly version and point readers back at the old count source.

## Validation

Fastly:

```bash
curl -sI "https://media.divine.video/<sha>" | head -20
curl -sI -H 'Range: bytes=0-200000' "https://media.divine.video/<sha>" | head -20
curl -sI "https://media.divine.video/<sha>/720p.mp4" | head -20
```

Pub/Sub:

```bash
gcloud pubsub subscriptions describe cdn-view-logs-sub \
  --project=rich-compiler-479518-d2 \
  --format="value(numUndeliveredMessages)"
```

ClickHouse:

```sql
SELECT
    media_path_type,
    http_status,
    count() AS rows,
    sum(bytes_sent) AS bytes
FROM nostr.cdn_media_delivery_events
WHERE delivered_at >= now() - INTERVAL 30 MINUTE
GROUP BY media_path_type, http_status
ORDER BY rows DESC;
```

Compare old and new sources:

```sql
SELECT
    sha256,
    countIf(source = 'old') AS old_rows,
    countIf(source = 'new') AS new_rows
FROM
(
    SELECT sha256, 'old' AS source FROM nostr.cdn_view_counts
    WHERE viewed_at >= now() - INTERVAL 1 HOUR
    UNION ALL
    SELECT sha256, 'new' AS source FROM nostr.cdn_media_delivery_events
    WHERE delivered_at >= now() - INTERVAL 1 HOUR
)
GROUP BY sha256
ORDER BY new_rows DESC
LIMIT 50;
```

Expected result: new raw rows exceed old rows, especially for videos played through range requests, derivative MP4s, or HLS.

## Open risks

- Without anonymous identity, raw CDN delivery cannot dedupe retries or repeated range requests per viewer.
- Some social crawlers may fetch video bytes and count as CDN candidates. That is acceptable for raw-first capture and can be filtered later if needed.
- Historical undercount cannot be repaired where Fastly never emitted events.
- If the new event volume is much higher than expected, subscriber batching and ClickHouse part counts need monitoring.

## References

- `divine-blossom-stt/vcl/log_cdn_views.vcl`
- `divine-blossom-stt/docs/runbooks/cdn-view-counting.md`
- `divine-funnelcake/database/migrations/000105_cdn_view_counts.up.sql`
- `divine-funnelcake/docs/superpowers/plans/2026-05-23-cdn-view-pipeline-audit.md`
- ClickHouse rule: `insert-batch-size`
- ClickHouse rule: `insert-async-small-batches`
- ClickHouse rule: `query-mv-incremental`
- ClickHouse rule: `schema-pk-plan-before-creation`
- ClickHouse rule: `schema-pk-prioritize-filters`
- ClickHouse rule: `schema-partition-lifecycle`
- ClickHouse rule: `schema-types-lowcardinality`
