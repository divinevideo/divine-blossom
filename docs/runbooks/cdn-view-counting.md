# CDN View Counting: Operational Setup

Pipeline: Fastly VCL log → Google Cloud Pub/Sub → Cloud Run subscriber → ClickHouse

## Prerequisites

- GCP project: `rich-compiler-479518-d2`
- Fastly VCL service: `ML7R82HKfmTaqTpHExIDVN`
- ClickHouse cluster accessible from Cloud Run
- Migrations 000105 + 000106 applied (in divine-funnelcake repo)
- The v2 sink — `cdn_media_delivery_events` and a subscriber that parses `"v":2`
  — **does not exist yet.** It is tracked in
  [divine-funnelcake#1070](https://github.com/divinevideo/divine-funnelcake/issues/1070);
  see step 3, which gates step 5.

## 1. Create Pub/Sub Topic and Subscription

```bash
gcloud pubsub topics create cdn-view-logs \
  --project=rich-compiler-479518-d2

gcloud pubsub subscriptions create cdn-view-logs-sub \
  --topic=cdn-view-logs \
  --ack-deadline=60 \
  --message-retention-duration=7d \
  --project=rich-compiler-479518-d2
```

## 2. Create Service Account for Fastly

```bash
gcloud iam service-accounts create fastly-pubsub-writer \
  --display-name="Fastly CDN View Log Writer" \
  --project=rich-compiler-479518-d2

gcloud pubsub topics add-iam-policy-binding cdn-view-logs \
  --member="serviceAccount:fastly-pubsub-writer@rich-compiler-479518-d2.iam.gserviceaccount.com" \
  --role="roles/pubsub.publisher" \
  --project=rich-compiler-479518-d2

# Download JSON key for Fastly dashboard
gcloud iam service-accounts keys create fastly-pubsub-key.json \
  --iam-account=fastly-pubsub-writer@rich-compiler-479518-d2.iam.gserviceaccount.com
```

**Delete the key file after uploading to Fastly dashboard.**

## 3. Run ClickHouse Migrations

Do this **before** activating the Fastly change. Once Fastly emits `"v":2` rows
for range and derivative paths, a pipeline that still only understands v1 drops
them on the floor.

> **Blocker.** The migration that creates `cdn_media_delivery_events` has not
> been written. On `divine-funnelcake` main, `000149` is
> `000149_fix_view_counts_sort_key`, and no ref in that repository contains
> `cdn_media_delivery_events`. Nothing about that sink is applied yet, whatever
> the surrounding documents imply: the design doc describes the table as though
> it exists, and the implementation plan
> (`docs/superpowers/plans/2026-05-23-lossless-view-capture.md`) tracks the
> remaining funnelcake work. The deployable dependency is tracked in
> [divine-funnelcake#1070](https://github.com/divinevideo/divine-funnelcake/issues/1070).
> This runbook is the operational path; step 5 must not be run until that issue
> is complete and its end-to-end verification is recorded.

In the divine-funnelcake repo:

```bash
# Migration 000105: cdn_view_counts table + video_total_views unified view
# Migration 000106: rewire video_stats to use unified counts
# Then: the raw cdn_media_delivery_events table + total views from raw
#       deliveries, once that migration exists (see the blocker above)
# Use your standard migration workflow (golang-migrate)
```

## 4. Deploy the Subscriber

Also before Fastly activation: the subscriber must accept v2 payloads (and keep
accepting v1) before any v2 row is published. The current `cdn-view-subscriber`
deserializes v1 fields only and writes to `cdn_view_counts`; extra v2 keys are
ignored. That work is part of the same funnelcake blocker above.

In the divine-funnelcake repo:

```bash
gcloud run deploy cdn-view-subscriber \
  --source=bin/cdn-view-subscriber \
  --region=us-central1 \
  --project=rich-compiler-479518-d2 \
  --set-env-vars="PUBSUB_PROJECT_ID=rich-compiler-479518-d2,PUBSUB_SUBSCRIPTION=cdn-view-logs-sub,CLICKHOUSE_URL=<clickhouse-url>,CLICKHOUSE_DATABASE=nostr" \
  --min-instances=1 \
  --max-instances=3
```

## 5. Configure Fastly Log Endpoint

`vcl/log_cdn_views.vcl` is the authoritative source for the three regex
literals used here. Copy them from that file rather than retyping them;
`scripts/tests/test_cdn_view_vcl.py` fails if the copies below drift from it.

VCL string literals do not process backslash escapes (Fastly uses percent
escapes such as `%22`), so every regex escape below is a **single** backslash.
Doubling one turns `\?` into "optional literal backslash", which matches the
empty string and quietly disables the surrounding alternation.

In the Fastly dashboard for VCL service `ML7R82HKfmTaqTpHExIDVN`:

1. Go to **Logging** → **Create endpoint** → **Google Cloud Pub/Sub**
2. Configure:
   - **Name:** `cdn-view-logs`
   - **Project ID:** `rich-compiler-479518-d2`
   - **Topic:** `cdn-view-logs`
   - **Secret key:** paste contents of `fastly-pubsub-key.json`
   - **Format version:** `2` (`vcl_log`)
   - **Format:**
     ```text
     {"v":2,"ts":%{time.start.sec}V,"sha256":"%{std.tolower(regsub(req.url, "^/([0-9a-fA-F]{64})[\s\S]*", "\1"))}V","path":"%{std.tolower(regsub(req.url, "\?[\s\S]*$", ""))}V","status":%{resp.status}V,"bytes":%{resp.body_bytes_written}V,"pop":"%{server.datacenter}V","cache":"%{fastly_info.state}V"}
     ```
3. Create or update the response condition named `cdn-view-log-condition`:
   ```vcl
   req.method == "GET"
   && req.url ~ "^/[0-9a-fA-F]{64}($|\?|\.(mp4|m4v|webm|mov|mkv|ogv|avi)(\?|$)|/(720p|480p)(\.mp4)?(\?|$)|/hls/stream_(720p|480p)\.(ts|mp4)(\?|$))"
   && resp.http.Content-Type ~ "^video/"
   && resp.status >= 200
   && resp.status < 300
   && resp.body_bytes_written > 0
   ```
4. **Save into a cloned version and confirm it compiles before activating.** The
   format string nests braces (`{64}`) and double quotes inside `%{...}V`; a
   parse failure there is silent from the outside and only shows up as missing
   log rows. Check Fastly's logging diagnostics on the cloned version first.
5. Activate the new version.

`vcl/log_cdn_views.vcl` holds the equivalent explicit-snippet form if the
endpoint is ever moved back to a `vcl_log` snippet. Production uses the Google
Pub/Sub endpoint format plus response condition above.

## 6. Verify End-to-End

### Check Fastly logging

Download video bytes from the CDN:
```bash
curl -sI "https://media.divine.video/<known-video-sha256>" | head -20
curl -sI -H 'Range: bytes=0-200000' "https://media.divine.video/<known-video-sha256>" | head -20
curl -sI "https://media.divine.video/<known-video-sha256>/720p.mp4" | head -20
```

### Check Pub/Sub messages

```bash
gcloud pubsub subscriptions describe cdn-view-logs-sub \
  --project=rich-compiler-479518-d2 \
  --format="value(numUndeliveredMessages)"
```

Should show messages accumulating (or 0 if subscriber is consuming them).

### Check ClickHouse

```sql
SELECT count() FROM nostr.cdn_media_delivery_events;

-- Check a specific video
SELECT sha256, count() AS views
FROM nostr.cdn_media_delivery_events
WHERE bytes_sent > 0 AND http_status >= 200 AND http_status < 300
GROUP BY sha256
ORDER BY views DESC
LIMIT 10;

-- Check unified view
SELECT video_d_tag, cdn_views, auth_views, total_views
FROM nostr.video_total_views
ORDER BY total_views DESC
LIMIT 10;
```

### Check video_stats

```sql
SELECT d_tag, views
FROM nostr.video_stats
ORDER BY views DESC
LIMIT 10;
```

## Troubleshooting

**No messages in Pub/Sub:**
- Verify the Fastly log endpoint is active (check service version)
- Verify the Google Pub/Sub endpoint uses format version 2 so the log call lands in `vcl_log`
- Verify `cdn-view-log-condition` includes derivative video paths and `206` range responses
- Verify the endpoint format emits `"v":2`, `path`, `status`, and `cache`
- Check Fastly logging diagnostics in dashboard
- Test with direct, range, and derivative GETs to a known video SHA256

**Messages accumulating but not consumed:**
- Check subscriber Cloud Run logs: `gcloud run services logs read cdn-view-subscriber`
- Verify CLICKHOUSE_URL is reachable from Cloud Run
- Check subscription ack deadline isn't too short

**Views not showing in video_stats:**
- Verify migration 000106 was applied (video_stats uses video_total_views)
- Check that the video's SHA256 matches between cdn_media_delivery_events and events_deduped
- Run `SELECT * FROM nostr.video_total_views WHERE sha256 = '<hash>'` directly
