# CDN View Counting: Operational Setup

Pipeline: Fastly VCL log → Google Cloud Pub/Sub → Cloud Run subscriber → ClickHouse

## Prerequisites

- GCP project: `rich-compiler-479518-d2`
- Fastly VCL service: `ML7R82HKfmTaqTpHExIDVN`
- ClickHouse cluster accessible from Cloud Run
- Migrations 000105 + 000106 applied (in divine-funnelcake repo)

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

## 3. Configure Fastly Log Endpoint

In the Fastly dashboard for VCL service `ML7R82HKfmTaqTpHExIDVN`:

1. Go to **Logging** → **Create endpoint** → **Google Cloud Pub/Sub**
2. Configure:
   - **Name:** `cdn-view-logs`
   - **Project ID:** `rich-compiler-479518-d2`
   - **Topic:** `cdn-view-logs`
   - **Secret key:** paste contents of `fastly-pubsub-key.json`
3. Add a VCL snippet:
   - **Type:** `log` (vcl_log subroutine)
   - **Content:** paste from `vcl/log_cdn_views.vcl`
4. Activate the new version

## 4. Run ClickHouse Migrations

In the divine-funnelcake repo:

```bash
# Migration 000105: cdn_view_counts table + video_total_views unified view
# Migration 000106: rewire video_stats to use unified counts
# Use your standard migration workflow (golang-migrate)
```

## 5. Deploy the Subscriber

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

## 6. Verify End-to-End

### Check Fastly logging

Download a video from the CDN:
```bash
curl -sI "https://media.divine.video/<known-sha256>" | head -5
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
SELECT count() FROM nostr.cdn_view_counts;

-- Check a specific video
SELECT sha256, count() AS views
FROM nostr.cdn_view_counts
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
- Verify the VCL snippet is applied in vcl_log
- Check Fastly logging diagnostics in dashboard
- Test with a direct GET (not range request) to a known SHA256

**Messages accumulating but not consumed:**
- Check subscriber Cloud Run logs: `gcloud run services logs read cdn-view-subscriber`
- Verify CLICKHOUSE_URL is reachable from Cloud Run
- Check subscription ack deadline isn't too short

**Views not showing in video_stats:**
- Verify migration 000106 was applied (video_stats uses video_total_views)
- Check that the video's SHA256 matches between cdn_view_counts and events_deduped
- Run `SELECT * FROM nostr.video_total_views WHERE sha256 = '<hash>'` directly
