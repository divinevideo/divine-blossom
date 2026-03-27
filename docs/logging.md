# Persistent Logging

Application logs are written to a Fastly log endpoint (`app_logs`) backed by a GCS bucket with 7-day retention. Logs also go to stderr for real-time `fastly log-tail`.

## Log format

Each request produces a JSON line:

```json
{"method":"GET","path":"/abc123","status":200,"duration_ms":42}
{"method":"PUT","path":"/upload","status":500,"duration_ms":1200,"error":"backend timeout"}
```

Non-request events use tag/message format:

```json
{"tag":"HLS","message":"Triggered on-demand transcoding for abc123"}
```

## Setup

### 1. Create the GCS bucket

```bash
scripts/setup-logging-gcs.sh
```

This creates `divine-blossom-logs` with a 7-day lifecycle delete policy.

### 2. Create a GCS service account key

The Fastly GCS logging endpoint needs a JSON service account key (not HMAC). Create one for the existing `blossom-storage-sa` service account:

```bash
gcloud iam service-accounts keys create /tmp/sa-key.json \
  --iam-account blossom-storage-sa@$(gcloud config get-value project).iam.gserviceaccount.com
```

### 3. Configure the Fastly logging endpoint

```bash
fastly logging gcs create \
  --name app_logs \
  --bucket divine-blossom-logs \
  --user blossom-storage-sa@<PROJECT_ID>.iam.gserviceaccount.com \
  --secret-key "$(cat /tmp/sa-key.json)" \
  --path "/logs/" \
  --period 60 \
  --gzip-level 9 \
  --message-type blank \
  --service-id pOvEEWykEbpnylqst1KTrR \
  --version latest --autoclone
```

Then activate the new version:

```bash
fastly service-version activate --version latest --service-id pOvEEWykEbpnylqst1KTrR
```

### 4. Deploy

```bash
fastly compute publish --comment "add persistent logging" && \
  fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

## Verification

Check logs are arriving in GCS:

```bash
gsutil ls gs://divine-blossom-logs/logs/
```

Download and inspect a log file:

```bash
gsutil cat gs://divine-blossom-logs/logs/<latest-file>.gz | gunzip
```

## Local development

In local mode (`fastly compute serve` with `fastly.toml.local`), the `app_logs` endpoint writes to stdout. The logger also always writes to stderr regardless of endpoint availability.

## Architecture

- `src/logging.rs` — `FastlyLogger` implementing the `log` crate's `Log` trait
- Probes endpoint availability once at init via `OnceLock`
- Falls back to stderr-only when endpoint is unavailable (local dev)
- `log_request()` — structured JSON for every HTTP request
- `log_event()` — structured JSON for application events
