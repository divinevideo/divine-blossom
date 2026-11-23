# Running `divine-transcoder` workers off Cloud Run (Vultr / Hetzner US)

Moving the CPU-heavy HLS transcode worker off GCP Cloud Run eliminates both the
Cloud Run vCPU markup (~$120–$400/day) and GCP→Backblaze B2 internet egress
($0.105/GiB, ~$24–$149/day).

## Architecture: zero-Fastly-change split

You do **not** need to modify Fastly backend routing or `divine-upload-server`
to offload transcoding:

1. Fastly (`media.divine.video`) and `divine-upload-server` continue calling the
   existing Cloud Run front-door `divine-transcoder` (`POST /transcode`).
2. Cloud Run's `/transcode` handler immediately enqueues a Cloud Task onto
   `divine-transcode` targeting `${TRANSCODE_WORKER_URL}/internal/transcode`,
   authenticated via the `x-divine-transcode-worker` HMAC token derived from
   `TRANSCODE_DISPATCH_SECRET`.
3. The off-GCP worker fleet behind `https://transcoder-worker.divine.video`
   (e.g., 2× Vultr High Frequency / Bare Metal in US East `ewr` or 2× Hetzner
   US Ashburn `AX102`/`CCX33`) receives the Cloud Task, downloads the original
   from B2 `us-east-005`, runs stream-copy or single-variant FFmpeg, uploads HLS
   + MP4 derivatives back to B2 `us-east-005`, writes the tiny single-writer
   claim metadata to GCS via `GOOGLE_APPLICATION_CREDENTIALS`, and POSTs the
   completion webhook back to `https://media.divine.video/admin/transcode-status`.

### Provider choice (US East, next to B2 `us-east-005`)

- **Vultr (New Jersey `ewr` / Atlanta `atl`)**: Member of the Backblaze
  Bandwidth Alliance — **$0/GB egress between Vultr and Backblaze B2**. Two
  16-vCPU / 32 GB instances or one/two bare-metal nodes comfortably absorb peak
  archive backfill + live traffic.
- **Hetzner US (Ashburn `ash`)**: Bare-metal `AX102` (Ryzen 9 7950X3D, 16C/32T,
  128 GB RAM) is ~$115/mo with **20 TB/mo included egress per server** (40 TB/mo
  across 2 servers, in the same US East metro as B2 `us-east-005`).

## 1. Create a dedicated GCP service account for off-GCP workers

Create a minimal service account (for example `divine-transcoder-worker@rich-compiler-479518-d2.iam.gserviceaccount.com`) with:

- `roles/storage.objectAdmin` scoped to `gs://divine-blossom-media` (for `hls_claim` single-writer locks and legacy GCS fallback reads)
- `roles/aiplatform.user` (only if Vertex AI Gemini transcription runs on the worker)
- `roles/cloudtasks.enqueuer` (only if `STATUS_QUEUE_ENABLED=true` or the worker enqueues follow-up tasks)
- `roles/iam.serviceAccountTokenCreator` on **itself** (required by `fetch_gcp_identity_token` via `iamcredentials.googleapis.com:generateIdToken` to authenticate to private Cloud Run sidecars such as `divine-asr-parakeet` and `divine-audio-analyzer`)

Export its JSON key to `/etc/divine-transcoder/gcp-sa.json` (`chmod 600`) on each worker host.

## 2. Build and run the slim CPU worker image

Build from a clean archive with `cloud-run-transcoder/prepare-build-context.sh`
and `cloud-run-transcoder/Dockerfile.cpu` (omits the ~3 GB CUDA runtime layer):

```sh
docker build -f Dockerfile.cpu -t gcr.io/rich-compiler-479518-d2/divine-transcoder:cpu-<sha> .
docker push gcr.io/rich-compiler-479518-d2/divine-transcoder:cpu-<sha>
```

On each worker host:

1. Point DNS (`transcoder-worker.divine.video`, or a Cloudflare Load Balancer
   across 2+ nodes) at the host(s).
2. Copy `cloud-run-transcoder/deploy/off-gcp/` to `/opt/divine-transcoder/`.
3. Populate `/opt/divine-transcoder/.env` from `.env.example` (`chmod 600 .env`)
   and place `/etc/divine-transcoder/gcp-sa.json` (`chmod 600`).
4. Start the stack and verify `curl -fsS https://transcoder-worker.divine.video/health`.

## 3. Single-writer cutover & instant rollback

Follow `docs/runbooks/hls-single-writer.md` — never run concurrent unpaused
Cloud Run and off-GCP writers simultaneously:

1. Pause the Cloud Tasks queue:
   ```sh
   gcloud tasks queues pause divine-transcode \
     --location=us-central1 --project=rich-compiler-479518-d2
   ```
2. Wait for in-flight Cloud Run `/internal/transcode` requests to drain to 0.
3. Update Cloud Run's `TRANSCODE_WORKER_URL` to the off-GCP origin and pause
   direct HLS writes on Cloud Run (`TRANSCODE_WRITES_PAUSED=true` still allows
   ordinary `POST /transcode` queue admission, while preventing Cloud Run from
   running `/internal/transcode`, `force: true` repairs, or `/backfill-fmp4`
   concurrently with the off-GCP worker — target `https://transcoder-worker.divine.video`
   directly for forced repairs and `/backfill-fmp4`):
   ```sh
   gcloud run services update divine-transcoder \
     --region=us-central1 --project=rich-compiler-479518-d2 \
     --update-env-vars "TRANSCODE_WORKER_URL=https://transcoder-worker.divine.video,TRANSCODE_WRITES_PAUSED=true"
   ```
4. Resume the queue and monitor both worker logs and `hls_claim` metrics:
   ```sh
   gcloud tasks queues resume divine-transcode \
     --location=us-central1 --project=rich-compiler-479518-d2
   ```
5. **Instant rollback:** Pause `divine-transcode`, set `TRANSCODE_WORKER_URL`
   back to `https://divine-transcoder-nr3owfkrxa-uc.a.run.app` (and
   `TRANSCODE_WRITES_PAUSED=false`), wait for off-GCP tasks to drain, and resume
   `divine-transcode`.
