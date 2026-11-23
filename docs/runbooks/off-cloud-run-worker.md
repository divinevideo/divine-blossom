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
3. The off-GCP worker behind `https://transcoder-worker.divine.video`
   (e.g., Vultr US East `ewr` or Hetzner US Ashburn `ash`) receives the Cloud
   Task, downloads the original from B2 `us-east-005`, runs stream-copy or
   single-variant FFmpeg, uploads HLS + MP4 derivatives back to B2 `us-east-005`,
   writes single-writer claim metadata to GCS via `GOOGLE_APPLICATION_CREDENTIALS`,
   and POSTs the completion webhook back to `https://media.divine.video/admin/transcode-status`.

### Provider choice (US East, next to B2 `us-east-005`)

- **Vultr (New Jersey `ewr` / Atlanta `atl`)**: Member of the Backblaze
  Bandwidth Alliance — **$0/GB egress between Vultr and Backblaze B2**. Two
  16-vCPU / 32 GB instances or one/two bare-metal nodes comfortably absorb peak
  archive backfill + live traffic.
- **Hetzner US (Ashburn `ash`)**: Bare-metal `AX102` (Ryzen 9 7950X3D, 16C/32T,
  128 GB RAM) is ~$115/mo with **20 TB/mo included egress per server** (40 TB/mo
  across 2 servers, in the same US East metro as B2 `us-east-005`).

### DNS, TLS, and multi-node caveats

- **Do NOT orange-cloud proxy `transcoder-worker.divine.video` through Cloudflare:**
  Cloudflare's HTTP proxy enforces a 100s origin read timeout (Free/Pro/Business),
  which aborts long transcode requests with HTTP `524` before Cloud Tasks' `900s`
  `dispatchDeadline`. Use **DNS-only** (grey cloud) or a TCP/L4 load balancer.
- **Multi-node TLS:** The included `Caddyfile` uses ACME HTTP-01 with local
  `caddy_data`, which works for a single node. For 2+ nodes behind DNS/LB,
  switch Caddy to ACME DNS-01 (Cloudflare DNS module) or terminate TLS at the
  load balancer so certificate renewals do not split across nodes.
- **Host clock sync:** Keep `systemd-timesyncd` or `chrony` enabled on worker
  hosts. Service-account JWT token exchange fails with `invalid_grant` if clock
  skew exceeds a few minutes.

## 1. Create a dedicated GCP service account for off-GCP workers

Enable the IAM Service Account Credentials API if not already enabled:

```sh
gcloud services enable iamcredentials.googleapis.com \
  --project=rich-compiler-479518-d2
```

Create a dedicated service account (for example `divine-transcoder-worker@rich-compiler-479518-d2.iam.gserviceaccount.com`) with least-privilege roles:

- `roles/storage.objectViewer` on `gs://divine-blossom-media` plus an IAM-conditioned `roles/storage.objectAdmin` scoped to the `hls_claim` / lock prefix (or bucket-scoped `roles/storage.objectAdmin` if legacy GCS writes are needed — note the broader blast radius of a static key on an off-GCP VM).
- `roles/aiplatform.user` (only if Vertex AI Gemini transcription runs on the worker).
- `roles/cloudtasks.enqueuer` (only if `STATUS_QUEUE_ENABLED=true` or the worker enqueues follow-up tasks).
- `roles/iam.serviceAccountTokenCreator` **on itself** (required by `fetch_gcp_identity_token` via `iamcredentials.googleapis.com:generateIdToken` to mint OIDC tokens for private Cloud Run sidecars).
- `roles/run.invoker` on `divine-asr-parakeet` and `divine-audio-analyzer` (required for those private Cloud Run services to accept the worker's OIDC identity tokens).

Export its JSON key to `/etc/divine-transcoder/gcp-sa.json` (`chmod 600`, readable by container UID `10001` or `chown 10001:10001`) on each worker host.

For container image pulls from `gcr.io/rich-compiler-479518-d2`, configure Docker
registry auth on the host using a separate read-only pull credential (with
`roles/artifactregistry.reader` / GCR bucket viewer) via
`docker login -u _json_key --password-stdin https://gcr.io < pull-key.json`.

## 2. Build and run the slim CPU worker image

Build an `amd64` CPU image from a clean context prepared by
`cloud-run-transcoder/prepare-build-context.sh` (uses `debian:bookworm-slim` for
glibc 2.36 ABI parity with the Rust builder and omits ~3 GB of CUDA layers):

```sh
CTX="$(mktemp -d)"
./cloud-run-transcoder/prepare-build-context.sh "$CTX"
docker build --platform linux/amd64 -f "$CTX/Dockerfile.cpu" \
  -t "gcr.io/rich-compiler-479518-d2/divine-transcoder:cpu-$(git rev-parse --short HEAD)" \
  "$CTX"
docker push "gcr.io/rich-compiler-479518-d2/divine-transcoder:cpu-$(git rev-parse --short HEAD)"
rm -rf "$CTX"
```

On the worker host:

1. Point DNS-only `A`/`AAAA` for `transcoder-worker.divine.video` at the host.
2. Copy `cloud-run-transcoder/deploy/off-gcp/` to `/opt/divine-transcoder/`.
3. Populate `/opt/divine-transcoder/.env` from `.env.example` (`chmod 600 .env`)
   with `TRANSCODE_WRITES_PAUSED=true` initially, and place `/etc/divine-transcoder/gcp-sa.json` (`chown 10001:10001`, `chmod 600`).
4. Start the stack (`docker compose up -d`) and verify `curl -fsS https://transcoder-worker.divine.video/health`.

## 3. Single-writer cutover & rollback (Cloud Tasks URL-safe)

Follow `docs/runbooks/hls-single-writer.md` — never run concurrent unpaused
Cloud Run and off-GCP writers simultaneously. Because Cloud Tasks freezes
`httpRequest.url` on each task **at enqueue time**, follow this exact order so
queued tasks never strand or overlap:

### Cutover (Cloud Run -> off-GCP)

1. Confirm the off-GCP worker is healthy with **`TRANSCODE_WRITES_PAUSED=true`**.
2. Point Cloud Run's `TRANSCODE_WORKER_URL` to the off-GCP origin while leaving
   Cloud Run's `TRANSCODE_WRITES_PAUSED=false` briefly so tasks *already* in
   `divine-transcode` targeting Cloud Run drain cleanly (any newly enqueued tasks
   targeting off-GCP receive `503` paused and retry cleanly via Cloud Tasks):
   ```sh
   gcloud run services update divine-transcoder \
     --region=us-central1 --project=rich-compiler-479518-d2 \
     --update-env-vars "TRANSCODE_WORKER_URL=https://transcoder-worker.divine.video"
   ```
3. Pause `divine-transcode` briefly or monitor Cloud Run logs/metrics until
   Cloud Run `/internal/transcode` requests drop to **0** (all previously queued
   Cloud Run-targeted tasks have drained).
4. Pause direct HLS writes on Cloud Run (`TRANSCODE_WRITES_PAUSED=true` still
   permits ordinary `POST /transcode` queue admission, while blocking
   `/internal/transcode`, `force: true` repairs, and `/backfill-fmp4` on Cloud
   Run — direct forced repairs and `/backfill-fmp4` to `https://transcoder-worker.divine.video`):
   ```sh
   gcloud run services update divine-transcoder \
     --region=us-central1 --project=rich-compiler-479518-d2 \
     --update-env-vars "TRANSCODE_WRITES_PAUSED=true"
   ```
5. Flip `TRANSCODE_WRITES_PAUSED=false` in `/opt/divine-transcoder/.env`, run
   `docker compose up -d transcoder`, and resume `divine-transcode` if paused.
   Verify B2 writes, GCS claims, and webhook callbacks succeed in worker logs.

### Rollback (off-GCP -> Cloud Run)

1. Pause `divine-transcode`:
   ```sh
   gcloud tasks queues pause divine-transcode \
     --location=us-central1 --project=rich-compiler-479518-d2
   ```
2. Set `TRANSCODE_WRITES_PAUSED=true` in `/opt/divine-transcoder/.env` and
   reload `transcoder` (or wait for in-flight jobs to drain to **0** before
   stopping the worker; do not run Cloud Run unpaused while off-GCP jobs are
   still executing).
3. Update Cloud Run back to its own origin and unpause Cloud Run writes:
   ```sh
   gcloud run services update divine-transcoder \
     --region=us-central1 --project=rich-compiler-479518-d2 \
     --update-env-vars "TRANSCODE_WORKER_URL=https://divine-transcoder-nr3owfkrxa-uc.a.run.app,TRANSCODE_WRITES_PAUSED=false"
   ```
4. Resume `divine-transcode`. Any residual tasks enqueued with the off-GCP URL
   will hit the paused off-GCP worker (`503`) and cannot write concurrently with
   Cloud Run; re-enqueue or purge stale off-GCP-targeted tasks if needed.
