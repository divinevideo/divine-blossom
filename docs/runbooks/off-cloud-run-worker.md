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

- `roles/storage.objectViewer` on `gs://divine-blossom-media` plus an IAM-conditioned `roles/storage.objectAdmin` scoped to the `.internal/hls-claims/` prefix (or bucket-scoped `roles/storage.objectAdmin` if legacy GCS writes are needed — note the broader blast radius of a static key on an off-GCP VM).
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

### Off-GCP job intake

The worker may continue receiving Cloud Tasks at `/internal/transcode` while
Cloud Run accepts new jobs. To move admission separately, deploy a worker with
`TRANSCODE_ADMISSION_AUTH_REQUIRED=true` and a dedicated
`TRANSCODE_ADMISSION_SECRET` before opening admission in the reverse proxy.
The bundled Compose and Caddy configuration checks the admission credential
before forwarding either route in required-auth mode, including if an older
worker image is restored. Use the literal lowercase `true` in Compose.
For forced repairs in that mode, use `docker compose exec transcoder` on the
worker host to POST `force: true` to `http://127.0.0.1:8080/transcode`
inside the container, with the configured `x-divine-repair-secret` header.
That path bypasses the public proxy and still requires the worker's repair
credential. On hosts with a custom Caddyfile, retain the existing allowlist
and apply equivalent credential checks before opening either intake route.

Configure queue-scoped enqueue access for the worker identity only after
verifying that external unauthenticated admission is blocked. Ordinary requests
to either intake route use `x-divine-transcode-admission`. Keep that credential
separate from task delivery and forced repair. Verify that missing and wrong
credentials return 401 and that a synthetic authenticated request returns 202
and becomes playable before moving any caller. Keep non-HLS routes on their
existing origin.

To roll back admission, return every moved producer to Cloud Run intake and
confirm new jobs are being accepted there before shutting down, downgrading or
closing off-GCP intake. Keep the worker serving the jobs it already accepted
until those jobs drain. If also rolling back the writer, follow the queue
pause and target-override procedure below after the producer cutback. Revoke
the off-GCP queue grant before removing the admission credential or returning
to a legacy proxy configuration.

## 3. Single-writer cutover & rollback (Cloud Tasks URL-safe)

Follow `docs/runbooks/hls-single-writer.md` — never run concurrent unpaused
Cloud Run and off-GCP writers simultaneously. Because Cloud Tasks freezes
`httpRequest.url` on each task **at enqueue time**, follow this exact order so
queued tasks never strand or overlap:

### Cutover (Cloud Run -> off-GCP)

Before the steps below, deploy the copy-only upload-service dispatch suppression,
then edge metadata/policy lookup, then the policy-aware worker image. Configure
`MEDIA_PROCESSING_POLICY_URL=https://media.divine.video/internal/media-policy`
with the existing webhook secret. The edge must have `kv_origin_read_token` and
`metadata_kv_store_id` configured: missing origin configuration retries instead
of granting encoding permission. See [media processing policy](../../cloud-run-transcoder/MEDIA_POLICY.md).
Keep archive publishing paused until its separate maintainer hold is lifted.

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
   Run). Direct those operations to the off-GCP worker. Use container loopback
   for forced repairs when the off-GCP proxy requires admission authentication.
   ```sh
   gcloud run services update divine-transcoder \
     --region=us-central1 --project=rich-compiler-479518-d2 \
     --update-env-vars "TRANSCODE_WRITES_PAUSED=true"
   ```
5. Flip `TRANSCODE_WRITES_PAUSED=false` in `/opt/divine-transcoder/.env`, run
   `docker compose up -d transcoder`, and resume `divine-transcode` if paused.
   Verify B2 writes, GCS claims, and webhook callbacks succeed in worker logs.

### Rollback (off-GCP -> Cloud Run)

Never purge `divine-transcode` or discard a write journal blindly (see
`docs/runbooks/hls-single-writer.md`).

1. Pause `divine-transcode`:
   ```sh
   gcloud tasks queues pause divine-transcode \
     --location=us-central1 --project=rich-compiler-479518-d2
   ```
2. Wait for all in-flight off-GCP transcode jobs to drain to **0** first (do not
   recreate/SIGTERM `transcoder` while jobs are executing), then set
   `TRANSCODE_WRITES_PAUSED=true` in `/opt/divine-transcoder/.env` and run
   `docker compose up -d transcoder` (or `docker compose stop transcoder`).
3. Update Cloud Run back to its own origin and unpause Cloud Run writes:
   ```sh
   gcloud run services update divine-transcoder \
     --region=us-central1 --project=rich-compiler-479518-d2 \
     --update-env-vars "TRANSCODE_WORKER_URL=https://divine-transcoder-nr3owfkrxa-uc.a.run.app,TRANSCODE_WRITES_PAUSED=false"
   ```
4. While `divine-transcode` is still paused, if residual queued tasks still
   target the off-GCP origin, set a queue-level HTTP URI override pointing at
   `https://divine-transcoder-nr3owfkrxa-uc.a.run.app` (per
   `docs/runbooks/hls-single-writer.md`) and wait 1 minute for queue config
   propagation before resuming.
5. Resume `divine-transcode` (and clear any temporary URI override once queued
   tasks have drained).

## 4. Co-locating `divine-upload-server` on the worker host

On a multi-core off-GCP worker host (such as the Ashburn `ccx43`), you can run
`divine-upload-server` alongside `transcoder` behind the same Caddy instance
with bounded CPU/memory limits (`UPLOAD_CPUS`, `UPLOAD_MEM_LIMIT`) to limit upload and on-demand thumbnail resource use. The services still share
host CPU, memory, and network capacity. Keep the existing transcoder as the
sole writer.

### Enable co-located upload

1. Export a dedicated GCP service account key for `divine-upload-server` to
   `/etc/divine-upload/gcp-sa.json` (`chown 0:0`, `chmod 600`) with
   `roles/storage.objectAdmin` on `gs://divine-blossom-media` (while
   `GCS_COMPAT_ENABLED=true`). `divine-upload-server`'s image currently runs as
   UID `0` (unlike GKE `runAsUser: 1000`), and `docker-compose.upload.yml` drops
   all Linux capabilities (`cap_drop: ALL`, removing `CAP_DAC_OVERRIDE`), so a
   `0600` key file must be owned by UID `0` (or match the image's runtime UID if
   the Dockerfile later switches to a non-root user).
2. Copy `cloud-run-transcoder/deploy/off-gcp/.env.upload.example` to
   `/opt/divine-transcoder/.env.upload` (`chmod 600`) and populate the B2,
   transcribe, and optional parity keys (`MIGRATION_NSEC`,
   `AI_DETECTOR_BASE_URL`, `MAX_UPLOAD_BYTES`, `MIRROR_FETCH_TIMEOUT_SECS`,
   `SENTRY_DSN`) to match live GKE production. Keep `TRANSCODER_URL` at its
   default (`https://divine-transcoder-149672065768.us-central1.run.app`) with
   `TRANSCODE_ADMISSION_SECRET` unset to match live GKE production; only set
   `TRANSCODE_ADMISSION_SECRET` when intentionally routing HLS admission to the
   off-GCP worker's `/transcode/queue` endpoint with matching
   `TRANSCODE_ADMISSION_AUTH_REQUIRED=true` and `TRANSCODE_ADMISSION_SECRET` on
   the worker (complete the worker-intake steps earlier in this runbook and
   verify an authenticated upload yields playable HLS before switching away from
   the Cloud Run default). Confirm `MEDIA_WRITE_PROVIDER`, `B2_MEDIA_BUCKET`, `GCS_BUCKET`,
   and `GCS_COMPAT_ENABLED` match live GKE production so both hosts share object
   storage and resumable sessions. Keep `TRANSCRIBER_URL` explicitly set to an
   origin serving `POST /transcribe/audio` (the Cloud Run origin
   `https://divine-transcoder-149672065768.us-central1.run.app` by default, or
   internal `http://transcoder:8080` only if the local worker is configured with
   transcription credentials and matching `TRANSCRIBE_SHARED_SECRET`); leaving
   `TRANSCRIBER_URL` unset falls back to `TRANSCODER_URL`, whose Caddy site
   intentionally returns `404` for `/transcribe/audio`. Set
   `UPLOAD_BASE_URL=https://upload-hetzner.divine.video` for candidate testing
   so `/upload/init` returns candidate-host `/sessions/:id` URLs instead of
   pointing chunk uploads back to GKE.
3. In `/opt/divine-transcoder/.env`, add:
   ```sh
   COMPOSE_FILE=docker-compose.yml:docker-compose.upload.yml
   UPLOAD_IMAGE=us-central1-docker.pkg.dev/dv-platform-prod/containers-production/divine-upload-server@sha256:<pinned-digest>
   ```
   *(Pin a digest built from a `divine-upload-server` commit that includes PR
   `divinevideo/divine-upload-server#51` — `spawn_blocking` thumbnail isolation
   and admission-accounting fixes. Do not set `UPLOAD_DOMAIN` to the candidate
   hostname here; use literal hostnames in `conf.d/upload-candidate.caddy` and
   `conf.d/upload.caddy` so staging and cutover never risk duplicate site blocks
   or an extra Caddy restart. Because `transcoder` loads `.env` via `env_file`,
   editing `.env` changes `transcoder`'s Compose config hash; do **not** run a
   broad `docker compose up -d` that would recreate `transcoder` and interrupt
   in-flight jobs.)*
4. Copy `Caddyfile.upload.example` to `conf.d/upload-candidate.caddy` and
   replace `{$UPLOAD_DOMAIN}` with the literal candidate hostname
   `upload-hetzner.divine.video` (so it can remain active alongside
   `conf.d/upload.caddy` during cutover). Confirm `transcoder` is healthy first,
   validate the updated Compose Caddy config (including the new `./conf.d`
   mount and `.env`) in a one-off container before touching live ingress, then
   start `upload` and update `caddy` with `--no-deps` so Compose does **not**
   recreate `transcoder`:
   ```sh
   docker compose ps transcoder
   docker compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
   docker compose up -d --no-deps upload
   docker compose up -d --no-deps caddy
   docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```
   *(Running `docker compose run --rm --no-deps caddy caddy validate` beforehand
   validates the `./conf.d` mount and `.env` without binding host ports or
   restarting live `caddy`, so a broken vhost cannot disrupt live
   `transcoder-worker.divine.video` traffic on first recreate. If `caddy` was
   recreated to pick up the new `./conf.d` mount, it already loaded the
   validated config; the `caddy reload` covers the no-recreate case.)*
5. Verify against the candidate hostname (DNS-only / grey cloud). The
   container health check only confirms that the port accepts connections.
   Confirm the pinned image can read `/run/secrets/gcp-sa.json` under
   `cap_drop: ALL`, write scratch files to `/tmp` with a read-only root, reach
   both configured storage buckets, and reach `TRANSCODER_URL` from inside the
   container (plus container-to-host HTTPS hairpinning if using the worker's
   `/transcode/queue` admission path). Confirm `.env.upload` uses the intended
   buckets, credentials, and concurrency limits for this host, then check:
   - `GET /` and `HEAD /` return `200`, and `OPTIONS` preflights succeed across
     the public routes.
   - `GET https://upload-hetzner.divine.video/thumbnail/<known-video-hash>` returns `200 image/jpeg`.
   - Direct `PUT /upload`, resumable `POST /upload/init` → `PUT`/`HEAD /sessions/:id` → `POST /upload/:id/complete`, and `DELETE /upload/:id` abort succeed and write to B2 + GCS.
   - An uploaded video completes HLS transcoding end-to-end via `TRANSCODER_URL`.
   - Requests larger than `16 MiB` are rejected by Caddy with `413`.
   - `POST /transcribe` (with valid BUD-11 `t=media` auth and a short sample
     audio clip) returns `200` with `text/vtt` WebVTT output (proving
     `TRANSCRIBER_URL` → `POST /transcribe/audio` works end-to-end).
   - `POST /migrate` routes through Caddy cleanly, while `POST /audit` returns
     `404` (only `CLOUD_RUN_HOST` handles `/audit`).
6. Before cutover, record the current DNS records, ownership TXT records, and
   TTL. Verify both upload instances share compatible object-backed session
   storage (`ProviderSessionStore`) and can resume each other's sessions in both
   directions (GKE → Hetzner and Hetzner → GKE). Confirm both submit to the
   existing single transcoder writer. Exercise `HEAD`, browser preflights, and
   slow bodies near the configured limit. Load test uploads, thumbnail misses,
   and transcoding together. Measure `/tmp` tmpfs and memory usage, CPU
   saturation, and transcode queue latency. Include both upload-generated and
   on-demand thumbnails in the budget.
7. Execute production cutover only after resolving DNS ownership and verifying
   production TLS on the worker **before** sending production traffic to it:
   1. **DNS ownership plan (`divine-iac-coreconfig`):** ExternalDNS currently
      manages `upload.divine.video` from GKE `HTTPRoute/divine-upload-server`
      under `policy: sync`, so manual Cloudflare edits will be reconciled back
      to GKE. Because ExternalDNS reads `spec.hostnames`, removing only the
      `external-dns.alpha.kubernetes.io/hostname` annotation will **not** release
      the record, and removing `spec.hostnames` deletes the live `A` record.
      Before cutting over, Platform must choose either a controller-managed
      target change or a DNS ownership handoff that excludes `upload.divine.video`
      from ExternalDNS reconciliation across all serving and redirect
      `HTTPRoute` resources (e.g., via `excludeDomains` in ExternalDNS config)
      while keeping `spec.hostnames: ["upload.divine.video"]` and preserving the
      live `A` record so GKE continues serving cached-DNS and rollback traffic;
      verify ExternalDNS stops reconciling the record (or transfer DNS ownership
      to an OpenTofu Cloudflare DNS stack), confirm no conflicting `AAAA` record
      remains, and dry-run the matching rollback path before cutover.
   2. **Stage production vhost & publicly trusted certificate on the worker before DNS flip:**
      Keep `conf.d/upload-candidate.caddy` active so in-flight resumable
      sessions issued on `upload-hetzner.divine.video` keep draining. Because
      stock `caddy:2-alpine` does not bundle the Cloudflare DNS-01 plugin,
      obtain a **publicly trusted** certificate for `upload.divine.video` on the
      host via DNS-01 (for example `certbot certonly --dns-cloudflare` or
      `acme.sh --dns dns_cf` — do **not** use a Cloudflare Origin CA cert, which
      fails direct TLS verification on DNS-only records). Copy regular files (not
      symlinks, which break inside `./conf.d:/etc/caddy/conf.d:ro`) for the full
      chain and private key to `/opt/divine-transcoder/conf.d/certs/upload.pem`
      (`fullchain.pem`, including intermediates) and
      `/opt/divine-transcoder/conf.d/certs/upload.key` (`privkey.pem`,
      `install -m 600` so it is readable only by root/Caddy). Configure an
      automated renewal hook that copies both renewed files into `conf.d/certs/`
      (`certbot` `--deploy-hook` or `acme.sh --install-cert --fullchain-file /opt/divine-transcoder/conf.d/certs/upload.pem --key-file /opt/divine-transcoder/conf.d/certs/upload.key --reloadcmd "..."`)
      and forces Caddy to reload its in-memory file certificate from outside the
      Compose directory:
      ```sh
      docker compose --project-directory /opt/divine-transcoder exec -T caddy caddy validate --config /etc/caddy/Caddyfile && \
      docker compose --project-directory /opt/divine-transcoder exec -T caddy caddy reload --force --config /etc/caddy/Caddyfile
      ```
      *(Both `--force` and `--project-directory` are required: plain
      `caddy reload` is a no-op when the Caddyfile text is unchanged and would
      keep serving the old in-memory cert until expiry, and non-interactive
      `certbot`/`acme.sh` hooks run without a Compose working directory or TTY.)*
      Next, copy `Caddyfile.upload.example` to `conf.d/upload.caddy` with
      literal site address `upload.divine.video` and
      `tls /etc/caddy/conf.d/certs/upload.pem /etc/caddy/conf.d/certs/upload.key`
      inside the site block, then validate and reload Caddy without recreating
      `caddy` or `transcoder`:
      ```sh
      docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile
      docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
      ```
   3. **Verify production SNI & TLS directly on the worker before DNS cutover:**
      Confirm the worker presents a valid trusted certificate for
      `upload.divine.video` and answers healthy directly at the worker IP:
      ```sh
      curl -fsS --resolve upload.divine.video:443:<worker-ip> https://upload.divine.video/
      ```
      Do not move DNS until this check succeeds.
   4. **Switch `UPLOAD_BASE_URL`, drain safely, and re-verify health:** Update
      `UPLOAD_BASE_URL=https://upload.divine.video` in `.env.upload` and
      recreate `upload` cleanly (`docker compose up -d --no-deps --force-recreate upload`
      — Compose honors `stop_grace_period: 330s` to let `divine-upload-server`'s
      300s shutdown drain complete) so newly initialized sessions advertise the
      production hostname. Avoid starting new candidate-hostname test uploads
      between this step and step 7.5. Confirm `upload` is healthy and still
      serves the production SNI check before flipping DNS:
      ```sh
      docker compose ps upload
      curl -fsS --resolve upload.divine.video:443:<worker-ip> https://upload.divine.video/
      ```
   5. **Flip production DNS via the chosen controller/owner and verify steady-state TLS:**
      Point the DNS-only (grey-cloud) `A` record for `upload.divine.video` to
      the worker IP (with matching or removed `AAAA`), wait for public DNS
      propagation (`dig @1.1.1.1 +short A upload.divine.video`), and repeat the
      smoke checks from step 5 (including the `POST /transcribe` WebVTT check)
      against `https://upload.divine.video`. Keep the DNS-01 file certificate
      (`conf.d/certs/upload.pem` / `upload.key`) and `tls` directive in
      `conf.d/upload.caddy` active under the automated `certbot` / `acme.sh`
      renewal hook installed in step 7.2 (which copies the renewed fullchain and
      private key into `conf.d/certs/` and runs `caddy reload --force`) — do
      **not** remove `tls` and reload
      Caddy while Caddy's managed ACME storage is empty, because Caddy unloads
      the file certificate immediately and fails TLS SNI handshakes until a
      managed issuer certificate is obtained. Only transition to Caddy-managed
      ACME if a managed certificate is already provisioned and verified in
      Caddy storage (or during a planned maintenance window). Keep the previous
      GKE endpoint available during DNS propagation, and keep
      `conf.d/upload-candidate.caddy` active until all sessions issued on the
      candidate hostname have drained.

### Rollback

Restore `upload.divine.video` `A` record to the GKE Gateway IP while
`upload.divine.video` remains excluded from ExternalDNS (or through the
chosen DNS controller / OpenTofu stack). Verify the GKE endpoint serves the
production certificate and can resume sessions begun on Hetzner, and only then
re-enable ExternalDNS management (`excludeDomains` removal) if returning DNS
ownership to ExternalDNS. Keep `conf.d/upload.caddy` serving through DNS
propagation and active-request drain (`stop_grace_period: 330s`), then remove
`conf.d/upload.caddy` and `conf.d/certs/` and validate/reload Caddy:
```sh
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
```
Resumable sessions issued on the candidate hostname (`UPLOAD_BASE_URL` =
`https://upload-hetzner.divine.video`) stay pinned to the worker and can sit
idle between chunks up to `RESUMABLE_SESSION_TTL_SECS` (`86400`s). Keep
`conf.d/upload-candidate.caddy` and `upload` running until candidate-host
sessions finish or reach their `86400`s expiry (or after confirming no active
candidate sessions remain). Only then remove `conf.d/upload-candidate.caddy`,
validate and reload Caddy
(`docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile && docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`),
stop and remove `upload` (`docker compose stop upload && docker compose rm -f upload`),
and finally remove `COMPOSE_FILE` (and `UPLOAD_DOMAIN`, if set) from `.env`
(so empty `UPLOAD_DOMAIN` cannot fail Caddy config parsing and `upload` is not
left behind as an orphan container). Remember that editing `.env` still changes
`transcoder`'s Compose hash; avoid broad `docker compose up -d` until
`transcoder` is intentionally drained.
