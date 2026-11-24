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
   transcode admission, transcribe, and optional parity keys (`MIGRATION_NSEC`,
   `AI_DETECTOR_BASE_URL`, `MAX_UPLOAD_BYTES`, `MIRROR_FETCH_TIMEOUT_SECS`,
   `SENTRY_DSN`) to match live GKE production. Confirm `MEDIA_WRITE_PROVIDER`,
   `B2_MEDIA_BUCKET`, `GCS_BUCKET`, and `GCS_COMPAT_ENABLED` match live GKE
   production so both hosts share object storage and resumable sessions. Keep
   `TRANSCRIBER_URL` explicitly set to an origin serving `POST /transcribe/audio`
   (the Cloud Run origin `https://divine-transcoder-149672065768.us-central1.run.app`
   by default, or internal `http://transcoder:8080` only if the local worker is
   configured with transcription credentials and matching `TRANSCRIBE_SHARED_SECRET`);
   leaving `TRANSCRIBER_URL` unset falls back to `TRANSCODER_URL`, whose Caddy
   site intentionally returns `404` for `/transcribe/audio`. Set
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
   start `upload` with `--no-deps`, ensure `caddy` has the `./conf.d` mount
   without touching `transcoder`, and validate before reloading Caddy:
   ```sh
   docker compose ps transcoder
   docker compose up -d --no-deps upload
   docker compose up -d --no-deps caddy
   docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile
   docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```
   *(Always run `caddy validate` before `caddy reload` so a broken vhost cannot
   disrupt live `transcoder-worker.divine.video` traffic. If `caddy` was just
   recreated to pick up the new `./conf.d` mount, wait a second for its admin
   API before validating/reloading.)*
5. Verify against the candidate hostname (DNS-only / grey cloud). The
   container health check only confirms that the port accepts connections.
   Confirm the pinned image can read `/run/secrets/gcp-sa.json` under
   `cap_drop: ALL`, write scratch files to `/tmp` with a read-only root, reach
   both configured storage buckets, and hairpin HTTPS requests to
   `TRANSCODER_URL` (`https://transcoder-worker.divine.video`) from inside the
   container. Confirm `.env.upload` uses the intended buckets, credentials, and
   concurrency limits for this host, then check:
   - `GET /` and `HEAD /` return `200`, and `OPTIONS` preflights succeed across
     the public routes.
   - `GET https://upload-hetzner.divine.video/thumbnail/<known-video-hash>` returns `200 image/jpeg`.
   - Direct `PUT /upload`, resumable `POST /upload/init` → `PUT`/`HEAD /sessions/:id` → `POST /upload/:id/complete`, and `DELETE /upload/:id` abort succeed and write to B2 + GCS.
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
   1. **DNS ownership plan (`divine-iac-coreconfig`):** GKE's production
      `HTTPRoute/divine-upload-server` currently declares
      `external-dns.alpha.kubernetes.io/hostname: upload.divine.video`, so
      ExternalDNS will reconcile manual Cloudflare edits back to GKE. Before
      cutting over, Platform must choose and merge a controller-managed handoff:
      remove the `external-dns.alpha.kubernetes.io/hostname` annotation from
      GKE's `HTTPRoute` (while keeping `spec.hostnames: ["upload.divine.video"]`
      so GKE continues serving rollback traffic), verify ExternalDNS releases
      the record or transfer ownership to an OpenTofu Cloudflare DNS stack, and
      confirm no conflicting `AAAA` record remains.
   2. **Stage production vhost & publicly trusted certificate on the worker before DNS flip:**
      Keep `conf.d/upload-candidate.caddy` active so in-flight resumable
      sessions issued on `upload-hetzner.divine.video` keep draining. Because
      stock `caddy:2-alpine` does not bundle the Cloudflare DNS-01 plugin,
      obtain a **publicly trusted** certificate for `upload.divine.video` on the
      host via DNS-01 (for example `certbot certonly --dns-cloudflare` or
      `acme.sh --dns dns_cf` — do **not** use a Cloudflare Origin CA cert, which
      fails direct TLS verification on DNS-only records). Place the certificate
      and key at `conf.d/certs/upload.pem` and `conf.d/certs/upload.key`
      (`chmod 600 conf.d/certs/upload.key`, readable by Caddy inside the
      existing `./conf.d:/etc/caddy/conf.d:ro` mount), copy
      `Caddyfile.upload.example` to `conf.d/upload.caddy` with literal site
      address `upload.divine.video` and a temporary
      `tls /etc/caddy/conf.d/certs/upload.pem /etc/caddy/conf.d/certs/upload.key`
      directive inside the site block, then validate and reload Caddy without
      recreating `caddy` or `transcoder`:
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
   5. **Flip production DNS via the chosen controller/owner and hand TLS back to Caddy auto-renewal:**
      Point the DNS-only (grey-cloud) `A` record for `upload.divine.video` to
      the worker IP (with matching or removed `AAAA`), wait for public DNS
      propagation (`dig @1.1.1.1 +short A upload.divine.video`), and repeat the
      smoke checks from step 5 (including the `POST /transcribe` WebVTT check)
      against `https://upload.divine.video`. Because a static `tls` directive
      disables Caddy's automatic ACME renewal, once public DNS resolves to the
      worker, remove the temporary `tls /etc/caddy/conf.d/certs/...` line from
      `conf.d/upload.caddy`, validate and reload Caddy
      (`docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile && docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`),
      confirm Caddy serves a renewed ACME certificate for `upload.divine.video`,
      and remove `conf.d/certs/`. Keep the previous GKE endpoint available
      during DNS propagation, and keep `conf.d/upload-candidate.caddy` active
      until all sessions issued on the candidate hostname have drained.

### Rollback

Restore `upload.divine.video` DNS through the same ownership path chosen in step
7.1 (either restoring the GKE `HTTPRoute` ExternalDNS annotation in
`divine-iac-coreconfig` or reverting the OpenTofu Cloudflare DNS record back to
the GKE Gateway IP). Verify the GKE endpoint serves the production certificate
and can resume sessions begun on Hetzner. Keep the Hetzner upload endpoint
running through DNS propagation and until outstanding requests have drained
(`stop_grace_period: 330s`). Then remove `conf.d/upload.caddy`,
`conf.d/upload-candidate.caddy`, and any temporary `conf.d/certs/`, validate
and reload Caddy
(`docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile && docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`),
stop and remove `upload` (`docker compose stop upload && docker compose rm -f upload`),
and only then remove `COMPOSE_FILE` (and `UPLOAD_DOMAIN`, if set) from `.env`
(so empty `UPLOAD_DOMAIN` cannot fail Caddy config parsing and `upload` is not
left behind as an orphan container). Remember that editing `.env` still changes
`transcoder`'s Compose hash; avoid broad `docker compose up -d` until
`transcoder` is intentionally drained.
