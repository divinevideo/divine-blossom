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
   Also provision a **bounded** disk scratch filesystem at
   `/var/lib/divine-upload/scratch` with two inner directories —
   `/var/lib/divine-upload/scratch/tmp` (`chown 0:0`, `chmod 1777`, mounted into
   `upload:/tmp`) and `/var/lib/divine-upload/scratch/proxy-tmp` (`chown 101:101`,
   `chmod 0700`, mounted into `upload-proxy:/tmp`) — and verify the bounded
   filesystem from your configured limits: worst-case concurrent `/tmp` spooling
   (`divine-upload-server` resumable completion/verification, `/migrate`, and
   sync `ffmpeg` thumbnail extraction up to `MAX_SYNC_VIDEO_BYTES=100 MiB`,
   plus up to `64` concurrent `16 MiB`
   request bodies buffered on scratch disk by `upload-proxy` across all
   body-eligible methods (`GET`, `HEAD`, `OPTIONS`, and `DELETE` reject
   non-empty bodies with `413` before buffering)) is
   `(MAX_CONCURRENT_UPLOADS + MAX_CONCURRENT_MIRRORS) * MAX_UPLOAD_BYTES + MAX_CONCURRENT_THUMBNAILS * 100 MiB + 64 * 16 MiB`
   plus MP4 remux and filesystem overhead. With `.env.upload.example` defaults
   (`16` uploads + `2` mirrors at `1 GiB`, `12` thumbnails × `100 MiB`, and `64`
   × `16 MiB` proxy body spills ≈ `20.2 GiB` peak), provision at least **`24 GiB`**
   (`24G`–`32G`, scaling up if you raise those concurrency or size caps). Prefer
   a dedicated logical volume/partition; otherwise verify root disk headroom
   (`df -h /`) and run the fail-closed loopback provisioning subshell below
   (create `scratch/tmp` and `scratch/proxy-tmp` **only after** verifying the
   bounded `ext4` filesystem is mounted, never on `/`, and never reformat an
   existing or mounted image):
   ```sh
   (
     set -eu
     SCRATCH_DIR=/var/lib/divine-upload/scratch
     SCRATCH_IMG=/var/lib/divine-upload/scratch.img
     TMP_IMG=/var/lib/divine-upload/scratch.img.tmp
     trap 'rm -f "$TMP_IMG"' EXIT

     df -h /
     install -d -m 0755 "$SCRATCH_DIR"
     if ! mountpoint -q "$SCRATCH_DIR" && [ ! -e "$SCRATCH_IMG" ]; then
       # Use fallocate (or dd if=/dev/zero bs=1M count=24576 if the root FS lacks fallocate)
       fallocate -l 24G "$TMP_IMG"
       mkfs.ext4 -F -E nodiscard -m 0 "$TMP_IMG"
       mv -n "$TMP_IMG" "$SCRATCH_IMG"
     fi
     if [ -e "$SCRATCH_IMG" ]; then
       set -- $(stat -c '%b %s' "$SCRATCH_IMG")
       test $(( $1 * 512 )) -ge "$2"
     fi
     grep -q "$SCRATCH_IMG" /etc/fstab || \
       echo "$SCRATCH_IMG $SCRATCH_DIR ext4 loop,nosuid,nodev,noexec,nofail,x-systemd.before=docker.service 0 2" >> /etc/fstab
     systemctl daemon-reload
     mountpoint -q "$SCRATCH_DIR" || mount "$SCRATCH_DIR"
     mountpoint -q "$SCRATCH_DIR"
     test "$(findmnt -rn -o FSTYPE --target "$SCRATCH_DIR")" = "ext4"
     install -d -m 1777 -o 0 -g 0 "$SCRATCH_DIR/tmp"
     install -m 0644 -o 0 -g 0 /dev/null "$SCRATCH_DIR/tmp/.divine-upload-scratch"
     install -d -m 0700 -o 101 -g 101 "$SCRATCH_DIR/proxy-tmp"
     install -m 0644 -o 101 -g 101 /dev/null "$SCRATCH_DIR/proxy-tmp/.divine-upload-scratch"
     if [ -e "$SCRATCH_IMG" ]; then
       du -h --apparent-size "$SCRATCH_IMG"
       du -h "$SCRATCH_IMG"
     fi
   )
   ```
   Using the inner `tmp/` and `proxy-tmp/` directories plus the
   `.divine-upload-scratch` markers paired with `create_host_path: false` in
   `docker-compose.upload.yml` guarantees Docker refuses to start `upload` or
   `upload-proxy` if those directories do not exist on `/`, and both
   entrypoints fail closed if `/tmp/.divine-upload-scratch` is absent from
   their mounted directory (always verify
   `mountpoint -q /var/lib/divine-upload/scratch && test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch && test -f /var/lib/divine-upload/scratch/proxy-tmp/.divine-upload-scratch`
   before starting `upload` or `upload-proxy`).
   Because OOM kills or forced stops can leave orphaned `NamedTempFile` `.tmp*`
   dotfiles behind, `docker-compose.upload.yml` sweeps `.tmp*` entries on
   container start (warning rather than crash-looping if an entry cannot be
   removed) before `exec /app/divine-upload-server`, and caps `upload` stdout
   logs via Docker `json-file` rotation (`50m` × `5`). Also configure host-level
   Docker `daemon.json` log limits (`log-opts`) for `caddy` and `transcoder`.
   If reclaiming manually while running, stop `upload` first
   (`docker compose stop upload`), remove `.tmp*` files under
   `/var/lib/divine-upload/scratch/tmp` (keeping `.divine-upload-scratch`),
   verify `mountpoint -q /var/lib/divine-upload/scratch && test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch`,
   and start only `upload` (`docker compose up -d --no-deps upload`).
2. On an existing worker, first snapshot the running known-good base Caddy
   configuration and local image ID so Phase C recovery can still restore a
   working ingress even if the updated base `docker-compose.yml` or `Caddyfile`
   fails at runtime (`if [ ! -e "$BACKUP_DIR" ]` preserves the baseline across
   mid-activation retries, and Phase C success, Phase C recovery success, and
   Rollback teardown remove the snapshot so later rollouts capture a fresh one):
   ```sh
   (
     set -eu
     BACKUP_DIR=/var/lib/divine-upload/pre-sync-backup
     BACKUP_TMP=/var/lib/divine-upload/pre-sync-backup.tmp
     if [ ! -e "$BACKUP_DIR" ]; then
       rm -rf "$BACKUP_TMP"
       mkdir -p "$BACKUP_TMP"
       cp -a /opt/divine-transcoder/docker-compose.yml "$BACKUP_TMP/docker-compose.yml"
       cp -a /opt/divine-transcoder/Caddyfile "$BACKUP_TMP/Caddyfile"
       caddy_cid="$(docker compose -f /opt/divine-transcoder/docker-compose.yml ps -q caddy || true)"
       if [ -n "$caddy_cid" ]; then
         docker inspect -f '{{.Config.Image}}' "$caddy_cid" >"$BACKUP_TMP/caddy-image.txt"
         docker inspect -f '{{.Image}}' "$caddy_cid" >"$BACKUP_TMP/caddy-image-id.txt"
       fi
       mv "$BACKUP_TMP" "$BACKUP_DIR"
     fi
   )
   ```
   Then sync the updated deployment files (`docker-compose.yml`,
   `docker-compose.upload.yml`, `Caddyfile`, `Caddyfile.upload.example`,
   `nginx.upload-proxy.conf`, `.env.upload.example`, and `conf.d/.gitkeep`) from
   `cloud-run-transcoder/deploy/off-gcp/` into `/opt/divine-transcoder/` without
   overwriting existing `/opt/divine-transcoder/.env` or `.env.upload` (required
   on existing workers so `Caddyfile` gains `import /etc/caddy/conf.d/*.caddy`
   and `docker-compose.upload.yml` exists before editing `COMPOSE_FILE`).
   Copy `cloud-run-transcoder/deploy/off-gcp/.env.upload.example` to
   `/opt/divine-transcoder/.env.upload` (`chmod 600`) and populate the B2,
   transcribe, and optional parity keys (`MIGRATION_NSEC`,
   `AI_DETECTOR_BASE_URL`, `MAX_UPLOAD_BYTES`, `MIRROR_FETCH_TIMEOUT_SECS`) to
   match live GKE production. Keep `TRANSCODER_URL` at its default
   (`https://divine-transcoder-149672065768.us-central1.run.app`) with
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
   internal `http://transcoder:8080` only if you also attach `transcoder` to the
   `upload_edge` network and configure the local worker with transcription
   credentials and matching `TRANSCRIBE_SHARED_SECRET`). Leaving
   `TRANSCRIBER_URL` unset falls back to `TRANSCODER_URL`, which works against
   the Cloud Run default but fails with `404` if `TRANSCODER_URL` is pointed at
   the off-GCP worker's public Caddy vhost (which intentionally blocks
   `/transcribe/audio`). Set
   `UPLOAD_BASE_URL=https://upload-hetzner.divine.video` for candidate testing
   so `/upload/init` returns candidate-host `/sessions/:id` URLs instead of
   pointing chunk uploads back to GKE.
3. Configure read-only Artifact Registry pull access for
   `us-central1-docker.pkg.dev` under the host account that runs Docker Compose
   (a dedicated service account with `roles/artifactregistry.reader` on
   `dv-platform-prod` / `containers-production` — the runtime `gcp-sa.json`
   mounted inside the container is unavailable to the Docker daemon during
   pulls, and section 1 only logs Docker into `gcr.io`):
   ```sh
   docker login -u _json_key --password-stdin https://us-central1-docker.pkg.dev < /etc/divine-upload/ar-pull-key.json
   ```
   Then add to `/opt/divine-transcoder/.env`:
   ```sh
   COMPOSE_FILE=docker-compose.yml:docker-compose.upload.yml
   UPLOAD_IMAGE=us-central1-docker.pkg.dev/dv-platform-prod/containers-production/divine-upload-server@sha256:<pinned-digest>
   ```
   And pre-pull the pinned image before touching Caddy:
   ```sh
   docker compose pull upload
   ```
   *(Pin a digest built from a `divine-upload-server` commit that includes PR
   `divinevideo/divine-upload-server#51` — `spawn_blocking` thumbnail isolation
   and admission-accounting fixes. Do not set `UPLOAD_DOMAIN` in `.env`; use
   literal hostnames in `conf.d/upload-candidate.caddy` and `conf.d/upload.caddy`
   so staging and cutover never risk duplicate site blocks or an extra Caddy
   restart. Because `transcoder` loads `.env` via `env_file`, editing `.env`
   changes `transcoder`'s Compose config hash; do **not** run a broad
   `docker compose up -d` that would recreate `transcoder` and interrupt
   in-flight jobs.)*
4. Have Platform create the DNS-only (grey-cloud) `A` (and `AAAA` if dual-stack)
   record for `upload-hetzner.divine.video` pointing to the worker IP and verify
   public propagation (`dig @1.1.1.1 +short A upload-hetzner.divine.video`)
   **before** loading the candidate vhost so Caddy's HTTP-01/TLS-ALPN-01 ACME
   certificate issuance succeeds without backoff. Next, copy
   `Caddyfile.upload.example` to `conf.d/upload-candidate.caddy` and
   replace `{$UPLOAD_DOMAIN}` with the literal candidate hostname
   `upload-hetzner.divine.video` (so it can remain active alongside
   `conf.d/upload.caddy` during cutover). Confirm `transcoder` is healthy and
   validate the updated Compose Caddy config (including `./conf.d`, `protocols
   h1 h2`, and `upload_edge`) in a one-off container before touching live
   ingress. Caddy keeps Docker's default 10s stop timeout so routine post-cutover
   restarts can never hold ports 80/443 closed across all vhosts for 15 minutes
   (retrying Cloud Tasks redelivers any aborted `/internal/transcode` HTTP call);
   nevertheless, before recreating `caddy` on a transcoder-only host, check and
   record whether `divine-transcode` already holds an intentional pause, pause
   it if `RUNNING`, and confirm in-flight transcode requests and `ffmpeg` jobs
   have drained to **0**. Only after validation, queue pause, and drain succeed,
   start `upload`, replace `caddy` with `--no-deps` (so Compose does **not**
   recreate `transcoder`), verify `/health`, and resume `divine-transcode` only if
   Phase A created the pause marker (leaving any pre-existing publication hold
   intact). Run these three fail-closed phases in order. If Phase A or Phase B
   fails, resume from the failed phase rather than re-running from Phase A
   (re-running Phase A preserves an existing
   `/var/lib/divine-upload/activation-paused-queue` marker and only Phase C removes
   it upon resuming). If Phase C fails **before** `docker compose up -d --no-deps caddy`
   stops live `caddy`, re-run Phase C; if Phase C fails **during or after**
   replacing `caddy` (leaving `caddy` stopped or unhealthy), do **not** re-run
   Phase C's live-Caddy admin API query — run **Phase C recovery** below to
   restore last known-good transcoder ingress while keeping the queue paused:

   Phase A — Preflight checks and pause `divine-transcode` only if not already paused:
   ```sh
   (
     set -eu
     mountpoint -q /var/lib/divine-upload/scratch
     test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch
     test -f /var/lib/divine-upload/scratch/proxy-tmp/.divine-upload-scratch
     docker compose ps --status running --services | grep -qx transcoder
     docker compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
     init_state="$(gcloud tasks queues describe divine-transcode \
       --location=us-central1 --project=rich-compiler-479518-d2 \
       --format='value(state)')"
     if [ "$init_state" != "PAUSED" ]; then
       gcloud tasks queues pause divine-transcode \
         --location=us-central1 --project=rich-compiler-479518-d2
       mkdir -p /var/lib/divine-upload
       : > /var/lib/divine-upload/activation-paused-queue
     elif [ -f /var/lib/divine-upload/activation-paused-queue ]; then
       echo 'divine-transcode is already PAUSED by this activation; retaining pause marker'
     else
       echo 'divine-transcode was already PAUSED; preserving existing hold for its owner'
     fi
     test "$(gcloud tasks queues describe divine-transcode \
       --location=us-central1 --project=rich-compiler-479518-d2 \
       --format='value(state)')" = "PAUSED"
   )
   ```

   Phase B — Wait up to `910s` until Caddy reports `0` active upstream
   requests and `transcoder` has no active `ffmpeg` worker processes (re-run
   until it exits `0`):
   ```sh
   (
     set -eu
     upstreams="$(docker compose exec -T caddy wget -qO- http://127.0.0.1:2019/reverse_proxy/upstreams)"
     printf '%s\n' "$upstreams" | \
       python3 -c 'import json, sys; up = json.load(sys.stdin); assert up and all(u.get("num_requests", 1) == 0 for u in up), up'
     top_out="$(docker compose top transcoder)"
     test -n "$top_out"
     if printf '%s\n' "$top_out" | grep -q '[f]fmpeg'; then
       echo 'transcoder still running ffmpeg' >&2
       exit 1
     fi
   )
   ```

   Phase C — Gated activation and conditional queue resume (re-checks preflight,
   pause, and captured drain gates inside one `set -eu` block, and resumes
   `divine-transcode` only if Phase A paused it):
   ```sh
   (
     set -eu
     wait_caddy_admin() {
       i=0
       while [ "$i" -lt 15 ]; do
         if docker compose exec -T caddy wget -qO- http://127.0.0.1:2019/config/ >/dev/null 2>&1; then
           return 0
         fi
         i=$((i + 1))
         if [ "$i" -lt 15 ]; then
           sleep 1
         fi
       done
       return 1
     }
     wait_transcoder_health() {
       i=0
       while [ "$i" -lt 15 ]; do
         if curl -fsS --max-time 5 https://transcoder-worker.divine.video/health >/dev/null; then
           return 0
         fi
         i=$((i + 1))
         if [ "$i" -lt 15 ]; then
           sleep 2
         fi
       done
       return 1
     }
     mountpoint -q /var/lib/divine-upload/scratch
     test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch
     test -f /var/lib/divine-upload/scratch/proxy-tmp/.divine-upload-scratch
     docker compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
     test "$(gcloud tasks queues describe divine-transcode \
       --location=us-central1 --project=rich-compiler-479518-d2 \
       --format='value(state)')" = "PAUSED"
     upstreams="$(docker compose exec -T caddy wget -qO- http://127.0.0.1:2019/reverse_proxy/upstreams)"
     printf '%s\n' "$upstreams" | \
       python3 -c 'import json, sys; up = json.load(sys.stdin); assert up and all(u.get("num_requests", 1) == 0 for u in up), up'
     top_out="$(docker compose top transcoder)"
     test -n "$top_out"
     if printf '%s\n' "$top_out" | grep -q '[f]fmpeg'; then
       echo 'transcoder still running ffmpeg' >&2
       exit 1
     fi
     docker compose up -d --no-deps upload-proxy upload
     docker compose up -d --no-deps caddy
     wait_caddy_admin
     docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile
     wait_transcoder_health
     if [ -f /var/lib/divine-upload/activation-paused-queue ]; then
       gcloud tasks queues resume divine-transcode \
         --location=us-central1 --project=rich-compiler-479518-d2
       rm -f /var/lib/divine-upload/activation-paused-queue
     else
       echo 'Preserving pre-existing divine-transcode pause for its owner'
     fi
     rm -rf /var/lib/divine-upload/pre-sync-backup /var/lib/divine-upload/pre-sync-backup.tmp
   )
   ```

   Phase C recovery — Restore last known-good transcoder-only `caddy` ingress if
   Phase C failed after stopping or replacing `caddy` (keeps `transcoder` untouched;
   if the updated base `docker-compose.yml` or `Caddyfile` fails `/health`,
   falls back automatically to `/var/lib/divine-upload/pre-sync-backup`,
   resumes `divine-transcode` only after `/health` passes and only if Phase A
   created the pause marker, and then clears the pre-sync backup so subsequent
   rollouts take a fresh baseline):
   ```sh
   (
     set -eu
     wait_transcoder_health() {
       i=0
       while [ "$i" -lt 15 ]; do
         if curl -fsS --max-time 5 https://transcoder-worker.divine.video/health >/dev/null; then
           return 0
         fi
         i=$((i + 1))
         if [ "$i" -lt 15 ]; then
           sleep 2
         fi
       done
       return 1
     }
     cd /opt/divine-transcoder
     test "$(gcloud tasks queues describe divine-transcode \
       --location=us-central1 --project=rich-compiler-479518-d2 \
       --format='value(state)')" = "PAUSED"
     top_out="$(docker compose top transcoder)"
     test -n "$top_out"
     if printf '%s\n' "$top_out" | grep -q '[f]fmpeg'; then
       echo 'transcoder still running ffmpeg' >&2
       exit 1
     fi
     if [ -f conf.d/upload-candidate.caddy ]; then
       mv -f conf.d/upload-candidate.caddy conf.d/upload-candidate.caddy.disabled
     fi
     docker compose stop upload-proxy upload 2>/dev/null || true
     if ! (
       docker compose -f docker-compose.yml run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile &&
       docker compose -f docker-compose.yml up -d --no-deps caddy &&
       wait_transcoder_health
     ); then
       BACKUP_DIR=/var/lib/divine-upload/pre-sync-backup
       if [ ! -d "$BACKUP_DIR" ]; then
         echo 'Updated base Caddy failed and no pre-sync backup exists; keeping queue paused' >&2
         exit 1
       fi
       echo 'Updated base Caddy failed; restoring pre-sync snapshot' >&2
       cp -a "$BACKUP_DIR/docker-compose.yml" /opt/divine-transcoder/docker-compose.yml
       cp -a "$BACKUP_DIR/Caddyfile" /opt/divine-transcoder/Caddyfile
       if [ -s "$BACKUP_DIR/caddy-image.txt" ] && [ -s "$BACKUP_DIR/caddy-image-id.txt" ]; then
         saved_ref="$(cat "$BACKUP_DIR/caddy-image.txt")"
         saved_id="$(cat "$BACKUP_DIR/caddy-image-id.txt")"
         cur_id="$(docker image inspect -f '{{.Id}}' "$saved_ref" 2>/dev/null || true)"
         if [ "$cur_id" != "$saved_id" ]; then
           docker tag "$saved_id" "$saved_ref"
         fi
       fi
       docker compose -f docker-compose.yml run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
       docker compose -f docker-compose.yml up -d --no-deps caddy
       wait_transcoder_health
     fi
     if [ -f /var/lib/divine-upload/activation-paused-queue ]; then
       gcloud tasks queues resume divine-transcode \
         --location=us-central1 --project=rich-compiler-479518-d2
       rm -f /var/lib/divine-upload/activation-paused-queue
     else
       echo 'Preserving pre-existing divine-transcode pause for its owner'
     fi
     rm -rf /var/lib/divine-upload/pre-sync-backup /var/lib/divine-upload/pre-sync-backup.tmp
   )
   ```
   *(Running `docker compose run --rm --no-deps caddy caddy validate` beforehand
   validates the `./conf.d` mount and site files without binding host ports or
   restarting live `caddy`, so a broken vhost cannot disrupt live
   `transcoder-worker.divine.video` traffic on recreate. The `caddy reload`
   covers the no-recreate case.)*
5. Verify against the candidate hostname (DNS-only / grey cloud). The
   container health check only confirms that the port accepts connections.
   Confirm the pinned image can read `/run/secrets/gcp-sa.json` under
   `cap_drop: ALL`, write scratch files to the bounded disk-backed `/tmp`
   mount (`/var/lib/divine-upload/scratch/tmp`, failing closed with
   `create_host_path: false` if unmounted) with a read-only root, reach both
   configured storage buckets, and reach `TRANSCODER_URL` from inside the
   container (plus container-to-host HTTPS hairpinning if using the worker's
   `/transcode/queue` admission path).
   Confirm `.env.upload` uses the intended buckets, credentials, and concurrency
   limits for this host, then check:
   - `GET /` and `HEAD /` return `200`, and `OPTIONS` preflights succeed across
     the public routes.
   - `GET https://upload-hetzner.divine.video/thumbnail/<known-video-hash>` returns `200 image/jpeg`.
   - Direct `PUT /upload`, resumable `POST /upload/init` → `PUT`/`HEAD /sessions/:id` → `POST /upload/:id/complete`, and `DELETE /upload/:id` abort succeed and write to B2 + GCS.
   - An uploaded video completes HLS transcoding end-to-end via `TRANSCODER_URL`.
   - Requests larger than `16 MiB` are rejected by Caddy with `413`.
   - `POST /transcribe` with a short sample audio clip and a valid BUD-11
     kind-24242 `t=media` token carrying an `expiration` tag returns `200` with
     `text/vtt` WebVTT output (proving `TRANSCRIBER_URL` →
     `POST /transcribe/audio` works end-to-end). Because the minimum `#51`
     `divine-upload-server` build only accepts `server` tag values of
     `upload.divine.video` or `media.divine.video` (rejecting
     `upload-hetzner.divine.video` with `401` before reaching
     `/transcribe/audio`), either omit the `server` tag or scope it to
     `upload.divine.video` / `media.divine.video` for this staging check (if
     staging must accept candidate-scoped clients, add explicit candidate-host
     support upstream in `divine-upload-server` and raise the pinned digest
     floor).
   - `POST /migrate` routes through Caddy cleanly, while `POST /audit` returns
     `404` (only `CLOUD_RUN_HOST` handles `/audit`).
6. Before cutover, record the current `A` and `AAAA` DNS records, ownership TXT
   records, and TTLs. Verify both upload instances share compatible
   object-backed session storage (`ProviderSessionStore`) and can resume each
   other's sessions in both directions (GKE → Hetzner and Hetzner → GKE).
   Confirm both submit to the existing single transcoder writer. Exercise
   `HEAD`, browser preflights, and throttled slow-client uploads near the 16 MiB
   body limit (note Caddy's global `timeouts { read_body 300s }` requires at
   least `~450 kbit/s` for a full `16 MiB` direct `PUT`, whereas `1 MiB`
   resumable chunks succeed down to `~28 kbit/s`). Load test concurrent slow
   uploads, thumbnail misses, and transcoding together: verify `upload-proxy`
   rejects non-empty bodies on strictly bodyless methods (`GET`/`HEAD`/`OPTIONS`/`DELETE`)
   before buffering (`413`), caps aggregate concurrent body-eligible requests at
   `64` across their full lifetime (body buffering on scratch disk plus upstream
   wait up to `310s` for `/upload`, `/upload/init`, `/upload/:id/complete`,
   `/transcribe`, and `/migrate`, with no per-IP cap so Fastly POP egress IPs
   are not throttled after cutover), and rejects excess load with a CORS-enabled
   `429` before body allocation without starving `GET /` / `/thumbnail/:hash` or
   holding Caddy RAM; measure shared `caddy` memory (`CADDY_MEM_LIMIT=2g`,
   `CADDY_GOMEMLIMIT=1600MiB`) and
   `upload-proxy` memory (`UPLOAD_PROXY_MEM_LIMIT=512m`), confirm
   `https://transcoder-worker.divine.video/health` and `/internal/transcode` keep
   succeeding under upload flood/saturation, and check bounded
   `/var/lib/divine-upload/scratch` (`df -h /var/lib/divine-upload/scratch`)
   disk usage (confirming peak stays well within the `>= 24 GiB` budget),
   `upload` container memory usage, CPU saturation, and transcode queue latency.
   Include both upload-generated and on-demand thumbnails in the budget.
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
      live `A` (and any `AAAA`) record so GKE continues serving cached-DNS and
      rollback traffic; verify ExternalDNS stops reconciling the record (or
      transfer DNS ownership to an OpenTofu Cloudflare DNS stack), confirm no
      conflicting `AAAA` record remains, and dry-run the matching rollback path
      before cutover.
   2. **Stage production vhost & publicly trusted certificate on the worker before DNS flip:**
      Keep `conf.d/upload-candidate.caddy` active so in-flight resumable
      sessions issued on `upload-hetzner.divine.video` keep draining. Because
      stock `caddy:2.11.9-alpine` does not bundle the Cloudflare DNS-01 plugin,
      obtain a **publicly trusted** certificate for `upload.divine.video` via
      DNS-01 (do **not** use a Cloudflare Origin CA cert, which fails direct TLS
      verification on DNS-only records). Because Cloudflare API tokens cannot
      be scoped below a whole zone, **never** place a `divine.video` zone-edit
      token on the internet-facing worker. Before cutover, Platform must choose
      one of these two credential-isolation schemes:
      - **Option A — Delegated ACME-only DNS zone:** Point
        `_acme-challenge.upload.divine.video` (`CNAME`) at a dedicated ACME-only
        zone (with no production `divine.video` records) and give the worker a
        token scoped solely to that ACME-only zone (e.g., `acme.sh --issue --dns dns_cf --challenge-alias <acme-only-zone>`
        installing into `/etc/divine-upload/acme/fullchain.pem` and
        `/etc/divine-upload/acme/privkey.pem`, or `lego` CNAME delegation).
      - **Option B — Off-host issuance (zero DNS credentials on the worker):**
        Issue and renew the `upload.divine.video` certificate off-host (where
        DNS-01 credentials already reside) and push only `fullchain.pem` (`0644`)
        and `privkey.pem` (`0600`) into `/etc/divine-upload/certs-inbox/`, then
        let `/usr/local/sbin/deploy-upload-cert.sh` activate them locally.
      Install regular files (not symlinks pointing outside `./conf.d`, which
      break inside `./conf.d:/etc/caddy/conf.d:ro`) inside a versioned release
      directory under `/opt/divine-transcoder/conf.d/certs/releases/<id>/` with
      a **relative** symlink `/opt/divine-transcoder/conf.d/certs/current ->
      releases/<id>` (both symlink and target stay inside the `./conf.d` bind
      mount). For initial staging, install `fullchain.pem` (mode `0644`,
      including intermediates) and `privkey.pem` (mode `0600`, readable only by
      root/Caddy) into `/opt/divine-transcoder/conf.d/certs/releases/initial/`
      as `upload.pem` and `upload.key`, then run
      `ln -sfn releases/initial /opt/divine-transcoder/conf.d/certs/current`.
      Next, copy `Caddyfile.upload.example` to `conf.d/upload.caddy` with
      literal site address `upload.divine.video` and
      `tls /etc/caddy/conf.d/certs/current/upload.pem /etc/caddy/conf.d/certs/current/upload.key`
      inside the site block, then validate and reload Caddy without recreating
      `caddy` or `transcoder`:
      ```sh
      docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile
      docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
      ```
      Once `conf.d/upload.caddy` is loaded and answering SNI for
      `upload.divine.video`, install `/usr/local/sbin/deploy-upload-cert.sh`
      (`chmod 755`) to handle automated renewals safely: it acquires
      `/run/deploy-upload-cert.lock`, confirms `conf.d/upload.caddy` is still
      present (exiting `0` cleanly without creating `conf.d/certs/` if teardown
      has already removed the production vhost), validates the staged leaf
      key-pair match and full certificate chain against the system trust store
      and `upload.divine.video` hostname (`openssl verify -untrusted "$SRC_CERT" -verify_hostname "$SNI_HOST" "$SRC_CERT"`)
      before modifying `conf.d/certs/`, checks idempotency against **both** the
      staged files and a **trusted, hostname-verified** TLS handshake over
      `127.0.0.1:443` matching the leaf SHA-256 fingerprint, atomically swaps
      `conf.d/certs/current`, validates and runs `caddy reload --force`, and
      polls `127.0.0.1:443` until Caddy completes a verified TLS handshake
      (`-verify_hostname "$SNI_HOST" -verify_return_error`) serving the new
      leaf SHA-256 fingerprint. If pre-swap verification, validation, reload,
      trusted TLS handshake verification, or a caught `INT`/`TERM` signal fails
      or interrupts activation, it retains `$PREV` (restoring
      `conf.d/certs/current -> $PREV` and running a recovery `caddy reload --force`
      plus verified TLS check if swapped). Only after the new leaf is confirmed
      trusted and live over TLS does it prune stale release directories:
      ```sh
      #!/bin/sh
      set -eu
      CERT_DIR=/opt/divine-transcoder/conf.d/certs
      VHOST_FILE=/opt/divine-transcoder/conf.d/upload.caddy
      SNI_HOST=upload.divine.video
      SRC_CERT="${1:-${RENEWED_LINEAGE:-/etc/divine-upload/certs-inbox}/fullchain.pem}"
      SRC_KEY="${2:-${RENEWED_LINEAGE:-/etc/divine-upload/certs-inbox}/privkey.pem}"

      mkdir -p /run
      exec 9>/run/deploy-upload-cert.lock
      flock -w 30 9

      if [ ! -f "$VHOST_FILE" ]; then
        exit 0
      fi
      mkdir -p "$CERT_DIR/releases"

      WANT_FP="$(openssl x509 -in "$SRC_CERT" -noout -fingerprint -sha256)"
      test -n "$WANT_FP"
      test "$(openssl x509 -in "$SRC_CERT" -noout -pubkey)" = \
           "$(openssl pkey -in "$SRC_KEY" -pubout)"
      openssl verify -untrusted "$SRC_CERT" -verify_hostname "$SNI_HOST" "$SRC_CERT" >/dev/null

      served_verified_fp() {
        out="$(timeout 5 openssl s_client -connect 127.0.0.1:443 -servername "$SNI_HOST" \
          -verify_hostname "$SNI_HOST" -verify_return_error </dev/null 2>/dev/null)" || return 1
        printf '%s\n' "$out" | openssl x509 -noout -fingerprint -sha256 2>/dev/null || return 1
      }

      wait_for_verified_fp() {
        want="$1"
        i=0
        while [ "$i" -lt 5 ]; do
          if [ "$(served_verified_fp || true)" = "$want" ]; then
            return 0
          fi
          i=$((i + 1))
          sleep 1
        done
        return 1
      }

      if [ -f "$CERT_DIR/current/upload.pem" ] && [ -f "$CERT_DIR/current/upload.key" ] \
         && cmp -s "$SRC_CERT" "$CERT_DIR/current/upload.pem" \
         && cmp -s "$SRC_KEY" "$CERT_DIR/current/upload.key" \
         && [ "$(served_verified_fp || true)" = "$WANT_FP" ]; then
        exit 0
      fi

      REL="releases/$(date -u +%Y%m%dT%H%M%SZ)-$$"
      STAGE="$CERT_DIR/$REL"
      PREV="$(readlink "$CERT_DIR/current" 2>/dev/null || true)"
      PREV_FP=""
      if [ -n "$PREV" ] && [ -f "$CERT_DIR/$PREV/upload.pem" ]; then
        PREV_FP="$(openssl x509 -in "$CERT_DIR/$PREV/upload.pem" -noout -fingerprint -sha256 2>/dev/null || true)"
      fi
      RELOADED=0

      rollback() {
        rc=$?
        trap - EXIT INT TERM
        rm -f "$CERT_DIR/current.next" "$CERT_DIR/current.prev"
        CUR_TARGET="$(readlink "$CERT_DIR/current" 2>/dev/null || true)"
        if [ "$CUR_TARGET" != "$REL" ]; then
          rm -rf "$STAGE"
          exit "$rc"
        fi
        if [ "$RELOADED" -eq 0 ]; then
          if [ -n "$PREV" ]; then
            ln -sfn "$PREV" "$CERT_DIR/current.prev"
            mv -Tf "$CERT_DIR/current.prev" "$CERT_DIR/current"
          else
            rm -f "$CERT_DIR/current"
          fi
          rm -rf "$STAGE"
          exit "$rc"
        fi
        if [ -n "$PREV" ] && [ -n "$PREV_FP" ]; then
          ln -sfn "$PREV" "$CERT_DIR/current.prev"
          mv -Tf "$CERT_DIR/current.prev" "$CERT_DIR/current"
          cd /opt/divine-transcoder
          if docker compose exec -T caddy caddy reload --force --config /etc/caddy/Caddyfile \
             && wait_for_verified_fp "$PREV_FP"; then
            rm -rf "$STAGE"
          else
            printf 'ERROR: certificate rollback to %s is unverified; keeping both %s and %s on disk\n' \
              "$PREV" "$PREV" "$REL" >&2
          fi
        else
          printf 'ERROR: certificate activation for %s failed with no verified previous release; keeping %s on disk\n' \
            "$REL" "$REL" >&2
        fi
        exit "$rc"
      }
      trap 'exit 143' INT TERM
      trap rollback EXIT

      mkdir -p "$STAGE"
      install -m 644 "$SRC_CERT" "$STAGE/upload.pem"
      install -m 600 "$SRC_KEY" "$STAGE/upload.key"
      test "$(openssl x509 -in "$STAGE/upload.pem" -noout -pubkey)" = \
           "$(openssl pkey -in "$STAGE/upload.key" -pubout)"
      openssl verify -untrusted "$STAGE/upload.pem" -verify_hostname "$SNI_HOST" "$STAGE/upload.pem" >/dev/null

      ln -sfn "$REL" "$CERT_DIR/current.next"
      mv -Tf "$CERT_DIR/current.next" "$CERT_DIR/current"

      cd /opt/divine-transcoder
      docker compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile
      RELOADED=1
      docker compose exec -T caddy caddy reload --force --config /etc/caddy/Caddyfile
      wait_for_verified_fp "$WANT_FP"

      trap - EXIT INT TERM
      for d in "$CERT_DIR"/releases/*; do
        [ -d "$d" ] || continue
        if [ "$d" != "$STAGE" ]; then
          rm -rf -- "$d"
        fi
      done
      ```
      *(All three Compose/Caddy details are required: `cd /opt/divine-transcoder`
      — not `--project-directory` alone — because `.env` sets relative
      `COMPOSE_FILE` paths that Docker Compose resolves against the caller's
      cwd, which in non-interactive ACME/systemd hooks defaults to `/`;
      `exec -T` because hooks and systemd units have no TTY; and
      `caddy reload --force` because plain `caddy reload` is a no-op when the
      Caddyfile text is unchanged and would keep serving the old in-memory cert
      until expiry.)*
      Configure **both** the renewal/inbox trigger **and** an independent hourly
      `systemd` activation timer so an interrupted reload is retried even if no
      new certificate is issued on the next cycle:
      - **Option A (`acme.sh` on delegated ACME zone):**
        `acme.sh --install-cert -d upload.divine.video --fullchain-file /etc/divine-upload/acme/fullchain.pem --key-file /etc/divine-upload/acme/privkey.pem --reloadcmd "/usr/local/sbin/deploy-upload-cert.sh /etc/divine-upload/acme/fullchain.pem /etc/divine-upload/acme/privkey.pem"`,
        passing those same `/etc/divine-upload/acme/{fullchain,privkey}.pem`
        paths in `ExecStart=` below *(or with Certbot in an isolated DNS-01
        setup, `certbot reconfigure --cert-name upload.divine.video --deploy-hook /usr/local/sbin/deploy-upload-cert.sh`
        and that lineage path in `ExecStart=`)*.
      - **Option B (off-host sync):** Keep the default
        `/etc/divine-upload/certs-inbox/{fullchain,privkey}.pem` paths in
        `ExecStart=` below and run `systemctl start deploy-upload-cert.service`
        immediately after syncing renewed files (the hourly timer also picks up
        updated inbox files).
      - **Independent retry timer (`/etc/systemd/system/deploy-upload-cert.service` and `.timer`):**
        ```ini
        # /etc/systemd/system/deploy-upload-cert.service
        [Unit]
        Description=Activate issued upload.divine.video TLS certificate in Caddy
        After=docker.service

        [Service]
        Type=oneshot
        TimeoutStartSec=10min
        ExecStart=/usr/local/sbin/deploy-upload-cert.sh
        ```
        ```ini
        # /etc/systemd/system/deploy-upload-cert.timer
        [Unit]
        Description=Retry upload.divine.video TLS certificate activation independently of issuance

        [Timer]
        OnCalendar=hourly
        Persistent=true

        [Install]
        WantedBy=timers.target
        ```
        Enable the timer and run a baseline verification (`systemctl daemon-reload && systemctl enable --now deploy-upload-cert.timer && systemctl start deploy-upload-cert.service`): any failed reload or SNI mismatch leaves `deploy-upload-cert.service` in `failed` state (`systemctl --failed`) and retries hourly until confirmed live.
   3. **Verify production SNI & TLS directly on every worker address family before DNS cutover:**
      Confirm the worker presents a valid trusted certificate for
      `upload.divine.video` and answers healthy directly on `<worker-ipv4>`, and
      also on `<worker-ipv6>` whenever publishing or retaining an `AAAA` record:
      ```sh
      curl -fsS -4 --resolve "upload.divine.video:443:<worker-ipv4>" https://upload.divine.video/
      # Required if publishing an AAAA record for upload.divine.video:
      curl -fsS -6 --resolve "upload.divine.video:443:[<worker-ipv6>]" https://upload.divine.video/
      ```
      Do not move DNS until every target address family check succeeds.
   4. **Switch `UPLOAD_BASE_URL`, drain safely, and re-verify health:** Confirm
      no active candidate-host test uploads are running first — force-recreating
      the single `upload` container stops it while draining
      (`stop_grace_period: 330s`), which briefly takes
      `upload-hetzner.divine.video` offline (`502`) until the new container
      starts. Confirm the bounded scratch mount and marker file are active
      (`mountpoint -q /var/lib/divine-upload/scratch && test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch`),
      update `UPLOAD_BASE_URL=https://upload.divine.video` in `.env.upload`, and
      recreate `upload` cleanly
      (`docker compose up -d --no-deps --force-recreate upload` — Compose honors
      `stop_grace_period: 330s` to let `divine-upload-server`'s 300s shutdown
      drain complete) so newly initialized sessions advertise the production
      hostname. Avoid starting new candidate-hostname test uploads between this
      step and step 7.5. Confirm `upload` is healthy and still serves the
      production SNI check on every target address family before flipping DNS:
      ```sh
      mountpoint -q /var/lib/divine-upload/scratch && test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch
      docker compose ps upload
      curl -fsS -4 --resolve "upload.divine.video:443:<worker-ipv4>" https://upload.divine.video/
      # Required if publishing an AAAA record:
      curl -fsS -6 --resolve "upload.divine.video:443:[<worker-ipv6>]" https://upload.divine.video/
      ```
   5. **Flip production DNS via the chosen controller/owner and verify steady-state TLS:**
      - **Dual-stack cutover:** Only after both IPv4 and IPv6 probes above pass,
        point both DNS-only (grey-cloud) `A` and `AAAA` records for
        `upload.divine.video` to the worker, wait for propagation on both
        address families (`dig @1.1.1.1 +short A upload.divine.video` and
        `dig @1.1.1.1 +short AAAA upload.divine.video`), and repeat the Step 5
        smoke checks (including `POST /transcribe`) over both IPv4 (`curl -4`)
        and IPv6 (`curl -6`).
      - **IPv4-only cutover:** If GKE previously published an `AAAA` record,
        delete that `AAAA` record first while GKE remains available over IPv4,
        wait for the pre-cutover `AAAA` TTL recorded in Step 6 to expire and
        confirm `dig @1.1.1.1 +short AAAA upload.divine.video` returns empty,
        and only then point DNS-only `A` to `<worker-ipv4>` and repeat the Step
        5 smoke checks (including `POST /transcribe`) against
        `https://upload.divine.video`.
      Keep the DNS-01 file certificate
      (`conf.d/certs/current/upload.pem` / `upload.key`) and `tls` directive in
      `conf.d/upload.caddy` active under `/usr/local/sbin/deploy-upload-cert.sh`
      and `deploy-upload-cert.timer` installed in step 7.2 (which atomically
      swaps `conf.d/certs/current`, runs `caddy reload --force`, and verifies
      a trusted, hostname-verified TLS handshake and leaf SHA-256 fingerprint —
      rolling back Caddy + `current` on failure — before cleaning old releases) — do **not** remove `tls` and reload
      Caddy while Caddy's managed ACME storage is empty, because Caddy unloads
      the file certificate immediately and fails TLS SNI handshakes until a
      managed issuer certificate is obtained. Only transition to Caddy-managed
      ACME if a managed certificate is already provisioned and verified in
      Caddy storage (or during a planned maintenance window). Keep the previous
      GKE endpoint available during DNS propagation, and keep
      `conf.d/upload-candidate.caddy` active until all sessions issued on the
      candidate hostname have drained.

### Post-cutover upload upgrades & maintenance

Because only one `upload` container and one `upload-proxy` container run behind
Caddy on this host, every post-cutover `docker compose up -d --no-deps --force-recreate`
on `upload` (image update or `.env.upload` change) or `upload-proxy` (nginx
image bump; nginx stops accepting new connections on `SIGQUIT` while draining)
stops the running container first and drains in-flight requests for up to
`stop_grace_period: 330s` (~5.5 minutes) before starting the replacement. During
that drain window, `upload.divine.video` returns `502` on new uploads,
`/upload/init`, `/complete`, and `/thumbnail` requests (unlike GKE's 2–8 pod
rolling updates). Plan container recreations for a maintenance window (or
temporarily route `upload.divine.video` back to GKE), and verify
`mountpoint -q /var/lib/divine-upload/scratch && test -f /var/lib/divine-upload/scratch/tmp/.divine-upload-scratch && test -f /var/lib/divine-upload/scratch/proxy-tmp/.divine-upload-scratch`
before recreating `upload` or `upload-proxy`.

For config-only changes to `/opt/divine-transcoder/nginx.upload-proxy.conf`,
update the file **in place** using `cp` (do **not** replace it via `mv` or a
write-temp-then-rename tool, because `nginx.upload-proxy.conf` is a single-file
bind mount and changing its host inode leaves the running container reading the
old configuration), then validate and reload cleanly without dropping active
connections:
```sh
docker compose exec upload-proxy nginx -t -c /etc/nginx/nginx.conf
docker compose exec upload-proxy nginx -s reload
```

Zero-downtime single-host `upload` upgrades would require running two `upload`
services behind Caddy/`upload-proxy` with health checks, `lb_try_duration`, and
**separate** `UPLOAD_TMP_DIR` directories so each container's startup sweep
cannot delete the other's scratch marker or spools.

### Rollback

Restore **both** the recorded `A` and `AAAA` DNS records for
`upload.divine.video` to their pre-cutover GKE Gateway state (removing any
Hetzner `AAAA` record if GKE originally had no `AAAA`) while
`upload.divine.video` remains excluded from ExternalDNS (or through the chosen
DNS controller / OpenTofu stack). Verify public propagation on both address
families (`dig @1.1.1.1 +short A upload.divine.video` and
`dig @1.1.1.1 +short AAAA upload.divine.video`), confirm the GKE endpoint serves
the production certificate (over IPv4 and, if restored, IPv6) and can resume
sessions begun on Hetzner, and only then re-enable ExternalDNS management
(`excludeDomains` removal) if returning DNS ownership to ExternalDNS. Keep
`conf.d/upload.caddy` and its TLS certificate serving for **at least the
longer of the published worker `A` and `AAAA` DNS TTLs** after restoring
authoritative DNS (so recursive resolvers expire cached worker records), plus
active-request drain (`stop_grace_period: 330s`). Then stop and remove all
certificate writers **inside a fail-closed teardown block** before removing
`conf.d/upload.caddy` or `conf.d/certs/`: first delete the Option A
`acme.sh`/`certbot` lineage and deploy-hook configuration (or pause off-host
sync for Option B), verify neither unit remains active/activating before
touching `conf.d/` (while keeping the teardown re-runnable after partial
failures), and serialize vhost removal, Caddy validation/reload, and
`conf.d/certs/` deletion under `/run/deploy-upload-cert.lock` (where
`/usr/local/sbin/deploy-upload-cert.sh` also re-checks `conf.d/upload.caddy`
before touching `conf.d/certs/`):
```sh
(
  set -eu
  systemctl disable --now deploy-upload-cert.timer 2>/dev/null || true
  systemctl stop deploy-upload-cert.service 2>/dev/null || true
  for unit in deploy-upload-cert.timer deploy-upload-cert.service; do
    state="$(systemctl is-active "$unit" 2>/dev/null || true)"
    case "$state" in
      inactive|failed|unknown|"") ;;
      *)
        echo "ERROR: $unit still $state; aborting teardown" >&2
        exit 1
        ;;
    esac
  done
  rm -f /etc/systemd/system/deploy-upload-cert.timer /etc/systemd/system/deploy-upload-cert.service
  systemctl daemon-reload
  exec 9>/run/deploy-upload-cert.lock
  flock -w 60 9
  rm -f /usr/local/sbin/deploy-upload-cert.sh
  rm -f /opt/divine-transcoder/conf.d/upload.caddy
  cd /opt/divine-transcoder
  docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile
  docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
  rm -rf /opt/divine-transcoder/conf.d/certs
  exec 9>&-
  rm -f /run/deploy-upload-cert.lock
)
```
Remove any local cert copies (`/etc/divine-upload/acme/`,
`/etc/divine-upload/certs-inbox/`) and any worker DNS-01 credential file, and
**revoke** any Cloudflare DNS-01 API token issued for Option A in Cloudflare
(and remove the `_acme-challenge.upload.divine.video` delegation CNAME if no
longer needed).
Resumable sessions issued on the candidate hostname (`UPLOAD_BASE_URL` =
`https://upload-hetzner.divine.video`) stay pinned to the worker and can sit
idle between chunks up to `RESUMABLE_SESSION_TTL_SECS` (`86400`s). Keep
`conf.d/upload-candidate.caddy` and `upload` running until candidate-host
sessions finish or reach their `86400`s expiry (or after confirming no active
candidate sessions remain). Only then:
1. Delete the `upload-hetzner.divine.video` DNS record(s) (`A` and any
   `AAAA`) so the candidate name never points to a released provider IP, then
   remove `conf.d/upload-candidate.caddy`, validate, and reload Caddy
   (`docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile && docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`).
2. Stop and remove `upload-proxy` and `upload` (`docker compose stop upload-proxy upload && docker compose rm -f upload-proxy upload`), then unmount `/var/lib/divine-upload/scratch`, remove its `/etc/fstab` entry and run `systemctl daemon-reload`, and delete `/var/lib/divine-upload/scratch.img` and `/var/lib/divine-upload/scratch` (or remove the dedicated LV/partition).
3. Delete `/etc/divine-upload/gcp-sa.json` and revoke that service-account key
   in GCP IAM (and remove/revoke `/etc/divine-upload/ar-pull-key.json` and run
   `docker logout https://us-central1-docker.pkg.dev` if no other service on the
   host pulls from Artifact Registry).
4. Remove `/opt/divine-transcoder/.env.upload`, `/var/lib/divine-upload/pre-sync-backup`,
   and `/var/lib/divine-upload/pre-sync-backup.tmp`, remove `COMPOSE_FILE` and
   `UPLOAD_IMAGE` (plus `UPLOAD_DOMAIN`, if set) from `/opt/divine-transcoder/.env`,
   and optionally remove `/opt/divine-transcoder/nginx.upload-proxy.conf` so
   `upload` and `upload-proxy` are not left behind or restarted on reboot. Remember that editing
   `.env` still changes `transcoder`'s Compose hash; avoid broad
   `docker compose up -d` until `transcoder` is intentionally drained.
