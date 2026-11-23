# Blossom on Bunny: Native Edge Scripting Runtime (Track 2)

Native TypeScript/Deno implementation of the Divine Blossom edge service for **Bunny Edge
Scripting** (Standalone `bunny.ts` and Pull Zone Middleware `middleware.ts`), backed by private
Backblaze B2, indexed SQL metadata (`schema.sql`), Cloud Run streaming upload delegation, B2 Native
all-version erasure, and Bunny CDN targeted purging.

> **Production isolation:** Canonical `media.divine.video` DNS and Fastly Compute (`src/main.rs`)
> remain untouched until cutover is explicitly verified and authorized.

## Verify locally

```sh
cd experiments/bunny-blossom
deno task verify
deno bundle --platform=deno bunny.ts -o /tmp/bunny-blossom-standalone.js
deno bundle --platform=deno middleware.ts -o /tmp/bunny-blossom-middleware.js
deno bundle --platform=deno probe_bunny.ts -o /tmp/bunny-blossom-probe.js
```

## Architecture

- **Entrypoints**:
  - `bunny.ts` — Standalone Bunny Edge Script (`ScriptType=0`, `BunnySDK.net.http.serve`)
  - `middleware.ts` — Pull Zone Middleware (`ScriptType=2`, `BunnySDK.net.http.servePullZone`) so
    cached public media HITs pay `$0` script compute while misses and authenticated/control routes
    run through `createApp`.
  - `probe_bunny.ts` — Ephemeral in-memory conformance probe (`GET/HEAD /health`).
- **Media delivery (`GET`/`HEAD`)**:
  - Originals `/<sha256>[.<ext>]`, video thumbnails `/<sha256>.jpg` & `/<sha256>/thumbnail`, HLS
    `/<sha256>.hls` & `/<sha256>/hls/*`, quality variants `/<sha256>/{1080p,720p,480p,360p}[.mp4]`,
    audio `/<sha256>.audio.m4a`, WebVTT transcripts `/<sha256>.vtt`, `/<sha256>.<lang>.vtt`,
    `/<sha256>/VTT`, sound analysis `/<sha256>/sound`, provenance `/<sha256>/provenance`.
  - Full `BlobMetadata::access_for` parity: `active`/`pending` public, `age_restricted` (`401`
    anonymous / `200 private, no-store` for NIP-98 or Blossom GET viewers including legacy optional
    expiry), `restricted` (owner/admin only), `banned`/`deleted`/quarantined (`404`).
  - Public CDN caching (`public, max-age=300, s-maxage=86400`) on unrestricted `active` media when
    `BLOSSOM_PUBLIC_CACHING=true`; `private, no-store` on `pending`, authenticated, restricted, and
    error responses.
- **Uploads, management & control plane**:
  - `HEAD /upload` (BUD-06), `PUT /upload` (streaming proxy to `BLOSSOM_UPLOAD_SERVICE_URL` or
    bounded direct B2 write; blocks legal holds/bans with `403`), `POST /upload/init` &
    `POST /upload/<id>/complete`, `POST /transcribe`.
  - `GET /list/<pubkey>` using indexed `blob_owners` join table with `?limit=&cursor=` pagination.
  - `DELETE /<sha256>` (multi-owner ref decrement, tombstone + durable `purge_outbox`),
    `DELETE /vanish` (GDPR erasure), `PUT /report` (BUD-09), `PUT /mirror` (BUD-04).
  - Subtitle jobs (`/v1/subtitles/jobs*`, `/v1/subtitles/by-hash/*`), transcode/transcript webhooks
    with monotonic generation checks, moderation (`/admin/moderate`, `/admin/api/moderate`,
    `/admin/api/delete`, `/admin/api/restore`, `/admin/api/quarantine`, `/admin/api/bulk-approve`,
    `/admin/api/vanish`), admin inspection (`/admin/api/stats`, `/recent`, `/users`, `/user/<pub>`,
    `/blob/<hash>[/content|/hls/*]`), `/internal/archive/v1/*`, `/api/bunny-playback/<parent>`, and
    `/admin/api/b2-cdn-purge/drain` (B2 Native all-version erasure + Bunny CDN URL/wildcard purge).
- **Migration & deployment tools**:
  - `migrate_kv_to_sql.py` — Idempotent Fastly KV (`blossom_metadata`) → SQL migration (supports
    `--from-backup` JSON or live `--kv-store-id`, `--sqlite-path` or `--sql-url`, `--dry-run`).
  - `deploy_bunny_blossom.py` — Bundles and deploys Standalone or Middleware script to Bunny Edge
    Scripting, binds runtime secrets, and configures Pull Zone `EnableCacheSlice=true` plus
    pre-cache bypass Edge Rules for `Authorization`, non-GET/HEAD, and control-plane routes.

## Durability note

Bunny Database is in public preview and documents possible acknowledged-write loss during primary
failover (up to 10 seconds or 4096 WAL frames). `SqlCatalog` speaks standard libSQL-over-HTTPS
(`https://.../v2/pipeline`, auto-normalizing `libsql://` URLs), so production deployments can point
`BLOSSOM_SQL_URL` at any durable primary libSQL/Turso endpoint or migrate behind a Postgres HTTP
adapter before cutting over canonical `media.divine.video` DNS.

## Remaining parity items before canonical `media.divine.video` cutover

- Admin browser OAuth HTML dashboard (`/admin`, `/admin/auth/google`, `/admin/auth/github*`,
  `/admin/logout`) — Bearer-token admin API is implemented; OAuth HTML UI remains deferred or hosted
  separately.
- Full catalog migration from Fastly KV `blossom_metadata` (`migrate_kv_to_sql.py`) plus dual-write
  or freeze window so Fastly and Bunny metadata do not diverge during cutover.
- Production durability validation of the selected SQL primary under failover and sustained load.
