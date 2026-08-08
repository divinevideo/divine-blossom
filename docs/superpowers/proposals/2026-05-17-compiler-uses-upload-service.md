# Proposal: refactor `BlossomPublisher` to call `cloud-run-upload` instead of writing Fastly KV directly

> **Status note (2026-08-08):** "the upload service" here means whatever serves
> `upload.divine.video`. That is the GKE-hosted `divinevideo/divine-upload-server`,
> not the `cloud-run-upload/` directory in this repository. See
> `docs/superpowers/specs/2026-07-26-compilation-deployment-design.md` for the
> current ownership and for why derivative suppression comes from the resumable
> completion path rather than a request flag.


**Status:** proposed
**Targets:** `docs/superpowers/plans/2026-05-17-compilation-service.md`, `docs/superpowers/specs/2026-05-17-compilation-service-design.md`
**Audience:** whoever picks up the next plan revision (codex or human)

## July 2026 transport update

The architectural direction in this proposal remains accepted: compiler outputs
go through `cloud-run-upload`, not direct GCS or Fastly KV writes. The approved
[Internal Compilation Editor design](../specs/2026-07-26-compilation-editor-design.md)
supersedes the one-shot upload mechanics below:

- Stream the output file through the resumable `/upload/init`, session, and
  `/upload/:upload_id/complete` flow instead of reading the complete MP4 into
  memory for one `PUT`.
- Add a trusted compiler-only completion option that suppresses HLS transcoding
  and transcription for these already-final distribution MP4s.
- Preserve the normal derivative behavior for every ordinary upload client.

The May implementation steps below are historical context and must not be
implemented unchanged.

## Context

The earlier plan revision added a direct Fastly KV metadata write inside `BlossomPublisher::put_metadata`. The bug fixes bundled with that pass — credit drawtext after concat, loudnorm in filtergraph, transactional rate limit, tenant-scoped GET, single signed callback secret, 401 in drop reasons — are all correct and should stay. The KV write itself is the only piece that's worth reworking before we ship.

## Problem

Writing the `blob:<sha256>` Fastly KV record from the compiler:

- Couples the compiler to a schema (`BlobMetadata`) that lives in another crate (`src/blossom.rs`, the Fastly Compute service).
- Introduces two new required env vars (`FASTLY_KV_STORE_ID`, `FASTLY_API_TOKEN`).
- Creates a new orphan-blob failure mode (GCS upload succeeds, KV write fails — the blob exists but isn't visible at the edge).
- Embeds a hand-rolled Fastly API client in a service that has no other reason to know Fastly exists.

The compiler ends up knowing things about how Divine serves blobs that aren't its job to know.

## Fix

Have `BlossomPublisher` upload finished MP4s to the existing `cloud-run-upload` service (`https://upload.divine.video/upload`) with a Blossom BUD-01 auth event signed by a service key. That service already does GCS write + Fastly KV registration as a single battle-tested operation; the compiler treats it as a black-box `bytes → BlobDescriptor`.

## Concrete changes

### 1. Config (`src/config.rs`)

- **Remove:** `fastly_kv_store_id`, `fastly_api_token`.
- **Remove:** `output_owner_pubkey` as a separate field (it's derivable from the nsec below).
- **Add:** `output_owner_nsec: String` (required; bech32 nsec or 32-byte hex). The compiler signs Blossom auth events with this key; the corresponding pubkey is the output owner.
- **Add:** `upload_service_url: String` with default `https://upload.divine.video`.
- Update `Config::from_env` + `tests/config.rs` fixtures. Test that a malformed nsec returns `ConfigError::Invalid`.

### 2. `src/blossom.rs` — rewrite `BlossomPublisher`

- Drop the `google-cloud-storage`-based upload; drop `put_metadata`; drop the Fastly API client setup.
- Keep the public contract: `publish_file(src, content_type) -> UploadResult { sha256, size, url }`.
- New body:
  1. Read file, compute sha256.
  2. Build a Blossom auth event (kind 24242, tag `["t", "upload"]`, tag `["x", <sha256>]`, tag `["expiration", <unix ts a few minutes in the future>]`) signed with the service nsec.
  3. Base64-encode the event.
  4. PUT the bytes to `{upload_service_url}/upload` with headers: `Authorization: Nostr <base64>`, `Content-Type: <content_type>`, `Content-Length`.
  5. Parse the upload service's JSON response (it returns a `BlobDescriptor`-shaped JSON: `{ url, sha256, size, ... }`) into `UploadResult`.
- Use the `nostr` crate (already a dep for NIP-98) for keypair load + event signing. `nostr::Keys::parse(&nsec)` accepts either bech32 or hex.

### 3. `deploy.sh`

- **Remove:** `FASTLY_KV_STORE_ID`, `FASTLY_API_TOKEN` env/secret bindings.
- **Remove:** `COMPILER_OUTPUT_OWNER_PUBKEY` env.
- **Add:** `COMPILER_OUTPUT_OWNER_NSEC` from a new Secret Manager secret `compiler_output_owner_nsec`.
- **Add:** `UPLOAD_SERVICE_URL` env with default `https://upload.divine.video`.
- Update the one-time-setup comment block: drop the Fastly secret/store provisioning lines, add:

  ```bash
  echo -n "nsec1..." | gcloud secrets create compiler_output_owner_nsec \
    --data-file=- --project="${PROJECT_ID}"
  ```

Net: 1 new secret added, 2 secrets + 1 env removed. Smaller config surface.

### 4. Spec (`docs/superpowers/specs/2026-05-17-compilation-service-design.md`)

- Pipeline step 2g: rewrite as "Upload each output MP4 to the `cloud-run-upload` service via a Blossom-signed PUT. The upload service handles GCS storage and Fastly KV registration; the compiler treats it as a black-box `bytes → BlobDescriptor` operation."
- "What's reused from cloud-run-transcoder" entry about Fastly KV writes: remove. Add a `cloud-run-upload` reuse note instead.
- Required env vars list: same swap as deploy.sh.

### 5. Tests

- `tests/blossom.rs` keeps the download tests as-is (they don't touch publish).
- For publish: add a wiremock test that asserts the compiler sends a PUT with an `Authorization: Nostr <b64>` header containing a kind-24242 event whose `x` tag matches the body's sha256. Don't test the full upload-service contract here — that's covered by smoke.
- The smoke test exercises the real upload service. No change needed in `scripts/smoke-test.sh`.

## Why this is more KISS than the current direct-KV-write design

- Compiler stops knowing about Fastly KV.
- Compiler stops knowing about the `BlobMetadata` schema (so it doesn't break when that struct gains or loses a field).
- One failure mode for publishing (upload service rejects or 5xxs), not two (GCS ok + KV fails leaves an orphan).
- Net config: 1 new secret added, 2 secrets + 1 env removed.
- Same code path handles every upload to `media.divine.video` — no parallel implementation to maintain.

## Out of scope for this refactor

All the other changes from the prior pass — drawtext-after-concat, loudnorm, transactional rate limit, tenant-scoped GET, signed callbacks, `aspects` non-empty + `https://` callback validation, 401 in drop reasons — stay exactly as written. Those are wins.

## Fallback if cloud-run-upload integration turns out blocked

If the upload service is being sunset, or its auth shape changes incompatibly, then trim the direct KV-write payload from 22 fields to the 6 non-defaults (`sha256`, `size`, `mime_type`, `uploaded`, `owner`, `status`). That at least decouples the compiler from `BlobMetadata` field additions, even if we keep the direct write.
