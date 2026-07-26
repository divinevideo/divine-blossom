# Internal Compilation Editor: Design Spec

**Status:** Approved design, awaiting written-spec review
**Date:** 2026-07-26
**Site:** `https://compiler.divine.video`
**Related backend design:** [Compilation Service: Design Spec](./2026-05-17-compilation-service-design.md)
**Related implementation plan:** [Compilation Service](../plans/2026-05-17-compilation-service.md)
**Related upload proposal:** [Compiler Uses Upload Service](../proposals/2026-05-17-compiler-uses-upload-service.md)

## Goal

Build a small internal site that lets Divine staff turn an existing ordered Nostr
video list into branded compilations for external platforms.

The editor must make list curation the primary workflow:

1. Open an existing Nostr list.
2. Reorder its videos and adjust framing.
3. Save the new order back to the list.
4. Render selected `9:16`, `1:1`, and `16:9` outputs.
5. Preview or download the resulting MP4 files.

Compilations are not Divine posts. Divine videos remain six-second creations.
The longer compilation outputs are files for Reels, TikTok, YouTube, and similar
external distribution.

## Product Principles

- **Lists are the source of truth.** The editor starts from an existing list and
  does not provide video search or an add-video flow in v1.
- **Ordering is authorship.** A changed order is published to Nostr before a
  compilation can start.
- **Human curation remains visible.** Credits identify the creator of each source
  clip, and the editor never presents the compilation as newly generated Divine
  content.
- **A render is reproducible.** Every job records the exact signed list event and
  render settings used, not a pointer that can resolve differently later.
- **The GPU is not the website.** Opening or editing a list must not start the
  Cloud Run GPU service.

## V1 Scope

### Included

- Internal site at `compiler.divine.video`.
- Whole-site Cloudflare Access protection for Divine staff.
- Nostr identity connection through the existing Divine signer and Keycast.
- Personal and authorized shared editorial signing identities.
- Existing kind `30005` list selection.
- Manual drag-and-drop ordering.
- Sequential full-frame playback: one clip at a time, with hard cuts.
- Global fit mode per aspect plus optional per-clip overrides.
- Instant browser preview using source media.
- Divine watermark and per-clip creator credit preview.
- Independent `9:16`, `1:1`, and `16:9` renders.
- Recent jobs for the initiating staff member.
- Playable completed-output preview, Download, and Copy URL actions.

### Excluded

- Searching for or adding videos.
- Creating a new list.
- Split-screen, picture-in-picture, collage, or freeform canvas layouts.
- Transitions other than hard cuts.
- Source trimming.
- Background music, audio replacement, or voiceover.
- Intro or outro cards.
- Publishing a compilation as a Nostr video event or Divine post.
- Direct publishing to an external social platform.
- Job cancellation.
- A server-generated low-resolution proof render.
- A public gallery or public compiler access.

## System Architecture

The feature lives in this repository as two new, separately deployable
components:

```text
compiler.divine.video
        |
        v
Cloudflare Access
        |
        v
compiler-web/                Cloudflare Worker + static React/Vite assets
        |
        | same-origin /api proxy
        v
cloud-run-compiler/          Private Cloud Run GPU service
        |
        +--> Divine API / relay data
        +--> media.divine.video source blobs
        +--> cloud-run-upload resumable upload API
        +--> Firestore compilation_jobs
```

### `compiler-web/`

`compiler-web/` contains:

- A React/Vite single-page editor.
- Cloudflare Worker routing and static asset delivery.
- A same-origin `/api/*` proxy to the compiler backend.
- Cloudflare Access identity validation and propagation.

The Worker serves all normal UI routes without contacting the compiler. It only
contacts Cloud Run for job creation, job status, recent jobs, and output
metadata.

### `cloud-run-compiler/`

`cloud-run-compiler/` remains a rendering API with no server-rendered UI. It:

- Authenticates and validates compile requests.
- Resolves source events and creator profiles.
- Downloads and probes source media.
- Builds aspect-specific FFmpeg filter graphs.
- Encodes with NVENC and falls back to CPU when required.
- Uploads outputs through `cloud-run-upload`.
- Persists immutable job inputs and job results in Firestore.

The Cloud Run service is not publicly invokable by a browser. Requests must
arrive through the compiler edge with valid edge-to-backend authentication.
The exact Cloudflare-to-Google credential mechanism may be selected in the
implementation plan, but it must prevent callers from reaching Cloud Run
directly or forging staff identity headers.

## Identity and Trust Boundaries

The editor uses two identities for distinct purposes.

### Staff identity

Cloudflare Access decides who may load the site. The edge records the verified
Access identity on each mutating request as `initiated_by`. This value is used
for internal audit, recent-job filtering, and incident response.

The backend trusts Access-derived headers only after it has authenticated the
compiler edge. It never accepts an `initiated_by` value from browser JSON.

### Nostr signing identity

Inside the protected site, the staff member connects the Divine signer through
Keycast and selects either:

- Their personal Nostr identity, or
- An editorial identity they are authorized to use.

That identity signs the replacement kind `30005` list event and the NIP-98
authorization for the compile request. No `nsec` is stored in the browser,
Cloudflare Worker, or compiler service.

For an editor-originated compile request:

- The NIP-98 pubkey must equal the signed list event pubkey.
- The NIP-98 URL binds to the public same-origin endpoint
  `https://compiler.divine.video/api/compile`.
- The backend verifies the NIP-98 event, exact method, exact URL, freshness, and
  request payload hash.
- The edge forwards the original public URL needed for verification; the
  private Cloud Run URL is not used as the NIP-98 audience.

The job records both the signing pubkey and the initiating Access identity.

## Nostr List Semantics

### Accepted list

V1 accepts an existing parameterized replaceable kind `30005` event. The list
must:

- Have a valid Nostr signature.
- Include a non-empty `d` tag.
- Be signed by the selected identity.
- Contain ordered `a` tags that address kind `34235` or `34236` video events.

The list's video order is the literal order of those `a` tags. The editor does
not sort by timestamp, title, engagement, or any other field.

### Reordering without data loss

When the curator reorders clips, the editor constructs a full replacement
event. It preserves:

- The list content exactly.
- Every non-video tag exactly, including its position, except the
  `play-order` tag described below.
- Every video `a` tag value and optional relay hint exactly.

Only the placement of video `a` tags among the existing video-tag slots changes.
The saved event contains exactly one `["play-order", "manual"]` tag so Divine
clients use the literal `a` tag order:

- If a `play-order` tag exists, its first occurrence is replaced in place and
  duplicate occurrences are removed.
- If none exists, the tag is inserted immediately before the first video `a`
  tag.

This is a full event replacement, not a patch. Tests must prove that unknown
tags survive byte-for-byte at the tag-array value level.

### Optimistic conflict detection

The event loaded by the editor is the edit base. Immediately before signing a
replacement, the editor queries the configured Divine relay/API for the newest
event with the same `(kind, pubkey, d)` coordinates.

- If its event ID equals the edit base ID, saving may proceed.
- If it differs, saving stops and the curator must reload the updated list.
- The editor does not merge two concurrent reorderings in v1.

The editor waits for the configured publish path to acknowledge the replacement
before enabling compilation. A save failure or stale-list conflict prevents the
job from starting.

### Immutable compile snapshot

After a successful save, the browser sends the exact signed replacement event
in the compile request. The compiler:

- Verifies the event signature, kind, author, and `d` tag.
- Reads ordered video coordinates from that event.
- Resolves those exact coordinates.
- Never fetches "the latest list" to determine render order.

The list may be edited again while the job runs without changing the job.

## Curator Workflow

The editor is one focused workspace rather than a multi-step wizard.

### 1. Choose a list

The header contains:

- Signing identity selector.
- Existing-list selector, limited to lists owned by the selected identity.
- Current save state.

Changing identity clears the current list and any unsaved edits.

### 2. Preview and frame

The main preview displays the current clip sequence using original or existing
playable source URLs. It approximates:

- Hard-cut timing and order.
- Selected aspect ratio.
- Fit mode.
- Watermark placement.
- Per-clip credit text.

Aspect tabs switch among `9:16`, `1:1`, and `16:9`. Each aspect has a global
fit mode:

- `blur-pad`
- `center-crop`
- `letterbox`

The selected clip may override the fit mode for the current aspect. Overrides
are keyed by the full Nostr `a` coordinate, never by a shortened identifier or
array index.

The preview is intentionally approximate. The FFmpeg output is authoritative
for final crop boundaries, fonts, timing, audio normalization, and codec
behavior.

### 3. Reorder

A horizontal or vertical timeline shows:

- Clip thumbnail.
- Creator credit.
- Source availability warning, when known.
- Per-aspect framing override indicator.

Dragging updates local editor state immediately but does not silently publish.
The primary save action clearly states that it updates the Nostr list.

### 4. Save list

`Save list` performs conflict detection, asks the connected signer to sign the
full replacement event, and publishes it. A successful save replaces the edit
base with the new signed event. The replacement event's `created_at` must be
strictly greater than the edit base's `created_at` so relays consistently select
it as the newer parameterized replaceable event.

`Render` is disabled while there are unsaved ordering changes.

### 5. Render

The curator selects one or more aspects and starts a job. All selected aspects
share one immutable list snapshot but have independent render configurations
and outcomes.

Closing the page does not cancel the job. Returning staff can find it under
Recent jobs.

### 6. Use outputs

For each successful aspect, the result view provides:

- An inline video player.
- Download.
- Copy URL.
- Dimensions, duration, file size, and SHA-256 digest.

The interface provides no "Publish to Divine" action.

## Visual and Brand Treatment

The editor follows Divine's current product guidelines:

- "Divine" capitalization in all copy.
- Bricolage Grotesque for display headings.
- Inter for UI and body text.
- Phosphor icons.
- No gradients on layout surfaces.
- Candid, direct labels rather than campaign or enterprise language.

The UI should feel like a compact editorial tool: a dark or neutral playback
surface, clear aspect controls, a tactile clip timeline, and one unmistakable
render action.

The existing compilation service's watermark and credit behavior remains the
rendering baseline for v1. Before implementation locks pixel positions, the
compiler-specific overlay must be checked against the current Divine brand
guideline for logo-plus-creator attribution. Any deliberate exception must be
recorded in the implementation plan and accepted with a rendered staging
sample.

## Editor API

The browser only calls same-origin `/api` routes. Schemas use full Nostr values;
examples below use descriptive placeholders rather than abbreviated IDs.

### `POST /api/compile`

The request contains the exact signed list event and all render settings:

```json
{
  "source": {
    "list_event": {
      "id": "<64-character-lowercase-hex-event-id>",
      "pubkey": "<64-character-lowercase-hex-pubkey>",
      "created_at": 1785024000,
      "kind": 30005,
      "tags": [
        ["d", "weekly-favorites"],
        [
          "a",
          "34236:<64-character-lowercase-hex-pubkey>:<video-d-tag>",
          "wss://relay.divine.video"
        ]
      ],
      "content": "",
      "sig": "<128-character-lowercase-hex-signature>"
    }
  },
  "renders": [
    {
      "aspect": "9:16",
      "default_fit": "blur-pad",
      "clip_overrides": [
        {
          "coordinate": "34236:<64-character-lowercase-hex-pubkey>:<video-d-tag>",
          "fit": "center-crop"
        }
      ]
    },
    {
      "aspect": "1:1",
      "default_fit": "center-crop",
      "clip_overrides": []
    }
  ],
  "watermark": {
    "enabled": true,
    "position": "bottom-right",
    "opacity": 0.3
  },
  "credit": {
    "duration_ms": 2500,
    "show_display_name": true,
    "show_nip05": true
  },
  "audio": {
    "target_lufs": -14
  },
  "max_duration_sec": 600
}
```

The real `list_event.tags` array is preserved in full. The shortened array in
the example only illustrates the schema.

Validation rules:

- `renders` contains one to three unique supported aspects.
- Every override coordinate exists in the signed list event.
- At most one override exists per coordinate per aspect.
- Fit values are one of the three supported modes.
- The signed list contains no more than 500 video coordinates.
- The NIP-98 signing pubkey matches `list_event.pubkey`.
- Unknown request fields are rejected.

The immediate response is:

```json
{
  "job_id": "cmp_<opaque-job-id>",
  "status": "queued"
}
```

### `GET /api/compile/:job_id`

The authenticated initiating staff member may poll a job. A successful
multi-aspect job may include failed aspects:

```json
{
  "job_id": "cmp_<opaque-job-id>",
  "status": "done",
  "progress": 1.0,
  "result": {
    "outputs": [
      {
        "aspect": "9:16",
        "url": "https://media.divine.video/<64-character-lowercase-hex-sha256>",
        "sha256": "<64-character-lowercase-hex-sha256>",
        "size": 12345,
        "dim": "1080x1920"
      }
    ],
    "aspect_failures": [
      {
        "aspect": "1:1",
        "code": "render_failed",
        "message": "The square version could not be rendered."
      }
    ],
    "duration_sec": 47.5,
    "clips_used": 8,
    "clips_dropped": [],
    "credits": []
  },
  "error": null
}
```

Job status remains `queued | running | done | failed`.

- `done` means at least one requested aspect produced and uploaded an output.
- `failed` means no requested aspect produced an output, or no source clip was
  usable.
- Each unsuccessful aspect appears in `result.aspect_failures`.

An unknown job, or a job outside the caller's allowed audit scope, returns
`404`.

### `GET /api/jobs?limit=20`

Returns recent jobs initiated by the authenticated Access user, newest first.
The response contains enough list identity, status, aspect, and output metadata
to reopen the result view. Operator-wide job inspection remains an admin
capability.

### Callbacks

The editor does not accept or expose `callback_url`. It polls job state, and a
page close has no effect on the worker.

The general compiler API may retain authenticated callbacks for trusted
programmatic callers, but callback configuration is not accepted from the
editor request body.

## Compilation Pipeline

1. Authenticate the compiler edge and validate the Access and NIP-98 identity
   context.
2. Verify the exact signed kind `30005` list event.
3. Persist the complete event, requested render settings, signing pubkey, and
   initiating Access identity before acknowledging the queued job.
4. Resolve the ordered kind `34235` and `34236` `a` coordinates from the signed
   event. Addressable reference resolution is mandatory in v1.
5. Fetch each video event and creator kind `0` profile without losing raw event
   tags.
6. Download the source MP4 blobs with bounded concurrency.
7. Probe duration, dimensions, codec, audio, and rotation.
8. Drop unusable clips with a machine-readable reason and continue.
9. Tail-drop clips that would exceed `max_duration_sec`.
10. Build an independent FFmpeg graph for each requested aspect, applying that
    aspect's default fit and per-clip overrides.
11. Concatenate clips with hard cuts, apply Divine overlay and timed creator
    credits, normalize audio, and encode H.264/AAC MP4 with `+faststart`.
12. Use NVENC when supported and retry the affected render on CPU when GPU
    encoding cannot handle an input.
13. Upload each completed aspect through the resumable `cloud-run-upload`
    session flow, using a trusted compiler-output option that suppresses
    downstream transcoding and transcription.
14. Persist each output as it succeeds, record per-aspect failures, and mark the
    job terminal.

Aspect renders are failure-isolated. One aspect failing does not discard an
already uploaded output from another aspect.

## Source and Render Failure Behavior

### Per-clip failures

Unavailable, moderated, corrupt, missing, or unsupported clips are represented
as warnings in `clips_dropped`. The worker continues with remaining clips.

Useful reason codes include:

- `event_not_found`
- `media_not_found`
- `media_restricted`
- `missing_media_metadata`
- `download_failed`
- `probe_failed`
- `unsupported_media`
- `duration_cap_exceeded`

If zero clips remain usable, the job fails with `no_usable_clips`.

### Save failures

A stale edit base, signer rejection, relay/API rejection, or publish timeout
keeps local edits visible and prevents compilation. The user may retry a
non-conflict failure. A conflict requires reload.

### Render failures

The service retries NVENC-specific failures on CPU. It does not retry malformed
inputs indefinitely. Independent aspect failures are reported as described in
the API contract.

### Upload failures

Outputs use the upload service's resumable `init`, session transfer, and
completion flow. The compiler must stream files from disk and must not read an
entire output into memory. An upload failure only fails its aspect.

The current upload completion path starts HLS transcoding and transcription for
every video. Compiler outputs are already final distribution MP4s, so the
upload service must accept a trusted compiler-only instruction to skip those
derivatives. Ordinary upload clients must not be able to forge that instruction,
and their current derivative behavior must remain unchanged.

### Rerendering

There is no in-place retry or mutation of a completed job. `Render again`
creates a new job from the same immutable signed event and copied settings.

## Output Ownership and Publishing

Compiled MP4s are service-owned Blossom blobs in v1. The compiler:

- Uses the existing upload service path so storage and CDN registration match
  normal Divine media.
- Suppresses redundant HLS transcoding and transcription through an
  authenticated internal upload option.
- Records the returned descriptor, URL, hash, and size.
- Does not publish a kind `34235`, kind `34236`, or any other Nostr event for the
  compilation.
- Does not add the compilation to the source list.
- Does not expose service signing keys to the editor.

The result URL is intended for staff-controlled external distribution. Operator
removal uses existing internal media administration.

## Persistence and Audit

Firestore collection `compilation_jobs` stores:

- Immutable signed list event.
- Full render configuration.
- Signing pubkey and derived tenant identity.
- Verified initiating Access identity.
- Job timestamps and state transitions.
- Per-clip drops.
- Per-aspect outputs and failures.
- Credit metadata used by the renderer.

Editor list reads and unsaved drag state stay in the browser. The compiler does
not persist Keycast sessions or Nostr private keys.

Structured logs include `job_id`, signing tenant, initiator, list coordinates,
requested aspects, terminal status, clip-drop counts, and per-aspect outcomes.
Logs never include authorization tokens, private keys, or shortened Nostr IDs.

## Rate Limiting

Compile-job limits apply per signing identity using the backend's transactional
hourly and daily counters. The verified Access identity is also logged so
operators can distinguish multiple people using one editorial signer.

Read polling uses a separate, substantially higher edge limit and must apply
bounded backoff while a job is running. Static editor assets and normal list
editing do not consume GPU compile quotas.

## Testing and Acceptance

### List event tests

- Reordering changes only video `a` tag placement and the canonical
  `["play-order", "manual"]` tag.
- Unknown tags, tag values, relay hints, content, and `d` tag survive.
- Stale-base detection blocks replacement publication.
- Personal and authorized shared signing identities both work.
- Signer rejection and publish failure leave the list unsaved.
- Full Nostr identifiers are preserved in fixtures and logs.

### Editor tests

- The preview follows list order.
- Aspect switching applies independent default fit settings.
- Per-clip framing overrides are scoped to their aspect.
- Credits and watermark appear in preview.
- Unsaved order disables rendering.
- The editor has no video search, add-video, Publish to Divine, or cancellation
  action.
- Returning to Recent jobs restores result access.

### Edge and API tests

- Cloudflare Access is required for every site and API route.
- Forged Access identity headers are rejected at the backend trust boundary.
- NIP-98 method, public URL, freshness, payload hash, and signature are checked.
- The NIP-98 pubkey must equal the list author.
- The backend verifies the list signature and reads literal `a` tag order.
- The job persists the exact event received rather than resolving the latest
  list.
- Tenant and initiator access checks prevent cross-user job enumeration.

### Compiler tests

- Kind `34235` and `34236` addressable coordinates resolve in order.
- FFmpeg filters apply the correct fit per clip and per aspect.
- Credit windows follow the concatenated timeline.
- Missing clips drop without reordering remaining clips.
- Zero usable clips fails the job.
- NVENC failure selects the CPU fallback.
- One successful aspect plus one failed aspect produces `done` with
  `aspect_failures`.
- Resumable output publishing streams from disk and records the returned blob
  descriptor.
- Compiler output completion does not trigger HLS transcoding or transcription,
  while ordinary video uploads still do.

### End-to-end verification

- CI renders a tiny CPU-only fixture and inspects duration, dimensions, codec,
  audio, watermark, credits, and order.
- Staging performs a GPU smoke test that renders all three aspects from one
  signed test list.
- A human reviews staging crop behavior, credit legibility, watermark treatment,
  and Download/Copy URL behavior before launch.

## Required Reconciliation With the May Backend Plan

The May backend plan remains useful for service scaffolding, job storage,
authentication, media processing, deployment, and most FFmpeg work. Before code
execution, the implementation plan must be revised for these approved v1
requirements:

1. Add `compiler-web/` and the Cloudflare Access-protected edge deployment.
2. Accept the exact signed kind `30005` event from the editor.
3. Resolve ordered kind `34235` and `34236` `a` coordinates in v1.
4. Add per-aspect defaults and per-clip fit overrides in v1.
5. Record both Nostr signing identity and Access initiator identity.
6. Remove editor-supplied callbacks.
7. Treat aspect rendering and upload as independent outcomes.
8. Stream outputs through the resumable upload-service path and add a trusted
   compiler-only way to suppress redundant derivatives.
9. Keep all compilation outputs off the Divine Nostr publishing path.
10. Add optimistic list-save conflict detection and full-tag preservation tests.

The old plan must not be executed unchanged.

## Decisions Locked

- The site is `compiler.divine.video`, not a route on the main Divine web app.
- Access is internal-only through Cloudflare Access.
- The implementation stays in this repository.
- The site starts from an existing list to encourage list making.
- Reordering updates the Nostr list before rendering.
- Sequential full-frame video is the only v1 layout.
- Preview is immediate and browser-side; there is no proof-render service.
- Fit has a per-aspect default and optional per-clip override.
- Personal and shared editorial signers are supported.
- The compile request contains the exact signed list snapshot.
- Jobs survive page close and cannot be cancelled in v1.
- Outputs can be previewed, downloaded, or copied by URL.
- Compilations are never published to Divine.
