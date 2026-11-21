# Bunny HLS and MP4 Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make approved public HLS and MP4 playable through media-bunny.divine.video behind a mobile flag, with verified publication, automatic enrollment and server rollback.

**Architecture:** Extend the existing isolated B2 delivery prefix and publisher. Publish bounded objects, finalize a verified family, and expose a small canonical control-plane selection API; Bunny serves the media directly. Keep canonical uploads and signed post URLs.

**Tech Stack:** Rust/Fastly, Python operational reconciler/probes, Flutter/Dart native players, Bunny CDN and private B2.

**Spec:** docs/superpowers/specs/2026-11-21-bunny-hls-delivery-design.md

## Global Constraints

- Production selection and publication default off; canonical upload, publishing and default playback remain usable.
- Preserve complete lowercase 64-character synthetic hashes in tests. Do not commit secrets, real fixture inventories or commercial cost models.
- Bunny reads only the private `bunny-delivery/` prefix with its own restricted reader.
- Only current approved public media is eligible; authenticated viewer playback stays canonical.
- Preserve uncertain-write exclusion, all-version erasure, retained purge targets and durable retry.
- One object per publication execution; every execution including cleanup fits the 32-backend-request limit.
- 16 MiB maximum object and 64 KiB maximum playlist; support the existing 720p/480p VOD single-TS-file families and original/progressive MP4.
- Readiness never means merely a successful PUT; verify destination bytes, source identities and current policy.
- Automatic enrollment plus updateable server selection are required; compiled fixture lists are only internal QA.
- No merge or production cutover is implied. Prepare and verify the isolated test hostname when available without changing canonical DNS or enabling all users.

## Wire Contract

The endpoint names and response shape below bind the server, reconciler and mobile tasks. Document implementation refinements in this plan/ledger before dependent work.

- Keep authenticated `POST /admin/api/bunny-pilot/publish` compatible with `{path, sha256}` for MP4. For HLS add a bounded `dependencies` array of `{path, sha256}` for the exact direct child delivery objects. `sha256` on the asset pins source bytes; dependency digests pin published child bytes. Normalize same-parent manifest URIs to relative paths. Return the published digest for transformed manifests in addition to the existing result; preserve legacy response shape where needed by existing tests.
- Add authenticated `POST /admin/api/bunny-pilot/finalize` with `{version:1,parent,assets:[{path,source_sha256,delivery_sha256}]}`. Accept an original/progressive set or a complete supported HLS family (plus optional MP4s), bounded to at most 8 objects. Verify exact source/destination bytes and immutable version evidence under parent exclusion and final policy checks, then store `bunny-ready:v1:<parent>`. Unsupported/incomplete families cannot finalize. Readiness carries schema version, parent, exact configured bucket/prefix/hosts and verified assets/destination versions. Existing publisher keys must not gain broader capabilities.
- Add anonymous no-store `GET /api/bunny-playback/<parent>` on the canonical service. If selected return `{version:1,host:"media-bunny.divine.video",paths:[...]}` containing only verified top-level original, progressive MP4 and canonical HLS master paths. No HLS child is a top-level source. Not selected or not ready returns `{version:1,host:"media-bunny.divine.video",paths:[]}`. Current policy denial returns 404; source/policy-service failure does not claim an alternate. Restrict methods and exact path; include CORS for the app.
- Configuration `bunny_playback_rollout_percent` accepts integer 0..100 (default 0), `bunny_playback_countries` accepts explicit uppercase country codes (default none). Use trusted edge geolocation, never a client-spoofable country header. Stable parent-hash bucketing selects cohorts. The existing `bunny_pilot_publish_enabled` independently gates enrollment.
- Mobile production flag `bunnyPlayback` defaults off and permits selection lookups; existing `bunnyPlaybackCanary` remains a device-only allowlisted QA override. Production responses cannot override policy, fixed host/path validation, existing rendition order, or authenticated playback handling.

## Review Focus

- A cached HLS child still resolves to Fastly or another parent: validate and normalize every reference, and probe the entire tree.
- A late producer, PUT or retry outlives revocation: retain exclusion and never finalize old work after current policy denies it.
- A partially published family enters the source ladder: finalize only complete verified families and expose top-level paths only.
- Mobile prefetch or a published post retains test-host selection after rollback: rebuild queued sources and preserve canonical signed post URLs.
- A provider outage is mistaken for either policy permission or completed deletion: keep terminal denials, bounded canonical fallback and durable cleanup evidence distinct.

### Task 1: HLS publication, verified readiness and server selection

**Files:** `blossom-core/src/bunny_pilot.rs`, a focused core HLS validator if needed, `src/bunny_publish.rs`, a focused readiness/selection module if needed, `src/storage.rs`, `src/main.rs`, publisher/revocation fixture scripts, `docs/runbooks/bunny-playback-pilot.md`, relevant Rust/Python tests.

**Consumes:** Existing parent gate, authoritative Bunny policy, B2 credentials, publisher and purge queue.
**Produces:** All server APIs/configuration in Wire Contract, path/MIME helpers and fixture-backed publication/readiness/selection proofs for Tasks 2 and 3.

- [ ] Add failing pure-logic tests for exact HLS/480p paths, relative/absolute same-family URI normalization, VOD/byte-range dependency validation and rejection of unsupported/cross-family references. Run to observe RED.
- [ ] Implement bounded path, MIME, playlist and inventory helpers following current transcoder output. Preserve original/720p behavior.
- [ ] Add failing real loopback tests for child-before-playlist verification, missing/conflicting dependencies, transformed manifest readback, finalization completeness/current policy, selection rollout and revocation of all HLS copies. Record backend request counts on the worst supported success and cleanup paths.
- [ ] Implement one-object HLS publication and finalization. Adjust the plan if a measured request budget requires splitting finalization into bounded stages; never relax source/policy verification or report a partial family ready.
- [ ] Invalidate readiness before revocation and keep retry/recovery working when publication is disabled. Never acknowledge deletion with surviving versions or cached media.
- [ ] Implement selection with strict readiness validation, current origin policy, trusted geography and server cohort controls. Include tests for malformed configuration/readiness and disabled/not-ready behavior.
- [ ] Run Blossom core tests, edge tests under Viceroy, both Bunny loopback scripts, `cargo check --tests --locked`, `cargo clippy --locked --all-targets --all-features`, and relevant Python suites. Run the existing relevant suite once; report pre-existing failures precisely.
- [ ] Update the runbook and sample payloads, self-review and commit. Supply a task report including RED/GREEN evidence, API examples, measured request budget and verification output.

### Task 2: Resumable enrollment and recursive acceptance probes

**Files:** New `scripts/publish_bunny_media.py` and tests, `scripts/probe_bunny_delivery.py` and tests, operational runbook and sample configuration only (no account values).

**Consumes:** Task 1 publication/finalization APIs and exact path/digest contract; existing `scripts/b2_playback_family.py` and `scripts/sync_b2_originals.py` inventory/pinned-source interfaces where applicable.
**Produces:** A bounded resumable operator runner for existing/new ready clips, complete fixture publication and recursive provider proof for activation.

- [ ] Write failing tests for automatic paginated discovery, persisted progress, source version/digest changes, transfer limits and interruption/retry. Record RED.
- [ ] Implement a runner that derives the supported source inventory, validates immutable completion evidence, publishes dependencies before playlists and finalizes only after verified responses. Persist private SQLite progress/cursors; repeat scans discover newly completed clips. Bound bytes, pages and concurrency; do not overwrite conflicting enrolled bytes or auto-clear uncertain gates.
- [ ] Keep credentials in approved environment/private files, out of CLI argument values/output. Report aggregate status without fixture identifiers. Provide a dry run and explicit byte ceiling.
- [ ] Add failing recursive-probe tests for relative URI resolution on both hostnames, segment bytes/ranges, incomplete trees, stale denied playlists and off-host children.
- [ ] Extend probes for the supported HLS family/MIME types, HEAD/Range/cold/warm and revoked children, with bounded traversal and scrubbed output. Preserve existing MP4 proof.
- [ ] Run relevant Python tests and full script suite with its declared dependencies once. Document scheduling/monitoring, retry and rollback; self-review and commit.

### Task 3: Native mobile flag for verified HLS and MP4

**Repository:** divine-mobile, fresh own worktree under its established `.worktrees/` location from origin/main.
**Files:** `mobile/packages/infinite_video_feed/lib/src/utils/canonical_divine_url.dart`, `playback_sources.dart`, `source_loader.dart`, registry/feed integration as needed; app feature flag/config/providers; focused package/app tests and feature flag README. Preserve unrelated UI/native behavior.

**Consumes:** Task 1 `GET /api/bunny-playback/<parent>` response, exact fixed host and path shapes.
**Produces:** Default-off production flag and extended internal HLS canary, both rollback-capable; canonical upload and post URLs preserved.

- [ ] Read repo/package instructions and establish baseline focused playback tests. Add failing tests for selecting equivalent ready HLS/MP4 at the existing rendition position, empty readiness, terminal 404, unsigned/public-only eligibility, malformed/off-host paths and child-load transport versus policy failures.
- [ ] Implement bounded/de-duplicated selection fetches with at most 30-second in-memory caching; on transport/config errors keep canonical sources without hiding policy denials. Keep remote cohorts authoritative.
- [ ] Extend internal canary to exact HLS master paths and use the new production `bunnyPlayback` flag for API-driven selection. Keep B2 canary precedence explicit. Do not require compiled fixture lists for production selection.
- [ ] Watch the flag in the feed and rebuild queued/prefetched sources when disabled. Preserve native no-persistent-cache behavior and credential/diagnostic handling for every Bunny HLS subrequest.
- [ ] Verify fresh publishing/upload flow stays canonical and its resulting clip can choose Bunny once server readiness exists. No event URL rewriting and no upload host change.
- [ ] Run relevant package/app tests, coverage gates and analysis; rebase onto current origin/main before publishing; document setup and commit. Report exact commands and RED/GREEN evidence.

### Task 4: Isolated host setup, end-to-end proof and delivery

**Files:** Operator runbook/configuration tooling as needed; no secrets or production-account snapshots in git.
**Consumes:** Reviewed Tasks 1-3 and existing approved secret runners/provider accounts.
**Produces:** Reviewable PRs plus an honest live-readiness report; a functioning isolated test host if credentials and provider access permit activation.

- [ ] Inspect available provider access and existing zone/bucket/DNS state using redacted read-only tooling. Verify live settings by names and metadata, never print secret values. Read required deployment/rollback runbooks before any relevant action.
- [ ] Prepare an isolated Bunny zone with prefix-scoped origin reads, exact public HLS/MP4 allowlist, no stale/error caching, bounded cache window, private client cache headers, custom hostname TLS and both-host purge coverage. Use current official Bunny docs for configuration semantics. Do not change canonical DNS or global rollout.
- [ ] Run the owned-fixture publication, full-tree byte/Range parity, cache-fill/revocation, purge failure/retry and rollback drills when the isolated provider resources and reviewed backend are available. Do not present local proofs as live acceptance.
- [ ] Obtain task and whole-branch independent review, resolve real findings, commit/push own branches and open conventional-title PRs against main with the shared API contract and explicit validation/activation state.
- [ ] Request mapped review teams once; wait for required/relevant CI and inspect actual outcomes. Return PR URLs, test-host state, how to enable the mobile flag, and any exact provider/activation blocker. Do not merge or enable production cohorts without authority.
