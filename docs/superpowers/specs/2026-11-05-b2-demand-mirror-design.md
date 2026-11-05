# B2 playback fallback and background migration

## Intent and selected approach

Serve media seamlessly while moving public original videos from GCS to private B2. Keep published event URLs and GCS upload authority. The existing design records the maintainer's selection: immediate GCS playback with deduplicated background copying, while retaining upload synchronization, historical backfill and rollback.

Inline copying delays playback and repeats work for popular clips. Scheduled backfill alone does not prioritize requested videos. Retain the selected background approach; this revision clarifies its delivery, durable handoff and repair contracts. It is a design update, not authorization to deploy, copy production media or switch global traffic.

## Current implementation and change boundaries

Reviewed against this branch at commit 4488048. These are existing building blocks, not completed demand-mirror functionality:

- [src/canary.rs](../../../src/canary.rs) gates the direct test host, reads uncached policy/readiness and rechecks policy after origin I/O. Strict mode returns 503 for missing readiness, copying and transient B2 failures.
- [src/storage.rs](../../../src/storage.rs), `download_canary_original`, pins B2 reads to a verified version, bypasses storage caches and checks the actual read/erasure bucket mapping. It currently collapses B2 404 and 5xx into the same unavailable response; 410 is an error. Demand mode needs distinct outcomes before choosing fallback or repair.
- The general `download_blob`/fallback route can use provider selection, storage caches, FOS and legacy origins. It is **not** the GCS-only fallback boundary required here. Its request builder also starts with GET, so it cannot supply a real HEAD unchanged.
- [scripts/sync_b2_originals.py](../../../scripts/sync_b2_originals.py) owns verified copies, durable SQLite state, upload notifications, historical scanning and the copy/erase mutex. `Worker.process` currently trusts matching local/KV readiness without checking the B2 version still exists. `FastlyKV.delete` is currently unconditional for readiness. Both need changes for safe repair.
- [b2-original-sync.md](../../runbooks/b2-original-sync.md) and [b2-playback-canary.md](../../runbooks/b2-playback-canary.md) define the existing operator contracts. Update both alongside implementation. Brain search corroborated the mirror contract in document 3F9F0B58233176B9345EE9AE94; local code is the source of truth for this revision.

## Scope and activation

Add `b2_demand_mirror_enabled` to the existing Compute configuration, absent or malformed meaning off. It only affects requests already admitted by the exact `b2_canary_host` check on media-b2.divine.video. It cannot enable that hostname, change canonical routing or be activated by forwarding headers. With the new flag off, retain the strict canary contract and its existing tests.

With the flag on, accept the same GET/HEAD paths: /{lowercase-sha256} and /{lowercase-sha256}.mp4. Only approved originals with positive size at or below 67,108,864 bytes are eligible for demand copying. Larger approved originals may use the same uncached GCS-only delivery path, but never create hints or use B2 in this mode. HLS, thumbnails, transcripts, non-video content, uploads and admin routes stay outside this host's accepted routes; their existing canonical GCS paths remain unchanged. This is not a full storage cutover.

The existing per-device app flag selects the direct host. Verify the client still falls back only on the intended availability failures, never on policy denial or configuration/integrity failures. No app retry through the outer VCL cache is required when the direct host successfully serves GCS.

## Delivery contract

### Policy comes first

Use the canary's uncached authoritative policy path for both origins, including the independent quarantine record, blob metadata allowing canonical anonymous access (active or public pending under reactive moderation), valid owner/references, tombstone and owner/reference vanish checks. Missing or malformed policy and failed policy lookups cannot authorize delivery or enqueue. Authenticated callers get no bypass.

Read `b2-sync:v1:{hash}` separately from approval. A valid `copying` marker permits GCS fallback only in demand mode, with no additional hint. `erasing`, malformed markers and failed gate lookups remain terminal: no origin request, fallback or hint. Never expire or steal a gate.

Recheck policy and the gate after each origin attempt, including failed attempts, before any fallback, hint insertion or response commitment. If metadata size/type changed, deny that response. A denial observed after B2 I/O wins over B2 failure and prevents GCS I/O. A denial observed after GCS I/O discards its response and prevents enqueue. This is a check before committing response headers/body, not a claim that bytes already streamed can be recalled or that multiple KV reads form an atomic snapshot.

### Explicit outcome table

The storage boundary must retain typed outcomes until the handler decides what to do. Do not infer a repair from an already-flattened 503.

| Condition after approval/gate checks | Demand-mode response | Hint |
| --- | --- | --- |
| Valid readiness and verified B2 200/206/HEAD | Serve B2 | None |
| Readiness key genuinely absent | Try GCS once | Demand hint after successful GCS 200/206/HEAD |
| Valid copying gate | Try GCS once | None |
| Approved original above size ceiling | Try GCS once | None |
| Pinned B2 version returns 404/410 | Try GCS once | Repair hint with observed version after successful GCS 200/206/HEAD |
| B2 transport availability failure, 429 or 5xx | Try GCS once | None; preserve readiness |
| Readiness malformed or mismatched | 502; no origin/client fallback; aggregate diagnostic | None |
| Readiness lookup unavailable, with policy/gate checks successful | 503; availability fallback allowed at client | None |
| B2 credentials/configuration/erasure mapping invalid; unexpected response; version/size mismatch | Error, normally 502 | None; no GCS fallback |
| Policy denied or erasing/malformed gate | Terminal denial, normally 404 | None |
| Policy/gate read unavailable | 500; no origin/client fallback | None |
| Valid B2 or GCS 416 | 416, empty body and validated Content-Range | None; not an origin miss |

These are demand-mode classifications. In particular, malformed readiness becomes terminal 502 in demand mode even though the existing strict canary returns 503 for it. Preserve flag-off parity, and verify the client treats only 503 as eligible for its canonical fallback.

GCS fallback uses the configured authoritative GCS bucket directly, with an explicit method and storage-cache bypass. It must not invoke the normal multi-origin route, FOS write-back, a redirect to the canonical host, or the global `media_read_primary` decision. GCS 404/410 becomes a missing response; GCS availability failure becomes 503; GCS auth/configuration/integrity failure remains an error. None triggers a second fallback or hint. Never expose origin error bodies.

Bound an execution to one B2 media attempt and at most one GCS media attempt, plus required authorization/policy calls and at most one hint insertion. No inline media copying, retries or unbounded retry loop. Set finite origin deadlines within the request's total budget, leaving time for GCS fallback and final policy checks. Include policy-reference fanout and native B2 authorization in the Compute resource-budget tests. Once response bytes are committed, a body-stream failure terminates that response; do not switch origins midstream.

### HTTP and cache behavior

Both origins use actual HEAD for HEAD, without downloading a full body. Forward the requested Range for GET, preserve 206, validate its total and span against metadata and the requested range, and retain 416 with an empty body. If B2 omits Content-Range on 416, reconstruct bytes */<size> only when the requested valid single range is mathematically unsatisfiable against authoritative size; reject mismatched origin totals and unexpected 416 for satisfiable or malformed requests. Cover open-ended and suffix ranges; document and test one consistent policy for unsupported multiple/malformed ranges. Preserve the strict host's conditional-header behavior; do not introduce provider-specific 304 handling during this change.

Every response on this host, including errors, has `Cache-Control: private, no-store` and `Surrogate-Control: no-store`. Both origin requests bypass backend storage caches. Successful responses set the actual `X-Divine-Source` (`b2` or `gcs`), `X-Divine-Storage-Cache: BYPASS`, current content type, hash/size headers and existing CORS headers. Never label fallback bytes as B2.

The host must bypass outer VCL. Repeated checks bypass this application's metadata cache, but do not establish global linearizability of provider KV. Production acceptance must exercise cross-POP revocation and document observed propagation and in-flight response limits. Any canonical-host activation needs a separate reviewed outer-cache revocation/bypass design and production tests; origin checks alone cannot govern existing shared-cache hits.

## Demand hints and durable handoff

Use the existing Fastly metadata store, without adding playback-path cloud credentials. Reserve one add-only key per full lowercase hash: `b2-demand:v1:{hash}`. Version-1 values contain `version`, `sha256`, `reason` (`missing_readiness` or `missing_version`), and, for repair, `observed_destination_version_id`. Validate key/value hash agreement and bound payload/version length. Do not include caller identity, request headers, signed URLs or arbitrary origin locations. A hint conveys demand, never approval, readiness or proof of absence.

Use at most one add-only insertion after eligible GCS success and the final policy check. An existing key is success for coalescing; never overwrite it on playback. Failure or exhausted enqueue budget leaves playback successful and increments an aggregate counter. Await only bounded KV work supported by the runtime; do not rely on detached work surviving the response. Accepted hints have no TTL and remain until durably handed off. Admission is limited to approved existing originals; observe aggregate store pressure and disable new hint emission with the demand flag if necessary. This bounds per-request work and one outstanding key per eligible hash, not total catalogue cardinality or write attempts across all POPs.

Extend the worker with separately enabled demand intake and a bounded, prefix-filtered KV listing. The handoff is:

1. Read at most the configured page/key/payload limits from `b2-demand:v1:`; read each value with its generation marker. Retain an opaque listing cursor across passes and restart at the end. Repeated scans cover inserts behind the cursor; do not treat listing as a snapshot.
2. Validate the record, then transactionally upsert the hash into the durable local schedule and demand queue. Only the worker's current source/policy reads determine eligibility and source generation. Demand intake does not need those remote checks before committing a request to SQLite.
3. Only after that transaction commits, remove the exact observed hint with a generation-conditional delete. Missing generation, conflict or uncertain deletion must never fall back to unconditional deletion. Redelivery is safe. Invalid records can be counted and conditionally removed without copying; unsupported future schema versions remain for operator diagnosis, with scanning continuing past them.
4. Persist cursor progress only after each page's records have either been durably accepted, safely rejected, or retained for retry. Reset an invalid cursor to a fresh scan without dropping existing work. If the configured pending-demand cap is reached, leave unaccepted hints in KV, report saturation and continue bounded scans/processing.

Extend the existing worker KV allowlist narrowly for listing/reading and conditionally deleting this namespace; no generic metadata-write capability in application code. Fastly's [KV item API](https://www.fastly.com/documentation/reference/api/services/resources/kv-store-item/) supports prefix/cursor listing and generation-preconditioned deletion. Exercise the real adapter against a local HTTP server, including pagination, conflict and missing-generation behavior.

Deduplication covers outstanding work, not a hash's lifetime. After handoff, another play may recreate the hint. SQLite must coalesce it without resetting an existing retry deadline, adding another copy job, or bypassing the 300-second transient retry delay used by upload work. A generic hint may mask a later repair hint in KV; therefore **every due demand item reconciles current remote readiness and the pinned B2 version before using the local ready shortcut**, regardless of the first hint's reason. A completed hash can become due again on later demand. Hints lost before successful insertion are best effort; historical scans and upload notifications remain the recovery sources.

## Safe repair and copy lifecycle

Never invalidate readiness or create a new B2 version solely because playback reported a miss. For a due demand item:

1. Read current authoritative approval, source identity/size, gate and readiness. Honor current rejection or erasure even if the queued hint predates it. Missing source, unsupported size/type and permanent denial finish the demand item without copying; an active review hold or transient lookup failure defers it. Keep the historical reconciliation record. Introduce an explicit eligible/deferred/terminal worker result instead of treating every `approved_metadata(...) is None` identically: public pending status is eligible, while an active quarantine hold defers; banned/deleted/restricted/age-restricted state, tombstone, vanish or erasing ends this demand item; missing/malformed policy and lookup errors defer without authorizing work. Historical reconciliation can reconsider later approval.
2. If readiness is valid, independently probe that exact immutable B2 version with bounded I/O and verify version/size on success. An old observed version must never invalidate a different current record. A generic hint still probes the current record, closing the coalesced-repair gap.
3. Verified existence completes demand without another PUT. Availability, authentication, malformed-response and integrity failures are not evidence of absence: preserve readiness, defer and alert as appropriate. Only an authoritative not-found result for the exact version permits repair.
4. Before clearing stale readiness/local completion, acquire the existing shared copy gate and reread policy, source and readiness. Compare the observed readiness generation/version; if it changed, stop this repair and reconcile the new state. Conditional deletion must prevent a stale observer from deleting newer readiness. Apply generation-aware invalidation to interacting worker paths as well; locking just the new repair helper while existing paths delete unconditionally is insufficient.
5. Durably clear the matching local completion and record pending repair so a crash between remote invalidation and local update cannot lose the repair request. If that crash leaves a copy gate, recovery remains operator-mediated under the existing drain/reconciliation rules; a journal entry is not proof that no PUT could be outstanding. Reuse the verified copy path with the same owned gate, without trying to acquire it again. Source download may be staged before gate acquisition as today, but readiness invalidation, PUT and publication are serialized with erasure. Preserve generation-pinned source reads, complete source SHA-256, immutable upload version ID, complete independent destination checksum and policy checks around publication.

When a demand item lacks local completion but valid remote readiness already exists, verify and adopt that readiness only when its source bucket/generation, size, hash and destination mapping match current worker state. Do not upload merely because the SQLite file was new or a hint was duplicated.

The existing uncertain-PUT rule is unchanged: a crash or uncertain remote write leaves the copying gate in place until an operator conclusively drains/reconciles the writer. Repair is not permission to clear a stuck gate, remove B2 versions, or bypass all-version erasure. No TTL on copying or erasing; all-version removal remains owned by the existing erasure workflow.

## Scheduling, capacity and operations

Demand, upload notifications and history share one copy-object budget, byte budget and spool ceiling. Track intake/control work separately and bound it per invocation. A hash in multiple queues occupies one attempt; acknowledge only the queue identities satisfied by that attempt, preserving a newer upload generation or repair observation.

Use three fair lanes with a persisted rotating first lane and at least one available object slot per nonempty lane when all three are enabled; require at least three slots in that configuration. Reclaim unused slots. Rotate first access to the shared byte budget across invocations as well, so repeated small demand copies cannot indefinitely prevent a large historical copy. Preserve the existing checks that bytes allow upload plus verification of one maximum object and spool can hold it. Avoid partial-file deadlock by completing resumable work before opening more partial files that exhaust spool; test this across lanes.

Demand intake, upload intake and source-listing failures are isolated: alert, retain their work/cursors and continue other already-durable work where its own policy/source checks succeed. The current unguarded source-page lookup must not abort the entire new scheduler. Continue scheduled reconciliation even when no playback occurs. Disabling demand intake leaves queued work durable; an explicit worker pause stops processing without deleting state.

Keep the existing single-writer lock, owner-only state directory and exact source/destination/store identity binding. Add an additive, restart-safe SQLite migration and retain/back up its state. KV hint deletion transfers retry responsibility to this database; rebuilding from GCS alone is not a substitute for restoring it. Implementation must document the periodic runner, cadence, capacity limits, backup/restore procedure and operator ownership before activation; no production schedule exists merely because the script is merged.

Report aggregate source/fallback reasons, hint insertion/error/coalescing counts, intake failures, pending count and oldest age by lane, completed copies/repairs, retries, locked gates, spool usage and reserved transfer bytes. Alert on growing age, saturation, persistent auth/config errors and stuck gates. Do not put hashes, pubkeys, bucket secrets or raw provider exceptions in telemetry. A configured time/byte/object cap is a bound, not evidence of acceptable playback latency or migration throughput: measure both.

## Rollout and rollback

1. Implement and test with the new flag off. Extend the existing strict-canary and worker suites; update both runbooks with the new mode, schema, adapter permissions, scheduling and recovery procedures.
2. Before any copy or activation, verify exact source/destination/read/erasure bucket identity, private B2 state, current scoped v4 runtime credentials, shared-gate deployment and recoverable state. Do not infer live configuration from this branch's files or widen credentials to compensate for preflight failures.
3. With an owned approved synthetic fixture and a bounded worker, prove the full missing-readiness → GCS success → durable queue → independently verified copy → B2 hit sequence through the actual direct Compute hostname. Validate HEAD/ranges, missing-version repair, outage fallback, policy changes during both origin attempts, and physical all-version erasure.
4. Enable only the existing per-device canary cohort after observing fallback latency, resource limits, queue age and cross-POP revocation behavior. A canonical/global switch requires separate approval and the cache design above.

Disable the device flag for normal canonical GCS playback. Turning off `b2_demand_mirror_enabled` restores strict B2-only behavior on the direct host; it does **not** make that host GCS-only. Disable worker demand intake separately if needed, retaining durable queues and backups. Pause the runner explicitly if copies must stop. Keep all-version erasure enabled while any B2 bytes remain, and retain permanent erasing markers. Never use queue cleanup or rollback to clear the copy/erase namespace.

## Acceptance and implementation slices

These are testable delivery slices, not an authorization to start implementation:

1. **Origin outcomes and uncached fallback.** Extend blossom-core/src/canary.rs, src/canary.rs, src/storage.rs and scripts/run-b2-canary-tests.py. Prove flag-off parity, GCS-only bypass despite other storage flags, true HEAD, range/416 behavior, actual source headers, missing versus outage/config classification (including terminal malformed readiness only in demand mode), and revocation before/after each origin. No hint on terminal/error/oversized/copying cases, and no midstream fallback.
2. **Hints and durable intake.** Add the narrow edge/worker adapters and SQLite migration. Prove at most one outstanding KV hint for concurrent requests; commit-before-delete; crash before/after commit and delete; generation conflicts; duplicate re-enqueue preserving backoff; invalid records, pagination restart and saturation. A failed hint write must not change successful playback.
3. **Repair and fair processing.** Extend scripts/sync_b2_originals.py and scripts/tests/test_sync_b2_originals.py. Prove exact-version absence repair, stale hint/new readiness races, generic hints coalescing later repair, existing remote readiness adoption, missing-source and policy rejection, uncertain PUT recovery, copy/erase exclusion and all-version erasure. Sustained demand/upload traffic must leave history progressing under object/byte/spool limits. Listing/intake outages must not abandon committed jobs.
4. **Operator validation.** Update both runbooks and run the bounded synthetic production acceptance only under operator authorization. Record what was observed, what remains untested, and which flags/runner were actually enabled. No visual change.

Implementation validation commands: `cargo test -p blossom-core --locked`, `cargo check --tests --locked`, `./scripts/run-edge-tests.sh` with Viceroy configured, `cargo clippy --locked --all-targets --all-features`, and `python -m unittest scripts.tests.test_sync_b2_originals -v` in the environment with scripts/requirements-b2-sync.txt installed. A documentation review does not establish that these future behaviors pass.

## Decisions left to the implementer

The new flag/key names, outcome distinctions, acknowledgement order, 300-second minimum transient retry delay, size ceiling and no-cache/no-gate-expiry contracts above are review decisions proposed by this revision. They preserve the selected background-copy approach. Module factoring, telemetry names, exact finite intake/pending/time limits and worker CLI spelling remain implementation choices, to be documented and tested before activation. Runtime capacity/cadence must follow measured budget and backlog rather than an invented throughput promise. No global traffic switch is included in implementation approval.
