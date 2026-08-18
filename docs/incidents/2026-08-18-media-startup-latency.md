# ABOUTME: Investigation log for the 2026-08-18 video startup stall reports on /HASH/720p.mp4.
# ABOUTME: Records what was verified against live Fastly config, what was ruled out, and what is still unknown.

# Media startup latency — investigation log (2026-08-18)

**Status: primary cause identified 2026-08-18. See section 0. Secondary
structural cause identified and NOT yet fixed.** Second session same day:
the section 8 hypothesis is falsified (12.1) and every server-side change in
the incident window is now exonerated or proven dormant (12.2–12.4).

This is a working log, not a conclusion. It exists so the next person does not
repeat the checks already done. Every claim below is labelled as **measured**
(read from live config or the repo) or **inferred** (reasoning, not yet tested).

Written during an in-progress support call with Fastly, so the "asks" section is
phrased for handing to their engineers.

---

## 0. Findings (added after the sections below were written)

The sections below record the investigation in the order it happened, including
hypotheses later withdrawn. This section is the current conclusion.

### 0.1 CI purged the entire edge cache on every deploy — FIXED

`.github/workflows/ci.yml` ran `fastly purge --all` unconditionally on every
push to `main`. That invalidates a 365-day edge TTL across the whole catalogue,
and a refill takes days.

**Measured:** 12 Compute deploys in the 7 days to 2026-08-18 — so 12 full cache
purges in a week. Byte offload never exceeded 13% on any day in that week,
against the ~25% `vcl/miss.vcl` was introduced to achieve. Daily request hit
ratio oscillated 45%-69% with a visible dip-and-recover after the 08-11 deploy.

The cache was structurally prevented from ever getting hot.

Fixed: the purge step now requires `[purge-cache]` in the commit message.
Targeted `Surrogate-Key` purges remain available and are preferred — Compute
already sets the hash as the key on every cacheable response.

### 0.2 Authenticated requests bypass cache entirely — NOT FIXED

`vcl/recv.vcl` returns `pass` for any request carrying an `Authorization`
header, and that check runs **before** the hash-path lookup. SHA-256-addressed,
immutable, public video is therefore uncacheable for any authenticated client.

**Measured**, outer VCL service, over the week:

| | 08-11 | 08-17 |
|---|---:|---:|
| pass share of requests | 31% | 48% |
| pass share of delivered bytes | 36% | 64% |

The climb is consistent with a mobile release rollout progressively sending
`Authorization` on media GETs. By 08-17, roughly two thirds of delivered bytes
never touched cache.

The justification in the VCL comment ("restricted content needs auth check") is
redundant: Compute already marks restricted content `private, no-store`
(`src/main.rs:689`) and `requires_private_cache()` drives
`add_private_cache_headers` at seven call sites. The origin already tells the
edge what must not be cached.

**Do not fix this in recv.vcl alone.** `vcl/fetch.vcl` sets `beresp.ttl = 365d`
for any 200/206 unconditionally; it defers to origin `Cache-Control` only when
setting the response *header*, not the TTL. Removing the `Authorization` pass
without also making the TTL honour `private`/`no-store` would cache restricted
content at the edge for a year and serve it to unauthorised clients. Both files
must change together, with tests.

**Refinement from section 12.7 (measured):** the client does not send
`Authorization` on media GETs generally — only as a 401 retry on gated
content, and the prefetcher sends none at all. The bypass climb is therefore
not "the app progressively authenticating everything"; it is gated plays
growing *while* the 08-11 V15 change removed edge caching for them. The two
mechanisms multiplied.

### 0.3 The 2026-08-17 22:00 UTC step change — cause not confirmed

Hit ratio and 503 rate both broke sharply at 22:00 UTC and were still degraded
at the last data point. Diurnal explanation is **refuted** by a control against
the same hours on the previous night.

| hour (UTC) | control 08-16/17 hit% | incident 08-17/18 hit% | control 503% | incident 503% |
|---|---:|---:|---:|---:|
| 20:00 | 58.0% | 67.1% | 0.163% | 0.052% |
| 21:00 | 64.6% | 67.1% | 0.040% | 0.056% |
| 22:00 | 62.4% | **56.8%** | 0.033% | **0.204%** |
| 23:00 | 66.5% | **49.6%** | 0.040% | **0.237%** |
| 00:00 | 63.2% | **50.6%** | 0.079% | **0.403%** |
| 01:00 | 62.1% | **52.4%** | 0.070% | **0.342%** |
| 02:00 | 64.1% | **51.0%** | 0.130% | **0.382%** |

Control overnight hit ratio never fell below 58%; incident night never rose
above 57%. All 5xx were **503** — the outer VCL's synthetic backend-unreachable
response, not Compute 500s.

Best explanation is a **manual** `fastly purge --all` around 21:00-22:00. Note a
manual purge creates no service version, so it leaves no trace in version
history — consistent with `blossom_config` being hand-mutated at 21:02:12 in the
same window. **Unconfirmed**; needs Fastly's audit log (section 9, ask 1).

### 0.4 Withdrawn hypotheses

- **Regional/APAC shielding.** Contradicted by delivery having worked well from
  NZ before, and by the 08-07 NZ baseline. Geography is a constant, not the change.
- **The purge alone explains everything.** It explains the step change in
  *request* hit ratio. It does **not** explain byte offload sitting at 1-13% for
  the entire week, which is structural (0.1 and 0.2).
- **PR #200 diagnostics going live on the request path.** Falsified by a second
  session — neither log endpoint exists on either service under any provider
  type. See sections 8 and 12.1.

---

## 1. What was handed to me

A triage report on intermittent video startup stalls and playback stumbling,
Divine Mobile 1.0.20+848 on iOS, incident window 2026-08-18 ~12:31 device-local
(NZST) = ~00:31 UTC. Private evidence is a device log outside this repo; account
identifiers, media hashes and exact URLs were deliberately omitted from it and
are omitted here.

Its headline numbers, all client-side:

- 27 completed prefetches: min 0.198s, median 2.447s, mean 2.585s, p90 3.677s, max 6.077s
- Immediately pre-incident completions of ~5.07s, ~4.97s, ~6.08s
- Two 720p prefetches cancelled at exactly 8.001s / 8.002s
- Active-player "source ready" delays of 0.98 / 3.68 / 3.75 / 1.19 / 3.49 / 2.75 / 6.18s

Its two conclusions were: (a) a confirmed Divine Mobile bug where an 8s
wall-clock deadline is mislabelled as a "stall" and cancels healthy in-progress
downloads, and (b) probable intermittent cold-path latency through
Fastly -> Compute -> GCS that cannot be attributed because slow *successful*
200/206 responses are not recorded anywhere.

**Provenance caveat that matters:** every one of those latency numbers came from
a single device in Christchurch, New Zealand. There is no US client evidence in
the report at all.

---

## 2. Corrections from Rabble during the session

These reframe the problem and invalidate parts of my own earlier reasoning:

1. **Most users are in the US, and an upcoming marketing campaign targets the
   US.** The NZ device is not a representative sample of production traffic.
2. **Delivery worked well from New Zealand until the latest mobile app release
   and service updates in the last day.** Therefore geography/RTT is a
   *constant*, not the change. Any hypothesis resting on trans-Pacific distance
   is wrong by construction.

I initially proposed regional/APAC shielding as a likely factor. **That was a
dead end and is withdrawn.** It contradicts correction 2.

---

## 3. Independent support for "NZ was fine before"

**Measured**, from `docs/measurements/2026-08-07-nz-wellington.md` (2026-08-07,
11 days before the incident):

| Edge | Serving PoP | p50 TTFB | p95 TTFB | Throughput | Errors |
|---|---|---:|---:|---:|---:|
| Fastly | `CHC` Christchurch, NZ | 42 ms | 50 ms | 273 Mbps | 0/45 |

45 measured fetches, real production blobs including a 1.4 MB 720p rendition.

**Caveat, and it is a large one:** that run warmed the cache first and every
measured response was a verified cache HIT. It establishes that **steady-state
NZ delivery was excellent**, and it rebuts "NZ is inherently slow". It says
**nothing** about cold-fill behaviour, which is the path under suspicion. We
have no cold-fill baseline from any region.

---

## 4. Verified against live Fastly config

All of this is **measured** via the Fastly CLI/MCP on 2026-08-18, not read from
the repo. Repo state and deployed state had to be checked separately because
they disagree.

### 4.1 Outer classic VCL service `ML7R82HKfmTaqTpHExIDVN`

- **v15 is active, activated `2026-08-11T08:22:38Z`. It is the newest version
  that exists** — there is nothing above it. Confirms the deployment drift the
  handoff suspected.
- `beresp.do_stream = true` **is present and live** in the `fetch` snippet
  ("Override backend cache headers", `qFBT5RfdLDRnIY5xKdk8V6`).
- The `vcl_miss` Range-strip snippet ("Cache full objects for range requests",
  `0yNLGmOZcBWHEi0owDoba2`) has **`CreatedAt: 2026-07-29T09:46:02Z`**.
  `unset bereq.http.Range` therefore predates the incident by ~3 weeks. It was
  only *recorded into git* on 08-11; the git date is misleading.
  **Do not let anyone chase this as a recent change.**
- The live `recv` / `deliver` / `error` snippets contain **none** of PR #200's
  diagnostics additions. No request-ID plumbing, no 5xx logging. Drift confirmed
  by direct inspection, not inferred.
- Backend `compute_origin`: shield `iad-va-us`, connect 1000ms, first-byte
  15000ms, between-bytes 10000ms.

### 4.2 Compute service `pOvEEWykEbpnylqst1KTrR`

- **v338 active since `2026-08-17T08:12:01Z`.** Comment `deploy from 63de4ff`
  (a docs-only commit — but a Compute deploy rebuilds the whole tree, so v338
  carries everything beneath it).
- **12 deploys in the last week**, with auto-generated `deploy from <sha>`
  comments. The outer VCL service has 15 versions *in total, ever*.
- **This answers "why was Compute deployed but not the VCL":** the two services
  have no coupled deploy path. Compute deploys are automated per-commit; the
  outer VCL is hand-managed. It is not a one-off oversight, it is structural.
- Backends `gcs_storage` and `fos_storage` both have **no shield** — Compute to
  storage is direct. `gcs_storage` first-byte timeout is 15000ms.

### 4.3 Config store `blossom_config` (`eiGxcbPYmkaCvCZyCtTVD3`)

- **`fos_read_enabled = true`** and **`fos_write_back_enabled = true`**, both set
  `2026-08-11T05:13:5xZ`. Bucket `divine-media-delivery`, host
  `us-east.object.fastlystorage.app`, region `us-east`.
  This is a real in-window change **invisible to git history** — but it is a week
  old, so it does not fit "worked until the last day".
- **UNEXPLAINED: the store's `updated_at` is `2026-08-17T21:02:12Z`** — roughly
  3.5 hours before the incident — **but no surviving entry carries that
  timestamp** (newest entry is 08-11). Since an edit would bump the entry's own
  `updated_at`, this was almost certainly a **deletion**.
- **Config stores are not versioned.** They are the only thing on this service
  that can change without a new service version. That makes this the sole
  post-deploy mutation in the window.
- I could not identify the deleted key. Deleted entries do not appear in the
  listing. My one candidate, `gcs_project_id` (present in the staging store,
  absent from prod), was **ruled out**: `grep` finds no code reading it.

---

## 5. New finding: a real regression, but NOT this incident

`src/storage.rs` -> `download_blob_read_through` -> `write_back_if_eligible`
calls `buffer_body_up_to`, which **fully buffers the response body in Compute
memory before any byte is returned to the client**.

The eligibility gate is `had_range` (`blossom-core/src/read_through.rs:90`) — but
the outer VCL **strips Range on cache miss**, so a cold fill arrives at Compute
with no Range. `had_range` is false, and every <=32MiB blob becomes eligible.
Compute emits nothing until the whole object has landed, which **defeats the
outer `do_stream` for that route**. The streaming fix and this buffering landed
the same day, 2026-08-11.

**However — this does not explain the reported incident.** Call-site check:
`/HASH/720p.mp4` (`src/main.rs:2436`) uses `download_hls_content`, **not**
`download_blob_read_through`. The handoff's claim that FOS read-through does not
cover derivatives holds up. This regression is on the **bare blob route only**.

**Sizing it honestly (inferred, not measured):** p99 blob is ~3.4 MB and the
ceiling is 32 MiB, so the added buffer wait is likely sub-second for typical
traffic and approaches ~a second only at the largest objects. Real, geography-
independent, worth fixing, **not a 6-second smoking gun**.

---

## 6. Ruled out

- **Permanently broken media.** The handoff re-tested seven exact 720p URLs: all
  currently return 206, correct `Content-Range`, correct `Content-Length`,
  `video/mp4`, `Accept-Ranges`. The two objects that blew the 8s client deadline
  now serve warm at ~19-20 MB/s, ~0.12s.
- **`do_stream` missing from production.** It is live on v15. Measured.
- **The `vcl_miss` Range strip as a recent change.** Live since 2026-07-29. Measured.
- **`gcs_project_id` as the deleted config key.** No code reads it. Measured.
- **FOS read-through as the cause of 720p latency.** Wrong route. Measured by call site.
- **Trans-Pacific distance / APAC shielding.** Contradicted by Rabble's correction
  2 and by the 08-07 NZ baseline.

---

## 7. Could NOT determine

- **Which config key was deleted at `2026-08-17T21:02:12Z`, or by whom.** The
  Fastly CLI exposes no event/audit command. This needs Fastly's audit log.
- ~~Whether the log endpoints `compute-diagnostics` and
  `vcl-error-diagnostics` exist on the service.~~ **Resolved 2026-08-18: they
  do not exist, on either service, under any provider type** (section 12.1).
- **Any server-side timing for the incident.** Slow *successful* 200/206
  responses are not recorded anywhere (`src/request_log.rs:24` returns early
  unless the request is a persisted failure), and the request-ID correlation
  from #200 is not deployed on the outer VCL service. This is the core
  observability gap and it blocks attribution.
- **Cold-fill performance from any region, including the US.** Never measured.
  The 08-07 baseline is warm-cache only.
- **Whether US users are affected at all.** No US client evidence exists.

---

## 8. Leading hypothesis — FALSIFIED 2026-08-18

**Falsified, see section 12.1: neither endpoint exists on either service under
any provider type, current or legacy. The diagnostics shipped dormant and are
still dormant.** Original text kept for the record:

PR #200 (`7330f36`, "persistent Fastly diagnostics") shipped as Compute v337 at
`2026-08-16T17:01` and is carried in v338. It added
`fastly::log::set_panic_endpoint("compute-diagnostics")` at `src/main.rs:93`
plus per-request diagnostics.

`docs/runbooks/fastly-5xx.md:36` is explicit that **neither endpoint is created
by repository code**, and that Compute logging **fails open while the endpoint is
absent**. So the code shipped in a dormant state and becomes live the moment
someone creates those endpoints by hand.

**Hypothesis:** if a diagnostics log endpoint was created recently — plausibly
the unexplained config-store-adjacent activity on 08-17 — that flips diagnostics
from a no-op into work on the request path, which would slow requests
service-wide, independent of geography, matching "worked great until the last
day".

**This is unverified.** Next step is simply to check whether those endpoints
exist and when they were created. Note the tension to resolve: creating a
logging endpoint normally requires a new service version, and there is no v339 —
so if they exist, they were created no later than v338's clone at
`2026-08-17T08:11:56Z`.

---

## 9. Asks for Fastly

1. Audit/event log for the account on **2026-08-17**, specifically config store
   `blossom_config` (`eiGxcbPYmkaCvCZyCtTVD3`) around **21:02:12 UTC**. We can
   see the store's `updated_at` moved but no surviving entry matches, so we
   believe a key was deleted. We need the key name and the actor. The CLI has no
   event command, so this cannot be self-served. From a code cross-check
   (section 12.4), the candidate set is small: `local_mode`,
   `google_allowed_domain`, `google_client_id`, `github_allowed_org`, or a key
   no deployed code reads. It is **not** any key the delivery path reads —
   those are all still present.
2. On service `ML7R82HKfmTaqTpHExIDVN` v15, backend `compute_origin` shields to
   `iad-va-us` and `vcl_fetch` sets `beresp.do_stream = true`. Does that take
   effect at the **shield node**, or only the edge node? Does the shield buffer
   the full object into cache before the edge begins receiving bytes?
3. With request collapsing: a second request arrives for the same object while a
   `do_stream` fill is in flight. Does it stream from that fill, or wait for the
   fill to complete before first byte?
4. Cold-fill first-byte timings from **US edge POPs** over the last week — the
   distribution, not a single trace. A US campaign is about to run through this
   and the cold path has never been measured from the US.
5. Under a spike where many clients hit the same cold objects at once, does
   shield request collapsing hold, or is there a concurrency limit to know about
   before driving campaign traffic at it?

---

## 10. Next steps, in priority order

1. ~~Check whether `compute-diagnostics` / `vcl-error-diagnostics` log
   endpoints exist and when they were created.~~ **Done 2026-08-18: neither
   exists; section 8 falsified (12.1).**
2. Get the audit log answer for the 21:02 deletion. Candidate key set now
   bounded (12.4); blast radius is off the delivery path regardless.
3. Build the cold/warm probe harness (approved) and point it at **US POPs** as
   well as CHC, using a synthetic non-user object. Never broadly purge user
   content. Establishes the cold-fill baseline nobody has. **Now the critical
   path:** with the server-side window exonerated, this is the only instrument
   that can separate "cold path got slower" from "cold path was always like
   this" (12.6).
4. Add sampled slow-success telemetry for the `quality_variant` route so slow
   200/206s stop being invisible. Privacy rules from the handoff apply: no
   hashes, URLs, pubkeys, auth headers, IPs, or account identifiers.
5. Deploy the drifted outer VCL so one sanitized request ID survives
   edge -> shield -> Compute. Separately from any behavioural cache change.
6. Fix the blob-route buffering regression in section 5 (independent of this
   incident).

**Do not** change Range forwarding in the Compute handler — authenticated and
restricted traffic bypasses the outer cache and depends on correct origin Range
forwarding. **Do not** blanket-preserve Range on public cache miss — that
restores uncached origin reads for every seek and replay.

---

## 11. Divine Mobile side (not this repo)

The handoff's confirmed client bug, recorded here only so it is not lost:
`mobile/packages/infinite_video_feed/lib/src/services/disk_prefetcher.dart:214`
applies `op.result.timeout(_stallTimeout)` with an 8s value. Despite comments
describing an idle/progress detector, it is a **wall-clock deadline for the
entire download** — a healthy, still-progressing download is cancelled at 8s and
logged as a "stall". It predates 2026-08-18, so it is not the regression, but it
converts moderate latency into visible playback failure.

Rabble also reports the latest mobile app release as a suspect in its own right.
That is being investigated separately and is not covered by this log.

---

## 12. Second-session measurements (2026-08-18)

Follow-up on section 8 and the config-store deletion. Endpoint and config data
is **measured** against the live services on 2026-08-18; code-path claims are
**measured** by reading the deployed commit `63de4ff`.

### 12.1 Log endpoints: the section 8 hypothesis is falsified

Scanned every Fastly logging endpoint type on the active versions of both
services (Compute v338, outer VCL v15): all 27 provider types the CLI models,
plus the two legacy types the CLI no longer knows (`http`, `logentries`)
queried directly against the API. The only log endpoints that exist anywhere:

- Compute: `edge_upload_logs` (googlepubsub, created `2026-08-13T10:07:18Z`) —
  the #199 upload-route sink. Compute endpoints are code-driven; this one only
  receives writes from the three upload routes.
- Outer VCL: `cdn-view-logs` (googlepubsub, created `2026-04-07`) — the
  response-conditioned view counter the 5xx runbook says not to reuse.

**Neither `compute-diagnostics` nor `vcl-error-diagnostics` exists.** PR #200
shipped dormant and is still dormant; nothing on 08-17 flipped it live. The
tension noted in section 8 (no v339, so any endpoint must predate v338's
clone) never materialized — there is nothing to explain.

### 12.2 PR #200 per-request cost on the success path: ~nil

Read of the deployed code: `main()` (`src/main.rs:88-113`) does
`set_panic_endpoint` (fails open while the endpoint is absent), one `Instant`,
a ≤64-char request-ID sanitize, and a route classify per request;
`request_log::emit` (`src/request_log.rs:24`) returns immediately unless the
final status is 500–599 (`should_persist_compute_diagnostic`,
`blossom-core/src/request_diagnostics.rs:15`). The `eprintln` mirror only runs
for persisted records. No per-request I/O is added to 200/206 responses.
#199's `with_upload_log` wraps exactly three upload routes
(`src/main.rs:168,176,179`) and never runs on media GETs.

### 12.3 Deploy-to-commit map for the incident window

| Version | Commit | Active (UTC) | Content |
|---|---|---|---|
| v335 | `a8c07c4` (#199 upload logging) | 08-15 01:52 → 16:58 | upload routes only |
| v336 | `cec892d` (#204 legacy-media backfill) | 08-15 16:58 → 08-16 17:01 | Python migration script + tests; its `src/storage.rs` diff is **comment-only** |
| v337 | `7330f36` (#200 diagnostics) | 08-16 17:01 → 08-17 08:12 | dormant per 12.1/12.2 |
| v338 | `63de4ff` (#207 docs-only) | since 08-17 08:12 | same runtime code as v337 |

In the ~31h before the incident the only Compute code change that went live
was #200 (dormant). The outer VCL has not changed since v15 on 08-11.

### 12.4 Config-store deletion: blast radius bounded from the code side

Keys the deployed code reads (`grep` over `src/`): `local_mode`, `gcs_bucket`,
`fos_bucket`, `fos_host`, `fos_region`, `fos_read_enabled`,
`fos_write_back_enabled`, `funnelcake_api_url`, `google_allowed_domain`,
`google_client_id`, `github_allowed_org`.

- The prod store holds **every delivery-path key** (`gcs_bucket`, `fos_*`,
  `funnelcake_api_url`) — all present, newest dated 08-11.
- Code-read keys **absent** from prod: `local_mode`, `google_allowed_domain`,
  `google_client_id`, `github_allowed_org` — each is read with a safe default
  or an optional gate, and all are admin/local-mode scope. None is on the
  media GET path.
- A deleted-then-recreated key would carry a post-08-11 `updated_at`; no entry
  does. So the 21:02 event was a true deletion, as suspected.

**Conclusion (inferred):** whatever was deleted at 21:02, it was not a key the
delivery path reads. Candidate set for the audit answer: the four absent
code-read keys above, or a key no deployed code reads (the staging-only
`gcs_project_id` remains ruled out — no code reads it). The audit log is still
needed for the key name and the actor.

### 12.5 Cold-route anatomy, confirmed against the deployed code

`GET /HASH/720p.mp4` on an outer-VCL cache miss costs: auth-header parse +
Nostr signature verification (local CPU, no I/O), one metadata lookup
(`get_blob_metadata`: 5-minute POP-local Simple Cache in front of KV store
`blossom_metadata`), then a SigV4-signed GCS GET with the client Range
forwarded (`download_hls_from_gcs`). Derivatives are never in Compute Simple
Cache (only m3u8 manifests are), so every outer-cache miss reaches GCS. Edge
TTL for derivatives post-#186 remains one year via `Surrogate-Control`
(`blossom-core/src/cache_policy.rs:19-25`), so #186 did not create a re-fetch
storm; cold fills happen for new/purged/long-tail content only.

### 12.6 Where this leaves the incident

Every server-side change in the window is now either dormant (#200),
upload-only (#199), comment-only (#204), docs-only (#207), or a week old
(the 08-11 bundle). The 21:02 deletion cannot touch the delivery path (12.4).
Remaining live explanations, none provable from this repo alone:

1. **Client-side.** The only evidence is one device on the new release, which
   carries the confirmed 8s wall-clock cancel bug; its 0.198s minimum prefetch
   shows the warm path was healthy. Concurrent prefetching on one device
   inflates each download's wall-clock time with no server change at all.
2. **Cold-fill latency that has never been measured.** The probe harness is
   the only instrument that can separate "cold path got slower" from "cold
   path was always like this" — and it must answer from US POPs, not just CHC.
3. **Fastly-side network/POP behaviour in the window** — covered by the
   section 9 asks, which stand.

**Reconciliation with section 0 (written in a parallel session).** 12.6's
conclusion — that no *code* change in the window explains this — holds, and
section 0 agrees with it. The cause found in section 0 is not a code change: it
is a recurring *operation*. CI ran `fastly purge --all` on every deploy, so the
cache was wiped 12 times that week and never filled, and the 22:00 step change
is best explained by a manual purge, which leaves no service version behind.
That is why it is invisible to a deploy-to-commit audit. Both analyses converge
on the same place: nothing that shipped did this, the cache handling did.

Item 2 above still stands and is still the right instrument — but note it now
has a confound to control for. Any cold-path measurement taken before the CI
purge fix lands, or shortly after any purge, is measuring a cache that was
recently emptied, not a steady-state cold path.

### 12.7 What drives the bypass volume: per-response cache policy, not just request auth

**Measured** (v14→v15 fetch-snippet diff from the live API; the recv, miss,
deliver and error snippets are byte-identical across v12–v15). Beyond
`do_stream`, the 08-11 fetch snippet changed one more thing: v14 **forced**
`Cache-Control: public, max-age=31536000, immutable` onto every 200/206,
overriding whatever Compute sent. v15 applies that only as a default when
Compute sent no `Cache-Control`, and otherwise honors Compute's per-response
policy.

**Measured** (code): for statuses where `requires_private_cache()` is true
(`blossom-core/src/types.rs:148`), Compute sends `Cache-Control: private,
no-store` (`add_private_cache_headers`, `src/main.rs:5983`). Until 08-11 the
outer VCL masked that with the uniform public policy; since v15 the header
reaches the edge intact and standard private-response handling keeps the
response out of the shared cache. So **every** authorized play of
privacy-scoped content is a full origin trip, not only the first one. The
fetch snippet also `return(pass)`es 202s and non-2xx errors, so
transcode-polling retries and gate-discovery 401s always reach Compute.

**Measured** (mobile code, `divine-mobile`): the app does not attach
`Authorization` to media GETs up front. Auth headers exist only as a
401 retry for gated content (`mobile/lib/services/media_auth_interceptor.dart`,
`mobile/lib/services/media_viewer_auth_service.dart`), and the feed
prefetcher (`infinite_video_feed/.../disk_prefetcher.dart`, via
`package:media_cache`) never sends auth at all. So the client half of 0.2's
mechanism is not "the app increasingly authenticates all media GETs"; it is
"gated plays grew, and each gated play now always bypasses". (The two halves
are measured; mapping them onto the traffic curve is inferred.)

This sharpens 0.2's fix direction: the knob is not the client and not only
the recv pass rule, but an edge design that can cache privacy-scoped content
safely (cache it, but re-check authorization per request at the edge). Any
change must keep the current guarantee that `private`/`no-store` responses
are never served from a shared cache without a fresh authorization check.

### 12.8 Additional second-session measurements

- **Compute-side latency, incident evening** (measured, Fastly stats): mean
  Compute request time roughly tripled for about two hours on 08-17
  (~20:00–22:00 UTC) against the same hours on 08-14 and 08-16, with
  per-request guest CPU about doubling, then recovered. No deploy happened
  in that window. The 21:02 config-store mutation and the suspected manual
  purge (0.3) both sit inside it; a bulk data job would produce the same
  signature. Unverified — folded into the section 9 audit ask.
- **At the NZ report time (~00:31 UTC 08-18)** (measured): ANZAC aggregate
  miss and bypass timings sat in their normal range with zero 5xx in that
  hour. Nothing was wrong at aggregate level at the moment of the report;
  the device's experience was the tail, not the mean.
- **Fastly public incident history** (measured): no delivery-path event on
  08-17/18. There *was* an Object Storage 429/503/timeout incident at IAD
  and FRA on **08-10** — context for the bare-blob read-through route only;
  `/HASH/720p.mp4` reads GCS directly.
- **Stats blind spot** (measured): historical stats have no per-path or
  per-method dimension, and Domain Inspector / Origin Inspector return empty
  for these services (not enabled). The bypass traffic's exact path mix
  cannot be decomposed from Fastly aggregates — one more reason the sampled
  slow-success telemetry (next step 4) matters.

---

## Appendix: commands used

```
fastly service-version list --service-id ML7R82HKfmTaqTpHExIDVN --json
fastly service-version list --service-id pOvEEWykEbpnylqst1KTrR --json
fastly vcl snippet list --service-id ML7R82HKfmTaqTpHExIDVN --version 15 --json
fastly backend list --service-id ML7R82HKfmTaqTpHExIDVN --version 15 --json
fastly backend list --service-id pOvEEWykEbpnylqst1KTrR --version 338 --json
fastly config-store list --json
fastly config-store-entry list --store-id eiGxcbPYmkaCvCZyCtTVD3 --json
fastly config-store-entry list --store-id 93s9TpdiGoAhDuOrpMqxk5 --json
```

Repo checks: `git log --since=2026-08-11 --name-only`, `git show 7ce2aee -- vcl/`,
`git show b19b7b0`, `git show 7330f36 --stat -- vcl/`, and grep for
`try_download_blob_from_fos` / `download_hls_content` call sites.

Second session additions:

```
# Log endpoint scan (all 27 CLI-modeled types × both services, --version active --json)
fastly logging <type> list --service-id pOvEEWykEbpnylqst1KTrR --version active --json
fastly logging <type> list --service-id ML7R82HKfmTaqTpHExIDVN --version active --json
# Legacy types the CLI no longer models, via direct API:
GET /service/pOvEEWykEbpnylqst1KTrR/version/338/logging/{http,logentries}  -> []
GET /service/ML7R82HKfmTaqTpHExIDVN/version/15/logging/{http,logentries}   -> []
# Deploy-to-commit mapping:
fastly service-version list --service-id pOvEEWykEbpnylqst1KTrR --json
# Config key inventory (field names are item_key / created_at / updated_at):
fastly config-store-entry list --store-id eiGxcbPYmkaCvCZyCtTVD3 --json
fastly config-store-entry list --store-id 93s9TpdiGoAhDuOrpMqxk5 --json
```

Repo checks: `git show cec892d -- src/storage.rs` (comment-only diff),
`git show a8c07c4 --stat`, greps for `get_config(`, `with_upload_log(`,
`request_log::emit`, `should_persist_compute_diagnostic`, and reads of
`src/main.rs:75-130,1269-1340,2400-2470,5974-6018`, `src/request_log.rs`,
`src/metadata.rs:54-120`, `src/auth.rs:40-123`,
`blossom-core/src/cache_policy.rs`, `blossom-core/src/request_diagnostics.rs`.

Note for future operators: `fastly logging <type> list` fails silently into an
empty result if given an invalid `--version` value (e.g. `latest-active` —
valid values are a number, `latest`, `active`, `staged`); a scan that swallows
stderr will report phantom absence. Verify one call by hand first.
`fastly profile list` prints API tokens to stdout; do not run it where output
is captured or shared.

Third block (traffic-shape and cache-policy analysis):

```
# Daily/hourly traffic shape, whole service or per region:
fastly stats historical --service-id ML7R82HKfmTaqTpHExIDVN \
  --from <ISO> --to <ISO> --by day|hour [--region usa|anzac|europe] --json
# (fields used: requests, hits, miss, pass, status_401, miss_time, pass_time,
#  pass_resp_body_bytes, all_status_5xx; Compute service: compute_requests,
#  compute_request_time_ms, compute_execution_time_ms)
fastly stats historical --service-id pOvEEWykEbpnylqst1KTrR --from ... --json
# Snippet content diff across versions (CLI has no content-diff; use the API):
GET /service/ML7R82HKfmTaqTpHExIDVN/version/{12,13,14,15}/snippet/<name>
# Domain ownership of an FQDN (version-scoped domain lists can be misleading):
fastly domain list --fqdn media.divine.video --json
```

Mobile-side reads in `../divine-mobile`: `mobile/lib/services/
media_auth_interceptor.dart`, `mobile/lib/services/media_viewer_auth_service.dart`,
`mobile/packages/infinite_video_feed/lib/src/services/disk_prefetcher.dart`,
and a repo-wide grep showing `packages/media_cache` never sets `Authorization`.

Branch: `wip/media-latency-diagnostics`.
