# Bunny playback pilot

The pilot serves approved MP4s and complete two-rendition HLS VOD families on `media-bunny.divine.video`.
Blossom keeps the canonical media paths, publishing flow, and viewer access
rules. Applying an age gate removes the Bunny delivery copy and evicts the
edge caches. Authorized age-gated playback uses the canonical endpoint. Use
owned synthetic fixtures to validate revocation before admitting real clips
or enabling the internal mobile flag.

## Configure the origin and edge

1. Verify the existing `b2_media_bucket` is private and matches the exact name,
   ID, and S3 region used by Blossom delivery and native erasure. The new Bunny
   origin uses `bunny-delivery/` in the same bucket. All public paths map to the same path below `bunny-delivery/`. Allow only a
   lowercase SHA-256 original, its `720p.mp4` and `480p.mp4` children, and
   the five HLS children under `/<sha256>/hls/` listed below.
2. Provision the Bunny signing key with only `readFiles`, restricted to the
   single bucket and exact `bunny-delivery/` prefix. Give the publisher a separate
   key with only `writeFiles` in that prefix. The private upload-service worker
   verifies reads with its own read-only bindings. Compute independently checks
   its bucket-scoped native erasure credential. Check the actual capabilities and
   confirm the signing key cannot list objects or read a known fixture outside
   the delivery prefix. [Backblaze application key capabilities](https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys)
3. Create a **Volume** pull zone and set its HTTPS origin to
   `https://s3.<region>.backblazeb2.com/<bucket>/bunny-delivery`. Enable S3
   authentication with the prefix-scoped signing key. Use the Backblaze region
   code from the actual S3 endpoint, for example `us-west-004`. Verify requests at the
   edge land on the intended prefixed key on cold `GET`, `HEAD`, and Range
   requests. Use verified origin TLS. [Backblaze’s Bunny integration](https://www.backblaze.com/docs/cloud-storage-integrate-bunnynet-with-backblaze-b2)
4. Apply the allowlist on both the custom hostname and the assigned
   `b-cdn.net` hostname before cache lookup. Allow anonymous `GET` and `HEAD`
   for the exact published paths. Serve the informational landing page on exact
   root GET and HEAD by routing that one URL to `https://media.divine.video`
   on both hostnames. Reject other root methods and never forward the root
   to the B2 bucket or allow bucket listing. Reject query strings, other
   methods, authorization and cookie headers, escaped or normalized alternate
   paths, and unrecognized hosts. Bunny patterns use Lua syntax. For a
   64-character hash match, repeat `[0-9a-f]` 64 times between the path anchors.
   Use separate anchored allow patterns for each exact suffix. Validate actual
   pattern behavior on warm cache as well as on misses. In particular, a
   versioned S3 GET must never be forwarded. [Bunny Edge Rules patterns](https://bunny.net/docs/cdn/edge-rules/pattern-matching)
5. Set a five-minute CDN cache TTL and `Cache-Control: private, no-store` on
   responses. Enable Cache Slicing for uncached Range support. Disable stale
   delivery on every error class, error caching, Perma-Cache, origin shield,
   redirect following, and byte-transforming optimizations. Set a bandwidth cap
   for the approved fixture run and preserve log IP anonymization. Inspect the
   deployed behavior because settings can affect caching and headers in
   different execution phases. [Bunny CDN FAQ](https://bunny.net/faq/) · [Bunny CDN logging](https://bunny.net/docs/cdn/logging)
6. Bind `media-bunny.divine.video` to the zone, add an explicit DNS-only CNAME
   with a short TTL, and provision and test TLS. The zone has an independent
   disable control. For outage testing, use a bounded tester-only fault or
   isolated test zone. The live canonical DNS record and Fastly service stay
   in service. [Bunny custom CDN hostname](https://support.bunny.net/hc/en-us/articles/207790279-How-to-set-up-a-custom-CDN-hostname)

## Configure Blossom and enroll fixtures

- Deploy the upload-service revision first. Its existing
  `/delete-blobs/ready` endpoint must advertise `bunny_pilot_worker=verified-v2`.
  Configure Cloud Run with `BUNNY_ORIGINAL_PRIMARY` and `BUNNY_DERIVED_PRIMARY`
  equal to the Compute media and derivative primaries (`b2` or `gcs`).
  Supply the exact `B2_REGION`, `B2_MEDIA_BUCKET`, `B2_BUCKET_ID`, and,
  for a GCS source, `GCS_BUCKET`. The two services reject a scope mismatch.
- Bind the following values using each service's approved secret runner.
  Use private secret bindings, keep values out of shell arguments and logs,
  and preserve existing unrelated standalone bindings.

  | Binding | Service | Contents |
  | --- | --- | --- |
  | `BUNNY_PILOT_READERS_V1` | Upload | JSON `{"b2":{"id":"…","key":"…"},"gcs":{"id":"…","key":"…"}}`. B2 reads canonical and delivery objects. GCS reads canonical objects. Omit `gcs` when both primaries are B2. |
  | `BUNNY_PILOT_WRITER_V1` | Upload | JSON `{"id":"…","key":"…"}`. Restrict the writer to one bucket, the exact delivery prefix and only `writeFiles`. The worker checks native authorization before PUT. |
  | `BUNNY_PILOT_WORKER_TOKEN` and `bunny_pilot_worker_token` | Upload and Compute respectively | Identical dedicated random bearer, at least 32 bytes. Compute sends jobs to the fixed `cloud_run_upload` backend. The worker sends pre-PUT permits to the fixed canonical `https://media.divine.video/admin/api/bunny-pilot/permit` route. Both hops use this dedicated bearer. |
  | `bunny_pilot_cleanup_v1` | Compute | JSON `{"eraser":{"id":"…","key":"…"},"bunny_api_key":"…","fastly_api_token":"…"}`. Existing bucket-scoped native `listFiles` and `deleteFiles` authority and the two targeted purge credentials. |

  The worker hard-codes provider hosts from its configured S3 region and uses
  its own readers and writer. Compute checks the worker's scope and immutable
  evidence, owns parent exclusion, and reads policy at the KV origin with the
  existing `kv_origin_read_token` and `metadata_kv_store_id`. Configure
  the `bunny_api` Fastly backend for the Bunny Core API. The deployed
  `cloud_run_upload` backend uses the companion's run.app authority for TLS and
  SNI, a 120 s first-byte timeout and a 30 s between-bytes timeout. Compute
  sets the same HTTP Host explicitly. The worker admits one job per instance
  and enforces a 45 s operation deadline. After source, dependency, destination
  and writer-scope checks, the worker asks Compute to verify its exact parent,
  attempt and generation at the KV origin, current moderation and original
  size. It issues the PUT only after an affirmative permit. Compute forces pass on jobs, sends no-store on permits,
  and the worker refuses redirects. A lost job reply keeps
  the fence; an acknowledged verified write can hand off to the durable drain.
- Before fixture enrollment, validate and activate the separate outer VCL draft
  using [the outer VCL runbook](outer-vcl.md). Its `compute_origin` backend
  defaults to 15 s first byte and 10 s between bytes. The pass snippet gives
  the two exact bearer-bearing publication/finalization POST routes 120 s
  for startup, worker execution and edge settlement. Compute authenticates
  the caller. Recheck both backend settings during activation.
  Prove version listing, deletion, purge on both hosts and verified publication
  against owned fixtures. Retain worker bindings through rollback until all
  attempts settle. Retain the cleanup bundle, target records and drain through
  verified removal and cache eviction.
- Set `bunny_pilot_zone_hosts` to the exact custom hostname followed by the
  assigned Bunny hostname, comma-separated. Keep the complete target set,
  active bindings, credentials, and the monitored
  `/admin/api/b2-cdn-purge/drain?max=1` runner through any rollback. Prove the drain
  can evict from both hostnames with the publisher disabled.
  The first write retains this target set in Blossom KV. A replacement zone
  needs a coordinated retirement of the previous zone and its cache entries.
  Each attempted publication also retains a per-parent enrollment record before
  sending the PUT. Revocation reads that record at the KV origin and leaves
  unrelated media and its mirror gates alone. Preserve these records on rollback.
  Before activation, inventory shared parent-gate consumers and drain legacy
  delete-based writers as required by `docs/contracts/parent-gate-v1.md`; mirror
  runners must support released sentinels before pilot publishers emit them.
  Discovery of retained targets uses the KV origin even when publication is off.
  An unreadable origin retains revocation work instead of acknowledging eviction;
  canonical Fastly invalidation prefers the standalone `fastly_api_token` when
  it fits the request budget. Keep this binding through rollback. A missing
  or malformed pilot bundle cannot suppress its independent purges.
  If the five secret lookups are already spent, the drain writes a per-parent
  canonical-priority hint. A provider 401/403 on the packed purge credential also
  sets this hint. Its next invocation spends the standalone credential
  on both Fastly rounds, then clears the hint and leaves the original CDN intent
  pending. Expect one extra drain interval for canonical eviction in this case.
  Repair the pilot binding and drain through origin absence and both CDN rounds.
- Verify `b2_replica_enabled` is `true` for the existing bucket. Enable
  `bunny_pilot_publish_enabled` for the fixture pass only. Use the
  authenticated `POST /admin/api/bunny-pilot/publish` request with `path` and
  `sha256`. The hash in `path` identifies the parent blob. `sha256` is the
  lowercase SHA-256 of the exact selected bytes and differs from the parent
  hash for a rendition. The pilot accepts files up to 16 MiB. Verify the
  publisher's returned success for each object. A manifest is limited to
  64 KiB. Publish the two TS files first, their two playlists second, then
  the master. Finalize the entire family before testing production selection.
  Retire a changed rendition, verify removal and both cache evictions, then
  re-enroll the repaired family.
- An interrupted or inconclusive PUT can retain the parent copy gate. Pause
  publication and keep the affected copy out of service. Reconcile the write
  with Backblaze before operator recovery. Require evidence that no PUT can
  still finish, then verify all-version removal and checked eviction before
  clearing a blocked gate. Keep the drain runner available during recovery.
  B2 400, 401, and 403 rejections release the attempt without claiming a write.
  Timeouts, transport failures, and other errors retain exclusion. Publication
  uses the shared gate protocol's 32-hex attempt identifier. The dedicated
  coordination authority can inspect it and release its exact generation using
  the existing parent-gate route only after positively settling every possible
  storage effect. An admin token is not that authority, and a timeout or elapsed
  lease is not settlement. Never delete the gate to recover availability.
- Seed only currently approved, public (`Active`) paths. Test owned fixtures
  that are Pending, age-gated, restricted, quarantined, and erased. Confirm
  they cannot enroll or serve from Bunny. Confirm age gating and authorized
  viewer playback through the canonical endpoint. The app never sends viewer
  credentials to Bunny. Confirm the exact installed flag and approved path
  list on each QA device. Leave the flag off for all other devices.

### Publish and finalize

Canonical source reads use `media_read_primary` for originals and
`derived_media_read_primary` for derivatives. Each defaults to GCS. The
worker reads the configured primary directly. An unavailable input fails verification.
The delivery destination always uses the private B2 prefix. A progressive path
such as `/<parent>/480p.mp4` reads `<parent>/hls/stream_480p.mp4` at the
source. An HLS path uses the same key at both providers.

| HLS filename under `/<parent>/hls/` | Published children |
| --- | --- |
| `stream_720p.ts`, `stream_480p.ts` | None |
| `stream_720p.m3u8` | `stream_720p.ts` |
| `stream_480p.m3u8` | `stream_480p.ts` |
| `master.m3u8` | Both rendition playlists |

A publisher sends one authenticated POST per object. The following example
builds a variant payload from a private inventory. `playlist_sha` pins the
current source bytes and `ts_sha` pins the child's delivery bytes.

```sh
jq -n --arg p "$parent" --arg src "$playlist_sha" --arg ts "$ts_sha" \
  '{path:("/"+$p+"/hls/stream_720p.m3u8"),sha256:$src,
    dependencies:[{path:("/"+$p+"/hls/stream_720p.ts"),sha256:$ts}]}'
```

The response includes `result` (`published` or `already_published`). A
playlist also returns `delivery_sha256` for its normalized relative-URI
representation. Use that value for the master dependency. The leaf and MP4
responses keep their earlier shape. A missing or changed child returns 409.
Unsupported tags, external URI attributes and invalid ranges reject the
manifest. Canonical source bytes keep their original references.

Submit `POST /admin/api/bunny-pilot/finalize` with the same administrator
credential and the JSON shape below. Each inventory row contains exactly
`path`, `source_sha256`, and `delivery_sha256`. The command shows the body
for a verified original-only fixture. For HLS include all five HLS rows and
any verified progressive renditions or original, at most eight rows in total.

```sh
jq -n --arg p "$parent" \
  '{version:1,parent:$p,assets:[{path:("/"+$p),source_sha256:$p,delivery_sha256:$p}]}'
```

A successful finalization returns `{"result":"ready"}`. Under parent
exclusion the authenticated upload-service worker reads and hashes each current source and delivery object,
checks immutable GCS generations or B2 version IDs and revalidates the HLS
closure. Compute validates the returned identities, exact requested pins and policy before recording readiness. The record
binds the source provider, bucket, key and version, destination bucket and
version, prefix, host pair and both digests.

### Select a cohort

The canonical endpoint `GET /api/bunny-playback/<parent>` returns
`version`, `host` and a `paths` array. In an eligible cohort the array
contains the verified original, progressive MP4s and/or HLS master. A
disabled cohort, authenticated request or missing readiness yields an empty
array. A policy denial returns 404. Control-plane errors leave the client on
its canonical route. Responses carry CORS and private no-store headers.

Set `bunny_playback_rollout_percent` to an integer from 0 to 100 (default
0) and `bunny_playback_countries` to comma-separated uppercase two-letter
country codes (default empty). Rollout buckets use the first eight hex digits
of the parent modulo 100. Country selection uses trusted edge geolocation.
On the outer VCL service, provision a **private, write-only** edge dictionary
named `bunny_playback_geo` before validating the VCL draft. Provision its
`hmac_key` item and the Compute secret `bunny_playback_geo_key` with the same
random 64-character hex string through the approved secret runner. Both
layers use the printable string as the HMAC key. Configure
`bunny_playback_compute_host` with the exact lowercase backend authority used
by the outer service when forwarding to Compute. Inspect the actual backend
binding before setting this value. Keep the rollout at zero while applying
the separately reviewed VCL and Compute changes. An empty signing dictionary,
missing verifier secret or invalid proof disables forwarded market selection.

The first client-facing POP replaces caller input and signs the canonical GET
path, host, country and time. The shield preserves that assertion. Compute
checks the HMAC and a 30-second lifetime. Repeat GETs can use a proof for the
same parent within that window and still recheck current policy. Direct
requests on the canonical authority use the SDK's downstream IP geolocation.
The shared signing key only authenticates the market for rollout. See the
[outer VCL runbook](outer-vcl.md) and [Fastly service chaining documentation](https://www.fastly.com/documentation/guides/getting-started/services/service-chaining/).

Monitor actual selection and both CDN hostnames with owned fixtures before
enabling a market. Verify the default-off app production flag, publisher
flag and server cohort independently.

For appealable moderation, use status changes or a review hold. Moderation
removes every version of the Bunny delivery copies and evicts their cached
responses. Canonical bytes remain available for moderator review and for
restoration after approval. To resume Bunny playback after an appeal, drain
the eviction, reapprove the clip, then verify and republish its pilot paths.
Retries consult the current policy so an old moderation intent cannot remove
a copy that has already been restored under a successful appeal.
Reserve creator deletion and account vanish for their existing erasure flows.

An interrupted publisher can leave a 32-hex copy attempt on an enrolled
parent hash. Pause enrollment and disable the pull zone if a revocation is
waiting on that attempt. Establish the storage outcome and confirm that the
original PUT has finished before settling the exact recorded gate generation.
Resume only after the outstanding purge has drained and both hostnames deny
the revoked paths.

## Verify before exposing real clips

The local loopback regression exercises an age-gate transition, version
removal, both Bunny hostnames, canonical Fastly eviction, and durable retry.
It uses synthetic credentials and a temporary local KV store. Set `VICEROY`
if the executable is outside `PATH`.

```sh
python3 scripts/run-bunny-pilot-revocation-tests.py
python3 scripts/run-bunny-pilot-publication-tests.py
```

Supply private text files with one exact fixture path per line. Keep retired
fixtures separately and include the original and 720p paths when both existed.
Run a one-shot parity check against the custom hostname and the assigned Bunny
alias:

```sh
python3 scripts/probe_bunny_delivery.py \
  --ready-file "$BUNNY_READY_PATHS_FILE" \
  --denied-file "$BUNNY_RETIRED_PATHS_FILE" \
  --alias "$BUNNY_ZONE_ALIAS" --region us-home
```

Inspect the first response cache status to confirm a fresh fixture started
cold, and require a subsequent hit. Use a separately cold fixture for Range
as the first request to confirm uncached byte serving. The probe compares full
bodies against canonical, verifies original SHA-256, checks HEAD and ranges,
and checks for client `no-store`. Retired checks require `401`, `403`, or `404`
on HEAD, full GET, and Range GET. Treat redirects, outages, and probe errors as
failed checks. Output uses fixture indices and excludes response bodies and
fixture paths. For continuous denial monitoring, omit `--ready-file` and add
`--interval 60` under a runner that alerts on nonzero exit.

Revoke an owned test clip after warming its variants on both hostnames. Repeat
while a cold request is waiting for origin headers and while another is still
reading the origin body. Use a controlled owned origin to hold the fill and
verify the same cache policy on the production-shaped zone. Release the held
fills after revocation and repeat probes across multiple Bunny locations
through the full cache window. A purge receipt is provider acknowledgement.
Fresh probes on both names must establish that no late refill serves bytes.
For physical erasure, independently confirm no replica versions remain before
accepting the completion result. Inject a failed purge and confirm the intent
is retained, alerted, and successfully retried by the drain. Keep real clips
out of the zone until these tests pass.

Run first-frame and clip-gap measurements with the same clip, rendition, and
native player on iOS and Android, first over U.S. home and mobile connections.
Record cold and warm runs, failure and fallback counts, and the selected source.
Test an isolated canonical-host reachability failure, a Bunny timeout or 503,
and terminal 401/403/404. Confirm an app flag rollback restores canonical
selection including prefetched entries. Use Tokyo and London as the next
measurements. Keep Australia and New Zealand on Fastly for the pilot.

For HTTP timing, use `scripts/probe_cdn_delivery.py` on the same verified paths,
with `--warmup 0` for the first request and repeated warmed samples. Keep its
raw sample output private because it includes paths. Compare Bunny billing and
bytes against equivalent Fastly playback, including range traffic and fallbacks.
Include B2 backfill and storage costs and existing Fastly commitments. Record
cost per delivered GB, playback success, first-frame and gap percentiles,
and hit/miss mix per market and rendition. Bunny request logs include HTTP
response headers in bytes sent, so use comparable denominators when comparing
providers. [Bunny CDN logging](https://bunny.net/docs/cdn/logging)

## Roll back

Set `bunny_playback_rollout_percent` to 0 and turn off the device flag. Verify canonical source selection. Turn off
publication when enrollment is complete or needs to pause. If any revocation
check fails, disable the zone and verify both public names deny delivery.
Keep the retained purge configuration and drain active until the copies,
cached entries, and pending fills are reconciled. Re-enable only after owned
fixtures pass the revocation drill again.
