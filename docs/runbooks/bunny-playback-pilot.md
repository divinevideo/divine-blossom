# Bunny playback pilot

The pilot serves approved progressive MP4s on `media-bunny.divine.video`.
Blossom keeps the canonical media paths, publishing flow, and viewer access
rules. Applying an age gate removes the Bunny delivery copy and evicts the
edge caches. Authorized age-gated playback uses the canonical endpoint. Use
owned synthetic fixtures to validate revocation before admitting real clips
or enabling the internal mobile flag.

## Configure the origin and edge

1. Verify the existing `b2_media_bucket` is private and matches the exact name,
   ID, and S3 region used by Blossom delivery and native erasure. The new Bunny
   origin uses `bunny-delivery/` in the same bucket. The two public path shapes
   are `/<lowercase-sha256>` and `/<lowercase-sha256>/720p.mp4`. They map to the
   same paths below `bunny-delivery/`.
2. Provision the Bunny signing key with only `readFiles`, restricted to the
   single bucket and exact `bunny-delivery/` prefix. Give the publisher a separate
   key with only `writeFiles` in that prefix. Blossom uses its existing B2 media
   read credentials to verify publication with a GET. Native erasure uses the
   existing separately scoped credential. Check the actual capabilities and
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
   for the two exact paths. Deny root and bucket listing, query strings, other
   methods, authorization and cookie headers, escaped or normalized alternate
   paths, and unrecognized hosts. Bunny patterns use Lua syntax. For a
   64-character hash match, repeat `[0-9a-f]` 64 times between the path anchors.
   Use separate allow patterns for the original and rendition. Validate actual
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

- Wire the `bunny_api` Fastly backend to the Bunny Core API and inject
  `bunny_api_key`, `bunny_b2_publish_key_id`, and `bunny_b2_publish_key` using
  the approved secret runner. The publisher requires the existing
  `kv_origin_read_token` and `metadata_kv_store_id` for its authoritative
  policy checks and the existing B2 media credentials with GET access. Keep
  secret values out of command arguments, shell history, and output.
  Prove that the native erasure binding lists and deletes versions in the
  delivery prefix and that targeted purges work on each hostname before
  publishing any real paths.
- Set `bunny_pilot_zone_hosts` to the exact custom hostname followed by the
  assigned Bunny hostname, comma-separated. Keep the complete target set,
  active bindings, credentials, and the monitored
  `/admin/api/b2-cdn-purge/drain?max=1` runner through any rollback. Prove the drain
  can evict from both hostnames with the publisher disabled.
  The first write retains this target set in Blossom KV. A replacement zone
  needs a coordinated retirement of the previous zone and its cache entries.
- Verify `b2_replica_enabled` is `true` for the existing bucket. Enable
  `bunny_pilot_publish_enabled` for the fixture pass only. Use the
  authenticated `POST /admin/api/bunny-pilot/publish` request with `path` and
  `sha256`. The hash in `path` identifies the parent blob. `sha256` is the
  lowercase SHA-256 of the exact selected bytes and differs from the parent
  hash for a rendition. The pilot accepts files up to 16 MiB. Verify the
  publisher's returned success for each path before adding it to the app test
  allowlist. Enrollment is manual. Before repairing a 720p rendition under the
  same parent hash, remove that clip from the pilot and verify eviction of the
  old replica. Re-enroll explicitly with the rebuilt rendition digest.
- An interrupted or inconclusive PUT can retain the parent copy gate. Pause
  publication and keep the affected copy out of service. Reconcile the write
  with Backblaze before operator recovery. Require evidence that no PUT can
  still finish, then verify all-version removal and checked eviction before
  clearing a blocked gate. Keep the drain runner available during recovery.
- Seed only currently approved, public (`Active`) paths. Test owned fixtures
  that are Pending, age-gated, restricted, quarantined, and erased. Confirm
  they cannot enroll or serve from Bunny. Confirm age gating and authorized
  viewer playback through the canonical endpoint. The app never sends viewer
  credentials to Bunny. Confirm the exact installed flag and approved path
  list on each QA device. Leave the flag off for all other devices.

For appealable moderation, use status changes or a review hold. Moderation
removes every version of the Bunny delivery copies and evicts their cached
responses. Canonical bytes remain available for moderator review and for
restoration after approval. To resume Bunny playback after an appeal, drain
the eviction, reapprove the clip, then verify and republish its pilot paths.
Retries consult the current policy so an old moderation intent cannot remove
a copy that has already been restored under a successful appeal.
Reserve creator deletion and account vanish for their existing erasure flows.

An interrupted publisher can leave a `bunny-pilot-` copy attempt on the
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

Turn off the device flag and verify canonical source selection. Turn off
publication when enrollment is complete or needs to pause. If any revocation
check fails, disable the zone and verify both public names deny delivery.
Keep the retained purge configuration and drain active until the copies,
cached entries, and pending fills are reconciled. Re-enable only after owned
fixtures pass the revocation drill again.
