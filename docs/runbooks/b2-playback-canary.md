# B2 playback canary endpoint

The canary reads verified original videos from private B2 while the canonical
media host keeps its current storage and write behavior. This change enables
no domain and changes no production configuration.

## Activation requirements

Bind media-b2.divine.video **directly to the existing Compute service**, with
working DNS and TLS. It must bypass the outer VCL service: the outer hash-path
cache can return cached bytes without executing Compute policy. Verify the
binding, DNS, certificate, and actual request path before enabling clients.
Do not reuse an outer VCL cache entry or change the main media host.

The blossom_config key b2_canary_host must equal media-b2.divine.video exactly.
Missing configuration disables the reserved host. Conflicting X-Original-Host,
URL authority, or Host values are denied. Forwarding headers cannot activate
the canary.

Before activation, independently inspect actual B2 bucket metadata and confirm
its type is allPrivate; retain sanitized evidence. Never use a public bucket.
The runtime deletion credential intentionally has only listFiles and
deleteFiles, so it cannot inspect privacy through listBuckets. Changing bucket
privacy invalidates activation evidence and requires disabling the canary until
reverified.

Configure the existing B2 origin backend, region, read bucket and read secrets
using the existing storage setup. The existing b2_replica_enabled erasure flag
must be enabled. Every request authenticates the native B2 erasure credential,
requires its existing exact single-bucket ID/capability scope, and verifies its
authenticated bucket name matches b2_media_bucket. A configured assertion alone
cannot enable delivery outside the actual erasure mapping. This adds a native
authorization request per origin read, intentionally uncached for this canary.

## Strict request and readiness contract (default)

Only GET and HEAD of /{lowercase-sha256} or /{lowercase-sha256}.mp4 are accepted.
Thumbnail, HLS, transcript, quality, upload, admin, and all other routes/methods
are denied. Authentication grants no bypass.

Each request reads uncached authoritative Fastly KV metadata and applies the
canonical anonymous access policy. Active and pending blobs are public; pending
does not require upload pre-screening under reactive moderation. The blob must
have a video MIME type and valid owner, have no tombstone, and have no
account vanish in progress for its owner or any uploader reference. Missing or
malformed metadata, failed lookups, and any copy/erase mutex prevent delivery.
Policy is checked again after origin I/O. The canonical metadata cache is never
used.

Readiness lives in blossom_metadata at b2-ready:{hash}:

    {
      "version": 1,
      "sha256": "<64 lowercase hex>",
      "verified_sha256": "<same hash>",
      "bucket": "<configured private read bucket>",
      "key": "<same hash>",
      "size": 123,
      "verified_at": 1,
      "destination_version_id": "<independently verified B2 version ID>"
    }

The worker may add source bucket/generation fields. See
[b2-original-sync.md](b2-original-sync.md) for publication and recovery rules.
Delivery requires matching hash, bucket, key, positive size, timestamp and
version ID. All reads pin that version, verify the returned version and
full/range size headers, and bypass storage caches. HEAD sends a real HEAD to
B2. There is no FOS, GCS, legacy origin, or per-play copy fallback inside Compute.

A policy denial returns 404 without revealing existence. An approved video
without valid readiness or verified origin bytes returns 503, allowing the
client's canonical source. A valid copying intent also returns 503 after
checking public policy; erasing or malformed intent remains a terminal 404.
A restricted video with a copying intent still returns 404. B2 origin transport
failures and HTTP 5xx also return 503 after rechecking policy, allowing canonical
fallback during transient outages. Revocation during origin I/O remains a
terminal 404. B2 auth/config or unexpected origin responses return
an error (normally 502), preventing fallback that hides broken configuration.
Range success preserves 206, Content-Range and partial Content-Length. Invalid
ranges retain 416 and Content-Range with an empty body. Origin error bodies
are never exposed.

Every response, including errors, sets Cache-Control: private, no-store and
Surrogate-Control: no-store. Successful reads report X-Divine-Source: b2 and
X-Divine-Storage-Cache: BYPASS; readiness errors do not claim a B2 source.

Disable the mobile flag and remove b2_canary_host to stop new canary delivery.
Keep erasure enabled while replica bytes may exist.

## Copy and erasure races

Sync PUT and all-version erasure share the atomic add-only key b2-sync:v1:{hash}.
A worker claims {"state":"copying","attempt_id":"<unique id>"} before PUT, then
rechecks policy. Erasure claims {"state":"erasing"} before listing/deleting B2
versions. Copying intent makes erasure fail and retry; erasing intent permanently
prevents new mirror writes. Creator physical deletion and account vanish use the
same all-version erasure function and mutex.

Neither state expires. A crash or lost PUT response leaves copying intent
durable, preventing erasure success while a late upload may still commit.
Recovery requires an operator to stop/drain the original writer, establish no
PUT can still commit, reconcile all B2 versions and current policy, then release
only the matching copying intent with generation-aware conditional deletion.
Never delete an erasing marker, release an uncertain copy automatically, or use
a timeout as proof a writer stopped.

## Verification

Run:

    cargo test -p blossom-core --locked
    cargo check --tests --locked
    VICEROY=/path/to/viceroy ./scripts/run-edge-tests.sh
    cargo clippy --locked --all-targets --all-features

The edge suite invokes scripts/run-b2-canary-tests.py with synthetic KV and
local origins. It covers default-off denial, approved-only policy, tombstones,
owner/reference vanish, readiness/version validation, exact erasure bucket
mapping, origin failures, actual range/HEAD, cache bypass, warm canonical
metadata revocation, and copy/erase mutual exclusion.

Before client activation, verify an approved synthetic object's GET, HEAD and
range response through the real direct Compute domain, inspect version/source
headers and no-store policy, and prove revoked or missing readiness cannot
return cached canonical bytes. Validate real private-bucket all-version erasure
with synthetic content through the owning operator workflow before production
content. No visual change.

## Demand mode (separately enabled)

After deploying and proving the bounded worker and erasure path with an owned
approved fixture, exact `b2_demand_mirror_enabled=true` adds server-side GCS
fallback on the already configured direct host. This flag does not enable the
host, affect canonical reads, or start a runner. Devices must keep the B2 flag
off until the actual endpoint acceptance passes. A disabled host returns 404;
clients deliberately do not fall back from that terminal response.

Approved supported originals use a verified B2 version when ready. Missing
readiness or an independently observed B2 404/410 tries GCS once, bypassing FOS,
legacy origins, storage caches and the global read-primary flag. A B2 transport
outage, 429 or 5xx (including native authorization availability failures) also
tries GCS once, preserving readiness and emitting no copy hint. Invalid native
credentials, malformed responses and incorrect scope/mapping remain terminal. Copying intent permits GCS without a hint; erasing or malformed intent
remains terminal. Approved originals above 64 MiB use GCS without B2 or hints.
Malformed/mismatched readiness and auth/configuration/integrity failures return
502 without fallback; unavailable readiness returns 503. Failed policy/gate
lookups cannot authorize an origin request. Both origins recheck uncached policy
and the gate after I/O, including failed attempts. A newly observed denial wins.

GCS success reports `X-Divine-Source: gcs` and
`X-Divine-Storage-Cache: BYPASS`. Every response is private/no-store. HEAD uses
an actual HEAD and ignores Range. GET supports one closed, open-ended or suffix
range; malformed or multiple ranges are ignored and request the full object.
206 must match the requested span and metadata size. For a mathematically unsatisfiable valid single range, 416 returns
`Content-Range: bytes */<size>` and an empty body, and emits no hint. Some
B2 responses omit this header; the edge reconstructs it only from the known
authoritative size after validating unsatisfiability. An explicit mismatched
header or unexpected 416 for a satisfiable/malformed request remains an error.

A successful GCS 200/206/HEAD for an eligible missing copy attempts at most one
add-only `b2-demand:v1:{hash}` insertion. Version-1 values carry `version: 1`,
`sha256`, and `reason: missing_readiness` or `reason: missing_version` with
`observed_destination_version_id`. Existing hints coalesce; hint failure leaves
playback successful. The hint grants no copying permission. See
[b2-original-sync.md](b2-original-sync.md) for durable intake and repair.

Demand requests admit at most 16 uploader references plus the owner to bound
policy fanout. B2 authorization headers/body and each media response-header attempt have a
three-second wait bound within a twelve-second origin/hint budget; the enqueue
wait is at most 50 milliseconds. Synchronous policy KV reads and the full client
download are outside that I/O budget. Response bodies stream after the final policy check: a later
stream failure terminates that response rather than switching origins. These
are execution bounds, not a measured latency or global revocation guarantee.
Cross-POP propagation and inflight-body limits remain production acceptance
work.

Turning this flag off restores strict B2-only mode, including its 503 behavior.
For ordinary GCS playback, turn off the device flag. Pause worker intake or the
runner separately; preserve committed queues, state backups, copy gates and
permanent erasing markers. Keep B2 erasure enabled while any replica bytes remain.
No canonical/global traffic switch is included.
