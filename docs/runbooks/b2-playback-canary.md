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

## Request and readiness contract

Only GET and HEAD of /{lowercase-sha256} or /{lowercase-sha256}.mp4 are accepted.
Thumbnail, HLS, transcript, quality, upload, admin, and all other routes/methods
are denied. Authentication grants no bypass.

Each request reads uncached authoritative Fastly KV metadata. The blob must be
active, have a video MIME type and valid owner, have no tombstone, and have no
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
