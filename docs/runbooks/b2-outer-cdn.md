# B2 originals through the outer CDN (default off)

This source adds an opt-in B2 delivery route behind outer VCL service
`ML7R82HKfmTaqTpHExIDVN`. A warm outer HIT serves bytes without executing
Compute or performing a provider read. A MISS runs the existing private B2
version/size verification, native erasure authorization, metadata/access,
vanish, copy/erasing and final quarantine policy checks. Missing B2 readiness
or a missing pinned object can use the existing GCS demand fallback, which
remains outer `no-store`. Browser responses always remain `private, no-store`.

Warm HITs deliberately use the canonical purge-based policy model. They do
not repeat the direct canary's fresh per-request checks. This source is not
proof that moderation/erasure invalidation, in-flight fills, or shielding are
safe to activate. Keep the feature off until the separate purge work and its
operator acceptance evidence establish that contract.

## Configuration and request scope

No production configuration is set by this change. All of the following are
required before the new route admits a response:

| Setting | Required value |
| --- | --- |
| `b2_cdn_enabled` | Exactly `true`; missing/other values stay off. |
| `b2_cdn_host` | Exactly `media-b2-cdn.divine.video`, or an explicitly migrated `media-b2.divine.video`. |
| `b2_cdn_origin_host` | Exact lowercase hostname of the existing outer `compute_origin` backend's overrideHost; inspect that backend before configuring it. No scheme, port, or path. |
| `b2_cdn_purge_hosts` | Comma-separated distinct declared B2 delivery hosts actually bound to this outer service, including `b2_cdn_host`; one or two entries, no whitespace. |
| Secret `fastly_api_token` | Existing nonempty purge credential; presence is checked, actual purge authorization still requires operator proof. |

B2 private-origin configuration, version readiness and erasure credentials
remain necessary as required by the demand path. CDN misses always use that
path independently of `b2_demand_mirror_enabled`. `b2_canary_cache_enabled`
continues to control only the existing optional inner storage cache.

Forwarded requests must have the configured Compute origin as both their
actual authority and Host, with exactly the configured delivery host in
`X-Original-Host`. The outer recv snippet overwrites `X-Original-Host` from the
incoming Host before service chaining. This is host routing, not an assertion
that an anonymous caller is authenticated by a forwarding header. Anonymous
GET/HEAD requests still require all original-video policy and integrity checks.
Direct requests on the dedicated `media-b2-cdn.divine.video` name are also
subject to these checks. Direct `media-b2.divine.video` requests retain the
existing strict canary behavior even when its forwarded name is migrated.

Any Authorization or Cookie header, including an empty header, prevents CDN
admission. Uploads, admin routes, derivatives, uppercase hashes, other
extensions and malformed original paths are denied on the CDN route. Only
`/{lowercase-64-hex}` and `/{lowercase-64-hex}.mp4` are original paths.
The original parser ignores query strings; the B2 outer route removes them
and the optional `.mp4` suffix before lookup, making one cache URL per host
and hash. Host case/port aliases are not admitted. Canonical GCS routing and
cache policy are unchanged.

## Admission and cache keys

After every routing and final policy guard has returned, only a successful
full verified B2 200 receives all of:

- `X-Divine-B2-CDN-Admission: original-v1`.
- `Surrogate-Key: {lowercase-64-hex}` (the bare hash).
- `Surrogate-Control: max-age=31536000, stale-while-revalidate=0, stale-if-error=0`.

The outer VCL requires this marker, status 200, the exact policy and hash key,
matching `X-Sha256`, and absence of Content-Range or Set-Cookie. Missing
admission means pass, including errors and cached negative responses. B2
entries have a 365-day purgeable TTL, zero grace, zero stale-while-revalidate
and zero stale-if-error. No denial or fallback is cached. A cold range or HEAD
lookup fetches a complete GET; Fastly handles client HEAD and warm ranges.

The normalized URL keys are `https://media-b2-cdn.divine.video/{hash}` and,
only when that hostname is actually migrated to this service,
`https://media-b2.divine.video/{hash}`. Keep each formerly active hostname in
`b2_cdn_purge_hosts` until its old cached URLs and pending fills have drained
and been purged. Do not URL-purge the strict Compute canary through the outer
service before its host binding is moved. A key purge alone is not proof of
in-flight/shield invalidation; that requires the separate acceptance test.

Admission markers, Surrogate-Key and Surrogate-Control survive the shield
hop and are stripped at client-facing delivery. B2 client ingress generates
a fresh outer UUID, preserved for its shield continuation and returned as
`X-Request-Id`. Cached Compute playback IDs, load IDs and provider/storage
source headers are stripped from client responses. A warm HIT must never be
reported as a fresh provider read. Delivery logging must take load IDs from
the current request, rather than a cached response; inspecting two warm HITs
must show distinct outer request IDs.

## Manual activation and rollback

The currently inspected outer service has a 20 MiB ordinary/streaming-miss
object limit. This route does not raise that limit. Initial acceptance must
stay below it; larger originals remain uncached and 32 MiB outer caching is
not supported by this change. Fastly's
documented segmented-caching option changes origin range requests and cache
identity, so it needs separate admission and invalidation tests before use.
Do not invent a settings API field or override generated VCL pragmas. An
oversize response can fail instead of merely remaining uncached.

1. Finish independent review and the separate moderation/erasure purge slice.
   Prove targeted invalidation on both ordinary warm entries and a blocked
   in-flight fill crossing the shield. Prove denied/restricted/admin/derivative,
   GCS fallback, native-auth failures and errors cannot refill an entry.
2. Inspect live backend host override, declared outer domain bindings and
   shield configuration without changing them. Configure only reviewed names;
   this document does not authorize DNS, binding or provider mutations.
3. Follow [outer VCL](outer-vcl.md) to compare the entire active snippet set,
   preserve unrelated live drift, prepare a draft and validate the complete
   draft. A Compute publish does not deploy VCL. Live Fastly VCL validation
   and two real warm HITs are operator gates; source contracts do not replace
   them. Check header retention on shield-to-edge delivery explicitly.
4. Follow [rollback](rollback.md) for the explicit operator activation order.
   Publish Compute with `fastly compute publish`, activate the reviewed outer
   version separately, and enable the configuration only after the above
   proofs. Verify cold 200, warm/range/HEAD delivery, body checksum, no browser
   caching, distinct warm request IDs and no extra Compute/provider events.
5. To stop admitting new entries, set `b2_cdn_enabled` off. Existing warm HITs
   skip Compute, so this setting alone does not stop their delivery. Restore
   the reviewed pre-activation outer/domain routing as the rollback plan
   requires and target-purge every affected normalized URL/hash across retained
   host bindings. Confirm erasure with independent requests after outstanding
   fills drain. Do not use a global purge for routine rollback.

## Local validation

`VICEROY=<local-path> python3 scripts/run-b2-cdn-tests.py` runs synthetic
private-origin fixtures only, covering exact host routing, GET/HEAD, aliases,
credentials, denied policy, version/size integrity, GCS fallback and default-off
configuration. It is included in `scripts/run-edge-tests.sh` alongside the
existing canary and quarantine-race suites. Pure policy tests run with
`cargo test -p blossom-core --locked`; VCL source contracts run with
`python3 -m unittest scripts.tests.test_b2_cdn_vcl`. No provider writes or
credentialed media probes are part of local validation.


## Durable invalidation and physical completion

CDN admission and invalidation have different lifetimes. Retaining the
`b2_cdn_purge_hosts` key keeps invalidation active even when admission or replica
reads are disabled. An empty or invalid retained host value is an error, never
permission to silently discard a queued eviction. Keep purge credentials and
host bindings until all retained entries and pending fills are reconciled.

Policy writes first persist a distinct per-attempt intent in
`b2-cdn-purge:v1:{hash}:{attempt}`. Prepared intents survive an interrupted
mutation; committed intents survive failed eviction. Prepared or foreign records
are not automatically cleared. A checked purge must succeed before a committed
intent can be marked cleared, and a receipt is bound to its exact attempt.
Missing records do not imply acknowledgement. Every URL and service-key request
in both rounds must return2xx. A URL404 does not establish that a retained host
is unbound or that eviction happened, even when all service-key requests succeed.
Any URL/key404, authentication failure or provider error fails the checked
operation and retains the committed intent and pending final acknowledgement.

For modern domains, Fastly's URL endpoint is
`POST /service/<outer-service-id>/purge_url/<validated-host>/<hash>` with a
scheme-free target; do not percent-encode the entire host/path. Both retained
hosts target the same outer service, as required by the
[modern domain contract](https://www.fastly.com/blog/domains-reimagined-faster-safer-fully-independent-from-service).
Bulk surrogate-key success responses are
maps of keys to purge IDs, not a `status:ok` object. These API acknowledgements
do not prove end-to-end eviction or in-flight-fill exclusion: live acceptance
must separately verify that `FASTLYPURGE` traverses the VCL cache path (and
`PURGE` is forwarded in Compute when applicable), with matching cache identity.

The authenticated POST `/admin/api/b2-cdn-purge/drain?max=2` drains at most two
hashes per execution. A recurring worker may use the dedicated Secret Store key
`b2_cdn_purge_drain_token`; it is accepted only on this endpoint and grants no
moderation or general admin authority. Existing operator admin authentication
remains supported. The response's `result`, `pending`, `errors` and `unknown`
are nonnegative counts for this bounded pass, not proof of a globally empty
queue. The request budget includes both URL/key rounds and
metadata operations. Do not combine that drain with a physical erasure wave or
raise its limit to accelerate a backlog. Cursor progress must pass blocked rows
without discarding them. A functioning unattended drain and alert/recovery path
must be deployed and demonstrated before broad CDN admission; a source endpoint
and manual successful call alone do not establish that operational readiness.

Physical creator deletion uses a separate bounded wave for the source and, if
unshared, its derived audio. Metadata denies delivery while the operation is
pending. Physical absence and the final checked eviction receipt are both needed
before reporting success. A request awaiting eviction returns conflict/retry;
it must not repeat an already-absent physical deletion. Audio mappings remain
until the audio has its own final receipt so a retry can still discover it.
Replica/provider failure never permits completion, and never cancels the need
to evict cached bytes. Permanent erasing gates remain in place.

These source transitions do not prove that a purge cancels an already-admitted
shield fill. Real pre-header and mid-body held-origin experiments and real
moderation/erasure tests remain required. A two-second second purge is a shield
ordering mitigation, not an unconditional late-fill cancellation guarantee.
