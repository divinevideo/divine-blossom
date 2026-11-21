# Bunny HLS and MP4 delivery

Status: proposed design, awaiting Rabble's approval before implementation.

## Intent and scope

Move approved public video delivery, including HLS playlists and segments, to
Bunny CDN from a private B2 origin. Preserve the existing transcode pipeline,
signed Nostr events, rendition selection, and canonical media URLs. The existing
mobile Bunny flag controls the alternate playback source and rollback.

Rabble explicitly requested HLS as well as MP4. Extending only MP4 leaves HLS
delivery on Fastly. Vendor comparisons and account costs stay out of this public
repository; the delivered-byte measurements will establish actual savings.

## Approaches

1. Extend the merged approved-public-content pilot to HLS. Reuse the isolated
   B2 delivery prefix, publication gate, revocation queue, and mobile opt-in.
   This supplies an incremental route to moving both playback formats.
2. Add signed playback capabilities and Bunny pre-cache middleware now. This
   can support viewer-specific access decisions, but also requires a capability
   issuer, expiry/refresh behavior, and a tested policy/revocation contract.
3. Port Blossom's whole edge service to Bunny. This also changes uploads,
   administration, metadata access and protocol handling, substantially widening
   the migration beyond video delivery.

Recommendation: approach 1, including production enrollment and rollout rather
than stopping at an internal canary. Approaches 2 and 3 are not prerequisites
for serving public HLS. This choice is proposed by the agent;
the user has approved the delivery objective, not this document yet.

## Current implementation

- Blossom PR #387 publishes originals and 720p MP4 through an authenticated
  single-object operation. Publication is off by default.
- `blossom-core/src/bunny_pilot.rs` currently accepts only the two MP4 paths.
- `src/bunny_publish.rs` verifies bytes and current public policy around B2 I/O.
- `src/storage.rs` scopes Bunny writes to `bunny-delivery/`, retains enrollment
  and purge targets, and removes all versions before checked eviction.
- Mobile PR #11198 adds `bunnyPlaybackCanary` and a build-time exact-path list.
  The native feed places a Bunny equivalent immediately before its matching
  canonical source. It currently excludes HLS.
- The transcoder produces VOD HLS with per-rendition single-file TS media and
  byte ranges. Existing master playlists may use relative or root-relative paths.
- Fastly has a 32-backend-request execution limit. Copying an entire family by
  naively repeating the current publisher in one execution is not acceptable.

## Publication and origin contract

Keep the private origin and separate read, write, and erasure credentials. Bunny
pulls from B2 directly; no Fastly origin proxy is in the normal delivery path.

Extend the exact public namespace to the canonical master, rendition playlists
and TS objects emitted by the current transcoder. Retain original and 720p MP4
support. Do not introduce arbitrary file-tree mirroring, redirects, or a return
to Bunny Stream processing. Continue requiring current approved public policy;
authenticated/age-gated playback remains canonical in this first increment.

Publish one object per bounded request, using the existing parent exclusion and
uncertain-write recovery protocol. For HLS the operator supplies a bounded,
complete inventory of expected source digests for the selected clip's master,
variant playlists and media files. A resumable reconciler derives that inventory
from immutable source versions and current producer completion evidence; it is
not maintained by hand for the production rollout. Reuse the existing
`scripts/b2_playback_family.py` validators and B2 mirroring interfaces where
their contracts match. Verify each source against that inventory.
An existing delivery object with different bytes is a conflict, never an
implicit replacement. Retire and verify eviction of an enrolled family before
publishing a repaired rendition under its existing paths.

Publish media first, variant playlists next, master last. Before publishing a
playlist, validate every referenced dependency against the inventory and verify
the exact destination bytes. Bound the family to the current two-rendition
transcoder output and fit the worst case, including cleanup, within the edge
request budget. Larger or unsupported families remain on canonical playback.
Retain the existing 16 MiB per-object bound. The master is added to a device's
allowlist for the internal fixture phase only after successful publication and
full-family verification. Production clients use verified readiness instead.

Normalize same-clip playlist references to relative paths in the published copy
so all subrequests resolve under the Bunny hostname. Check both URI lines and
URI attributes. Preserve playlist semantics, byte ranges and renditions. Decline
unsupported playlist forms or references outside the verified family. Verify
the source digest before transformation and the resulting delivery digest after
writing. No signed event or canonical object is rewritten.

Set correct playlist/TS MIME types and retain the pilot's cache/revocation
configuration. Update both custom and vendor-host allowlists for the exact HLS
paths; keep all other origin routes inaccessible.

## Mobile behavior

Extend the existing default-off device flag and exact-path allowlist to the
canonical HLS master for internal testing. Add a separate production playback
flag using the existing build/runtime feature-flag framework, default off until
the release is activated. Do not silently make the internal canary a global
build flag. Production builds require no compiled per-clip fixture list.

Insert a verified Bunny equivalent at the same point in the existing source
ladder; preserve MP4-versus-HLS selection and quality order.
The whole HLS tree resolves from the selected master host. Readiness or the
internal master allowlist represents a verified complete family, not permission
to try unverified paths.

Retain transport/timeout/503 fallback to the equivalent canonical source. Policy
denials stay terminal; viewer credentials never go to the public Bunny zone.
Cover native errors from child playlist and segment loads as well as master
loads. Switching the flag off rebuilds prefetched entries to canonical playback.
Public release activation follows verified internal acceptance; its automatic
enrollment and cohort controls are part of this migration's implementation.

## Production enrollment, selection and rollback

Run a resumable scheduled reconciler for backfill and newly completed clips.
Persist discovery cursors and per-parent publication progress privately. Use
the existing storage inventory/pinned-version interfaces and authoritative
policy checks; transient failures retain retryable progress. Unsupported,
restricted, incomplete or oversize content stays on canonical delivery. Do not
recopy changed bytes into enrolled paths without retiring the previous family.
Set explicit concurrency and transfer-byte limits and expose aggregate progress
and errors. Enrollment must not depend on a human compiling clip lists.

Write a versioned `bunny-ready:v1:<parent>` record only after the selected
playback family is verified, with exact delivery paths, source/delivery digests
and object versions. Finalize readiness under the existing parent exclusion,
with fresh public policy and source checks. Revocation invalidates readiness
before removing replicas; a revoked parent cannot be re-enrolled by an old job.
The complete bounded schema and budget are fixed in the implementation plan.

Provide a small no-store delivery-selection response on the canonical Blossom
service. It returns verified eligible alternate source URLs only after reading
current authoritative policy and readiness. This control-plane call may use
Fastly; media playlists, segments and MP4 bytes do not pass through it. Missing
readiness, a disabled cohort or a control-plane outage preserves canonical
source selection. Actual policy denials retain existing terminal behavior.
Only approved fixed Bunny hosts and paths may be returned or accepted by the
client. Authenticated viewer playback continues through canonical handling.

Server configuration independently controls publication, selection percentage
and eligible markets. Use stable per-parent hash cohorts for a 0/1/10/50/100
percent ramp. Zero stops selection without a new app release. The mobile
production flag allows selection lookups; it does not override server rollout
or policy. Bound selection latency and de-duplicate lookups during prefetch.
Any in-memory selection cache expires within 30 seconds. Rollback stops new
alternate selection within that bound; local flag disable also rebuilds queued
and prefetched entries. Already-playing public media and cached bytes are
revoked through the separate deletion/purge protocol, not by a selection flag.

Ship the reconciler, readiness/selection contract and mobile integration before
claiming production migration readiness. Only live activation and measured
traffic prove that delivery has switched.

## Revocation and recovery

Extend delivery-key validation so all enrolled HLS versions are enumerated and
removed by the existing bounded erasure flow. Reuse the hash-prefix purge on
both retained hostnames. Keep durable retry, all-version confirmation and
parent-write exclusion, including during interrupted publication. Pending
cleanup must survive publication disablement and device rollback.

Test revocation after warming every playlist and segment, and while an origin
fill is in flight. Verify denied GET, HEAD and Range responses across both
hostnames through the full cache window. Appeals require successful cleanup,
current approval and explicit verified republication.

## Bunny access controls and edge compute

Bunny has native signed URL/directory-token controls and Deno/V8 Edge Scripting.
Before-cache middleware can authorize cache hits, whereas its default post-cache
mode cannot. These are available architecture options, not a reason to retain
Fastly in the media-byte path. This increment does not introduce viewer tokens
or scripts. A later protected-playback design must specify the policy authority,
token scope/expiry, cache behavior and revocation semantics before activation.

Primary references, checked 2026-11-21:

- https://bunny.net/docs/cdn/security/token-authentication/advanced
- https://bunny.net/docs/scripting
- https://bunny.net/docs/scripting/before-cache

## Validation and release

Write failing Rust/Python/Dart behavior tests before implementation. Cover
publication order, incomplete families, changed digests, URI resolution, byte
ranges, media MIME types, idempotence, gate races, revocation/retry, fallback and
flag rollback. Use only synthetic identifiers and local provider fixtures.
Extend the read-only provider probe to recursively verify the supported family
on both Bunny names, including parity with the canonical media bytes and no
Fastly-hosted subresources. Bound traversal and redact fixture paths in output.

Run Blossom core, Viceroy edge and publisher/revocation suites plus the relevant
Python tests, compile checks and clippy. Run the mobile playback package tests
and analysis with the repository's coverage requirements. Open separate PRs
targeting each repository's main branch with their shared wire contract and
validation evidence. Obtain independent review and inspect required CI.

Live activation remains an operator action after code review: provision the
zone, scoped credentials, DNS/TLS, publication bindings and monitored cleanup;
exercise owned fixtures before real clips. Begin paired iOS/Android playback
measurements in the U.S.; keep Australia/New Zealand canonical initially.
Compare delivered bytes, hit/miss mix, first-frame/gap timings, fallback counts
and combined delivery/origin charges. Ramp supported eligible traffic using
the server cohort control after acceptance. Do not claim savings from merged code or
DNS alone. A failed revocation drill disables the zone pending reconciliation.

## Builder decisions and remaining user decision

The builder chooses exact internal types, bounded request/inventory schemas,
test organization and helper placement using existing repository patterns.
They must demonstrate the backend-request budget before finalizing the API.
The user decision is whether to approve this public HLS-and-MP4 migration,
including production enrollment and cohort controls. Protected viewer-specific
playback remains a separate subsequent migration.
