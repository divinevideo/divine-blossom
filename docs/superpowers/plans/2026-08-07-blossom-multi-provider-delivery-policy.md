# ABOUTME: Plan for serving public Divine media from a second CDN alongside Fastly, with rollback.
# ABOUTME: Scoped to public blobs only; restricted content stays on the existing Fastly Compute path.

# Blossom Multi-Provider Delivery Plan

**Date:** 2026-08-07 (rewritten to cut scope)
**Status:** Decision recorded — use Backblaze B2 as the second-CDN origin; pilot remains unapproved
**Scope:** Public read path only. Not authorization to deploy.
**Related:** `../specs/2026-08-06-cdn-delivery-steering-design.md`. The cost review this document
cites by section is commercial analysis and is deliberately not in this public repository; it lives
in `divine-context` under `repo-context/divine-blossom-media-delivery-cost-review-2026-08.md`.

## The question this answers

Can a second CDN serve public Divine media cheaper than Fastly, and can we fall back to it? That is
the whole pilot. Everything else in the earlier draft is deferred at the bottom of this document.

## What already exists — do not rebuild it

- `BlobMetadata` in Fastly KV *is* the per-hash policy record: `BlobStatus`, `AgeRestricted`,
  `tombstone:` keys (`src/metadata.rs`), soft delete and legal hold (`src/delete_policy.rs`).
- Viewer auth already runs at the edge — kind 24242 and NIP-98 (`src/viewer_auth.rs`). Restricted
  reads are already gated there.
- Moderation already purges by surrogate key.
- `to_descriptor(&base_url)` (`blossom-core/src/types.rs:381`), fed by `get_base_url()`
  (`src/main.rs:5795`), is the single place every outbound media URL is chosen. That is the
  steering point.
- Bunny was removed from this codebase in Feb 2026 (`1cb3ee8`), and
  `scripts/migration/migrate_from_bunny.py` migrated the content off it. **We left Bunny's HLS
  processing, not Bunny's delivery** — transcoding went Bunny → Cloudflare → Google Cloud → Fastly.
  Delivery cost was not the reason. So re-adopting Bunny *as a CDN only* does not re-incur why we
  left.

  **Guardrail:** transcoding and HLS packaging stay in the existing Cloud Run / GCS pipeline. Bunny
  Stream is out of scope. If a proposal starts moving processing back to a CDN vendor, it has
  stopped being this plan.

## Origin decision — private Backblaze B2

**Use a private Backblaze B2 bucket as the approved-only replica origin for bunny.** GCS remains
Divine's private authoritative store. Fastly Object Storage remains a separate, Fastly-only delivery
mirror. Do not put a non-Fastly CDN in front of FOS unless Fastly quotes and contractually supports
the required public-endpoint capacity.

Why B2 instead of letting bunny read GCS directly:

- B2 is $6.95/TB-month with free Class A/B/C transactions
  ([B2 pricing](https://www.backblaze.com/cloud-storage/pricing)), and Backblaze *claims* unlimited
  free egress through partner CDNs including bunny
  ([CDN partners](https://www.backblaze.com/cloud-storage/solutions/cdn)). Treat the partner-CDN
  rate as **unverified**: the vendor notes tag it `[U]` and the mechanism is undocumented. The
  downside case if it does not apply is $0.01/GB above the 3× storage allowance, which is still
  below GCS network egress on every bunny cache miss — the cost line this pilot exists to remove.
- B2 has a private S3-compatible endpoint and bucket-scoped application keys. bunny pull zones
  expose AWS signing configuration
  (`AWSSigningEnabled`, key, secret, and region) in the
  [pull-zone API](https://docs.bunny.net/api-reference/core/pull-zone/add-pull-zone), so the pilot
  can keep the replica private. Prove the B2 region, endpoint, host/path style, and range behavior
  against a real pull zone before traffic. The browser-visible behavior was validated on a *public*
  probe bucket, so a private signed origin has to re-prove it: an explicit CORS rule covering range
  and conditional headers and exposing `content-range` / `accept-ranges`; `Content-Type` carried
  from the source, because an `application/octet-stream` default makes `<track>` subtitles fail
  silently while video still plays; and cache-control set at upload so Fastly and bunny do not
  disagree on TTL for the same object. The rollout plan has the specifics, but its CORS rule was
  written against B2's native download operations, and a B2 CORS rule applies only to the operations
  it lists. Derive and record the S3-endpoint equivalent as part of the pilot rather than copying
  that rule — signing can prove out while browser range and VTT requests still fail CORS.
- B2 is always versioned. An S3 `DeleteObject` or `b2_hide_file` can leave older bytes retrievable;
  takedown must enumerate and permanently delete every file version
  ([B2 file versions](https://www.backblaze.com/docs/cloud-storage-file-versions)).
- B2 is a disposable replica. Its availability does not replace GCS durability because rollout can
  be set to zero and Fastly/GCS remains the authoritative path.

Why B2 and not R2, which the cost review ranks first (§8.1 step 5): on paper R2's $0 egress to any
consumer is the stronger position, and that ranking still stands on cost alone. B2 wins on evidence.
It has been stood up and drilled end-to-end as a real bunny pull-zone origin — delivery latency
within 6% of the alternatives, and the takedown semantics measured live — while R2 has no bucket and
no token (`../../cdn-evaluation-status.md`). Choosing the measured option for a pilot whose whole
purpose is measurement is the cheaper mistake to unwind: this is a disposable replica, and if
partner-CDN egress does not materialise on the billing account, R2 is the first fallback to test.

The initial GCS-to-B2 copy incurs one-time GCS egress; measure that separately from steady-state
delivery cost. Confirm on the production billing account that bunny-origin reads receive the
advertised partner-CDN egress treatment before ramping traffic.

GCS remains acceptable only as a short-lived non-production diagnostic origin if needed to test
bunny's AWS-signing compatibility. It is not the production choice. The earlier "Bunny primary +
Fastly Object Storage standby" shape conflated two independent mirrors; the settled topology is:

```text
GCS private authority -> FOS private mirror -> Fastly
                      +-> B2 approved-only mirror -> bunny
```

## The scope rule that removes most of the work

**Only approved, public, non-age-restricted blobs are eligible for the second provider.** Pending,
age-restricted, geo-restricted, legal-hold, and tombstoned hashes stay on the existing Fastly
Compute path, where the existing auth check already runs.

That single rule deletes, from the earlier draft:

- the playback-authorization API and short-lived signed CDN URLs;
- separate public and protected zones per provider;
- provider-side age and geography enforcement.

If restricted content ever needs multi-provider delivery, that is a separate plan with its own
justification. This rule does **not** remove the takedown obligation for content that was Active,
replicated, and later banned or deleted.

## Replication

After a blob is approved and public, explicitly copy it to B2 from the existing pipeline. Verify
length and SHA-256. Record which providers hold it as one field on the existing metadata record.

Publication does not wait for the copy, but **steering does**. Set the replicated flag only after
the copy verifies, and route a hash to bunny only once that flag is set. Reversing this order 404s
freshly-approved content for its first viewers. The implementation contract for that ordering — the
queued job, the flag, and the reconciler that asserts replica presence for `Active` hashes and
absence for everything else — is the bunny rollout plan
(`2026-08-07-bunny-delivery-rollout-plan.md`); this document selects the origin and does not restate
or override it.

Do not configure a pull-through or automatic rehydration path from preserved GCS objects into B2. A
deleted replica must not be silently recreated after a moderation action. The writer gets a
bucket-scoped credential with the explicit upload and version-delete capabilities it needs; bunny
gets a separate bucket-scoped read-only credential. Neither credential belongs in source control or
client-visible configuration.

No generic replication framework and no BUD-04 `PUT /mirror` path. Enqueue on Cloud Tasks, following
the pattern of the existing derivative-status queue rather than sharing that queue — its serialized
dispatch is part of a generation-ordering contract replication has no generation for. The reconciler
is a periodic repair pass over one flag, not new machinery.

Recheck policy immediately before copying. A delayed job must never publish a hash that has since
been tombstoned or restricted.

## Steering

Server-side only, per the steering design: a `select_delivery_host()` call at the descriptor seam.
Ineligible content never gets the second host. The percentage lives in the config store. Setting it
to 0 stops issuing new bunny URLs without a deploy.

That is **roll-forward control, not request-level failover**. A client that already holds a
second-provider URL continues using it until it refreshes the descriptor. The pilot must measure and
bound that URL lifetime.

The retroactive lever is DNS, and it only exists if the delivery URLs are on a Divine-owned
hostname. Descriptors must therefore never emit a vendor hostname, per the rollout plan's stage 0a
(`v.divine.video` as a custom hostname on the delivery zone). Repointing that record moves
already-published URLs back to Fastly; a cache purge does not, because purging only forces bunny to
refetch from B2 and it keeps serving.

Automatic retry from bunny to Fastly requires a client-visible fallback URL or a separate provider
failover mechanism and is deferred; this plan must not claim it already exists.

For HLS, the manifest and its segments come from one host for a given playback session. Do not
alternate providers per segment.

## Takedown

Eligibility prevents never-approved content from reaching B2, but it cannot revoke a bunny URL
already issued to a client. The cache purge and replica delete are therefore load-bearing for
takedown correctness.

Run one idempotent, retryable takedown job in this order:

1. commit the tombstone/status change so no new bunny URLs are issued;
2. list every B2 file version belonging to the hash (root, extension-suffixed objects, and
   hash-prefixed derivatives) and call `b2_delete_file_version` for each version and hide marker;
3. purge the hash from every bunny delivery zone;
4. purge the Fastly surrogate key;
5. verify representative URLs deny on both providers and `b2_list_file_versions` returns zero
   matching versions.

Do not report takedown completion until deletion and every cache purge are confirmed. Retry and alert
on partial completion. If the required legal SLA is shorter than this fan-out can guarantee, add an
edge deny-list before increasing rollout; descriptor steering alone is insufficient.

## Pilot

20–100 representative approved public objects.

1. Private non-production B2 bucket, separate scoped writer and read-only origin
   credentials, a bunny pull zone with AWS signing enabled, and a Divine-owned delivery hostname
   with a short TTL on that zone — step 5 cannot exercise the DNS move without it.
2. Copy and verify the sample objects.
3. Steer an explicit test-hash allowlist, then 1% of eligible public traffic.
4. Measure against Fastly on the same content: startup latency, rebuffering, cache hit rate, miss
   latency, origin bytes, billed units.
5. Exercise B2 404, 5xx, and timeout behavior. Verify that setting rollout to 0 stops new bunny
   descriptors, measure how long already-issued URLs remain in use, and exercise the DNS move that
   retires them. Do not label either one automatic failover.
6. Tombstone one test hash; confirm it is unreachable on both paths.
7. Decide.

Rollback at every step begins by setting the steering percentage to 0, which stops new descriptors.
Already-published URLs keep resolving to bunny until they are repointed by DNS, so rollback
verification must exercise both levers — the config flip and the hostname move.

## Go/no-go

- byte-identical content and correct range behavior from the second provider;
- no playback regression in the top regions (cost review §2, GA4 geographic distribution);
- measured cost per delivered GB beats Fastly's rate on the same content;
- tombstone honored on both paths;
- B2 remains private and bunny origin authentication works without public bucket access;
- partner-CDN egress is confirmed in actual B2 billing;
- the measured descriptor-refresh window is acceptable for operational rollback;
- a vendor quote covering campaign peak, in writing.

Do not restate cost projections here. The scaling tables live in the cost review (§4).

## Deferred on purpose

Each of these needs its own justification. None belong in the pilot.

- **Client-side BUD-03 fallback and kind `10063` publication.** Server-side steering chooses a
  provider but does not retry a failed request on another provider. Decide separately after the
  pilot whether automatic per-request failover earns the client complexity.
- Protected and age-gated content on the second provider (see the scope rule).
- Replication dashboards. The readiness flag and its repair pass are not deferred — steering
  correctness depends on them.
- A generic replication abstraction. Provider APIs called directly are fine for one provider.
- A third provider, or geographic steering.
- `backup.media.divine.video` as a separate published hostname. `media.divine.video` stays the
  compliant Blossom server (cost review §8.2); adding a second published name is a client-visible
  change and belongs with the client-fallback decision above.

## Open questions

1. Does bunny's AWS-signing mode interoperate with the private B2 S3 endpoint, range requests, and
   the required region and host/path style?
2. Will Fastly quote a sustained public-endpoint throughput above ~150 Mbps for a non-Fastly CDN?
   A "yes" with a number reopens FOS as the replica origin; silence means assume no.
3. Does the current derivative and HLS layout copy cleanly to another provider?
4. Can the second provider purge fast enough for bulk takedown?
5. How much does a second delivery hostname fragment the cache? The cost review flags the
   first-party vs third-party read split as unmeasured (§8.2).

*Resolved: why Bunny was removed — HLS processing, not delivery. See above.*
