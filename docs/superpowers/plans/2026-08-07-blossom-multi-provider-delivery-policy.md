# ABOUTME: Plan for serving public Divine media from a second CDN alongside Fastly, with rollback.
# ABOUTME: Scoped to public blobs only; restricted content stays on the existing Fastly Compute path.

# Blossom Multi-Provider Delivery Plan

**Date:** 2026-08-07 (rewritten to cut scope)
**Status:** Draft — one decision blocks the rest
**Scope:** Public read path only. Not authorization to deploy.
**Related:** `../specs/2026-08-06-cdn-delivery-steering-design.md`,
`../specs/2026-08-06-media-delivery-cost-architecture-review.md`

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

## The decision that blocks everything else

The second CDN needs an origin it can read at delivery rate. Fastly Object Storage's *public* S3
endpoint is documented at "~150Mbps and limited to a total of 100 requests per second"
([Fastly product docs](https://docs.fastly.com/products/object-storage)) — about 1.6 TB/day, against
a ~37 TB/day origin read requirement at 1M DAU. Reads from inside Fastly's network (Compute,
Deliver) are exempt, so this does not affect the sibling FOS-behind-Fastly plan. It only bites when
a *non-Fastly* CDN reads the bucket.

The same docs say "If your needs exceed these limits, reach out to sales@fastly.com," so this is a
commercial question, not a hard ceiling — but **a raise nobody has quoted is not a capacity plan.**
Until Fastly gives a sustained number in writing (cost review open question 16), assume FOS cannot
be the second CDN's origin. Two workable shapes:

- **(a)** second CDN reads GCS directly — works today, but GCS egress returns on every cache miss;
- **(b)** R2 as the replica origin, $0 egress to any consumer — what the cost review recommends
  first (§8.1 step 5).

Pick one before building anything. The earlier "Bunny primary + Fastly Object Storage standby"
shape is not buildable as written: it names FOS as the standby origin *and* assumes a second CDN in
front of it.

## The scope rule that removes most of the work

**Only approved, public, non-age-restricted blobs are eligible for the second provider.** Pending,
age-restricted, geo-restricted, legal-hold, and tombstoned hashes stay on the existing Fastly
Compute path, where the existing auth check already runs.

That single rule deletes, from the earlier draft:

- the playback-authorization API and short-lived signed CDN URLs;
- separate public and protected zones per provider;
- provider-side age and geography enforcement;
- most of the takedown sequence — a restricted hash was never on the second provider to begin with.

If restricted content ever needs multi-provider delivery, that is a separate plan with its own
justification.

## Replication

After a blob is approved and public, best-effort copy it to the second provider from the existing
pipeline. Verify length and SHA-256. Record which providers hold it as one field on the existing
metadata record. Do not block publication on the copy.

No queue, no reconciler, no replication framework, no BUD-04 `PUT /mirror` path. A periodic repair
command covers gaps until measurement shows it does not.

Recheck policy immediately before copying. A delayed job must never publish a hash that has since
been tombstoned or restricted.

## Steering

Server-side only, per the steering design: a `select_delivery_host()` call at the descriptor seam.
Ineligible content never gets the second host. The percentage lives in the config store; rollback is
setting it to 0. No mobile or web client change.

For HLS, the manifest and its segments come from one host for a given playback session. Do not
alternate providers per segment.

## Takedown

The existing flow is unchanged — tombstone, status update, surrogate-key purge. Add two steps:

1. purge the second provider's cache for that hash;
2. delete the replica.

Both retry. Neither is load-bearing for correctness: eligibility is checked at steering time, so a
tombstoned hash stops being steered to the second provider immediately, whether or not the replica
delete has landed. Alert if a replica delete stays unconfirmed.

## Pilot

20–100 representative approved public objects.

1. Non-production bucket/zone and credentials at the second provider.
2. Copy and verify the sample objects.
3. Steer an explicit test-hash allowlist, then 1% of eligible public traffic.
4. Measure against Fastly on the same content: startup latency, rebuffering, cache hit rate, miss
   latency, origin bytes, billed units.
5. Exercise 404, 5xx, and timeout fallback to the existing path.
6. Tombstone one test hash; confirm it is unreachable on both paths.
7. Decide.

Rollback at every step is setting the steering percentage to 0.

## Go/no-go

- byte-identical content and correct range behavior from the second provider;
- no playback regression in the top regions (cost review §1, GA4 geography);
- measured cost per delivered GB beats Fastly's rate on the same content;
- tombstone honored on both paths;
- a vendor quote covering campaign peak, in writing.

Do not restate cost projections here. The scaling tables live in the cost review (§4).

## Deferred on purpose

Each of these needs its own justification. None belong in the pilot.

- **Client-side BUD-03 fallback and kind `10063` publication.** Server-side steering already gives
  provider choice with no app release. Client fallback only earns its cost against a *total* Fastly
  outage — decide separately, after the pilot shows the second provider works at all.
- Protected and age-gated content on the second provider (see the scope rule).
- Durable replication queue, readiness reconciliation, dashboards.
- A generic replication abstraction. Provider APIs called directly are fine for one provider.
- A third provider, or geographic steering.
- `backup.media.divine.video` as a separate published hostname. `media.divine.video` stays the
  compliant Blossom server (cost review §8.2); adding a second published name is a client-visible
  change and belongs with the client-fallback decision above.

## Open questions

1. **Which origin does the second CDN read — GCS or R2?** Blocks everything.
2. Will Fastly quote a sustained public-endpoint throughput above ~150 Mbps for a non-Fastly CDN?
   A "yes" with a number reopens FOS as the replica origin; silence means assume no.
3. Does the current derivative and HLS layout copy cleanly to another provider?
4. Can the second provider purge fast enough for bulk takedown?
5. How much does a second delivery hostname fragment the cache? The cost review flags the
   first-party vs third-party read split as unmeasured (§8.2).

*Resolved: why Bunny was removed — HLS processing, not delivery. See above.*
