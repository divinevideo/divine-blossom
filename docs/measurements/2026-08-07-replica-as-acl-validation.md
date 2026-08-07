# ABOUTME: End-to-end validation that a push-replica delivery store enforces access control by absence.
# ABOUTME: Also isolates origin choice from geography by comparing a storage-backed pull zone to a pull-through one.

# Replica-as-ACL — Working Test System (2026-08-07)

Validates the access-control mechanism in
[`2026-08-06-cdn-delivery-steering-design.md`](../superpowers/specs/2026-08-06-cdn-delivery-steering-design.md):
**replicate only approved content, and absence becomes the denial.** No tokens, no deny-list, no
edge compute, no per-request cost.

## The test system

| Component | Identity | Notes |
|---|---|---|
| bunny Storage Zone | `divine-delivery-test`, id 1722644, region NY | Push-based. Nothing can appear here unless a replicator puts it there. |
| bunny Pull Zone | `divine-delivery-test`, id 6289348, Volume tier | Origin is the storage zone, **not** an upstream that could auto-populate. |

Four objects were pushed, standing in for "content that passed moderation":

```
832e9a4d…3cd3f8a1.mp4        7,932,750 bytes
832e9a4d…3cd3f8a1/720p.mp4   1,375,915 bytes
50dfc675…fad30c3a.mp4        6,493,539 bytes
50dfc675…fad30c3a/720p.mp4   1,301,393 bytes
```

Deliberately **not** replicated, standing in for gated or tombstoned content: the bare-hash path and
the `/480p.mp4` rendition of the same blobs, plus three unrelated hashes.

## Result — the mechanism works

| Path | On replica? | bunny | Fastly |
|---|---|---:|---:|
| `832e9a4d…/720p.mp4` | yes | **200** | 206 |
| `832e9a4d…3cd3f8a1.mp4` | yes | **200** | 206 |
| `50dfc675…/720p.mp4` | yes | **200** | 206 |
| `832e9a4d…3cd3f8a1` (bare hash) | **no** | **404** | **206** |
| `832e9a4d…/480p.mp4` | **no** | **404** | **206** |
| three unreplicated hashes | no | **404** | — |

The fourth and fifth rows are the proof. That content is **live and served by Fastly right now**, and
bunny returns 404 purely because the replicator did not put it there. Byte counts on the served
objects matched the uploaded sizes exactly.

Nothing enforces this. There is no rule to misconfigure and no policy to evaluate — the CDN cannot
serve what its origin does not contain. That is the property the design was after: a control that
cannot be eventually-consistent-wrong.

## Origin choice is not the variable — geography is

Same probe, same paths, from Wellington:

| Edge | Origin | p50 TTFB | p95 TTFB | Mbps |
|---|---|---:|---:|---:|
| Fastly | GCS via Compute | 40 ms | 45 ms | 106 |
| bunny Volume | pull-through Fastly | 465 ms | 505 ms | 7.7 |
| bunny Volume | **bunny Storage (NY)** | 456 ms | **491 ms** | 7.9 |

A storage-backed origin and a pull-through origin are within 3% of each other. The ~490 ms is
Wellington being served from Los Angeles, as established in
[`2026-08-07-four-region-summary.md`](./2026-08-07-four-region-summary.md) — **not** an origin
effect. Swapping to a real delivery origin introduces no regression.

(Absolute throughput is lower across all three than in earlier runs; local network variance. The
relative comparison is unaffected.)

## What this does and does not establish

**Establishes**
- Absence-as-denial works end to end on real infrastructure.
- A push replica cannot be auto-populated by a pull zone, which is what makes it safe.
- Origin choice does not measurably affect cache-hit delivery.

**Does not establish**
- Behaviour when the replicator has a bug or lags. The mechanism is only as good as "replicate on
  approval, never on upload" being true in the replication code.
- Negative-cache behaviour over time. bunny will cache the 404; a short TTL and purge-on-publish are
  still required and untested here.
- Cache hit ratio on a real library. Everything measured so far is a handful of hot objects.

## Required before any traffic is steered

The canary from the steering design: a permanently-tombstoned hash that must always 404 on every
delivery CDN, polled continuously, alarming if it ever returns 200. Gated content is a very small
fraction of the corpus, so a broken exclusion produces no visible symptom until someone finds it.

## Blocked

A Backblaze B2 origin could not be tested. B2 refuses to make a bucket public without **completed
payment history** — a card on file is not sufficient:

```
{"code": "no_payment_history",
 "message": "Account has no payment history. Please make a payment before making a public bucket."}
```

Bucket `divine-delivery-probe` (id `f6f9ae1e0c0adabd9ff70517`) exists but is private and therefore
unusable as a pull-zone origin, since B2 download authorization tokens expire.

## Teardown

Temporary, delete when the campaign closes (#178):

- storage zone `divine-delivery-test` (1722644) and its four objects
- pull zone `divine-delivery-test` (6289348)
- pull zones `divine-probe-volume` (6288620), `divine-probe-standard` (6288621)
- B2 bucket `divine-delivery-probe`
