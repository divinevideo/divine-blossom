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

## Also validated on a Backblaze B2 origin

The same test was repeated with the full production-shaped topology —
**GCS (authoritative) → B2 (approved-only replica) → bunny Volume → viewer** — using public bucket
`divine-delivery-probe` as the pull-zone origin. Identical result:

| Path | On replica? | bunny | Fastly |
|---|---|---:|---:|
| `832e9a4d…/720p.mp4` | yes | **200** | 206 |
| `832e9a4d…3cd3f8a1.mp4` | yes | **200** | 206 |
| `832e9a4d…3cd3f8a1` (bare hash) | **no** | **404** | **206** |
| `832e9a4d…/480p.mp4` | **no** | **404** | **206** |

## Origin choice is not the variable — geography is

Same probe, same paths, from Wellington, across three completely different origin types:

| Edge | Origin | p50 TTFB | p95 TTFB | Mbps |
|---|---|---:|---:|---:|
| Fastly | GCS via Compute | 40 ms | 44 ms | 108 |
| bunny Volume | pull-through Fastly | 451 ms | 483 ms | 7.9 |
| bunny Volume | bunny Storage (NY) | 452 ms | **474 ms** | 8.0 |
| bunny Volume | **Backblaze B2 (US-West)** | 461 ms | 504 ms | 7.9 |

**All three bunny origins land within 6% of each other.** The ~480 ms is Wellington being served
from Los Angeles, as established in
[`2026-08-07-four-region-summary.md`](./2026-08-07-four-region-summary.md) — not an origin effect.

This is a useful simplification: **on cache hits, origin choice does not affect delivery
performance at all.** The origin decision can therefore be made purely on storage cost, durability,
egress terms, and lock-in — the criteria in
[`../cdn-object-storage-vendor-notes.md`](../cdn-object-storage-vendor-notes.md) — without a
performance trade-off to weigh against them.

Cache-*miss* behaviour is a separate question and is not settled by this: a distant origin still
costs on fill. Measured separately, bunny's miss penalty on a warm-region zone was 1.0–1.9× the warm
TTFB, so fills are efficient, but that was against a Fastly origin rather than B2 or R2.

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

## Note on the B2 public-bucket gate

New B2 accounts cannot create or convert a public bucket until they have **completed payment
history** — a card on file is not sufficient, and the error is `no_payment_history`. This blocked
the B2 origin test until a payment was made. Worth knowing before planning around B2, since a
private bucket cannot back a pull zone (B2 download authorization tokens expire).

## Teardown

Temporary, delete when the campaign closes (#178):

- storage zone `divine-delivery-test` (1722644) and its four objects
- pull zone `divine-delivery-test` (6289348)
- pull zones `divine-probe-volume` (6288620), `divine-probe-standard` (6288621)
- pull zone `divine-b2-test` (6289364)
- B2 bucket `divine-delivery-probe` (`f6f9ae1e0c0adabd9ff70517`) and its four objects
