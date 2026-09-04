# Erased media at edge POPs

Use this runbook after a vanish or moderation purge when content that Compute
and the shield POP already return `404` for is still served with `200` from
another POP. Issue #279 records the mechanism and a live reproduction.

## Why edge copies survived a purge

The outer VCL backend `compute_origin` shields through one POP. When an edge
POP fills a blob it fetches from the shield, and the shield runs the
`Client-facing headers` snippet (`vcl/deliver.vcl`) on that hop too. Before
#279 that snippet unset `Surrogate-Key` unconditionally, so the edge stored the
object without its key. A purge by key evicts the shield's copy and the origin
returns `404` afterwards, but every edge POP that filled through the shield
keeps serving its untagged copy until its 365-day TTL expires or it is evicted.

The fix guards the strip with `fastly.ff.visits_this_service == 0`, so the
shield forwards the key and edge copies filled after activation are purgeable
by key. Fastly still removes `Surrogate-Key` from client responses on its own
unless the request carries `Fastly-Debug`.

## Activate the guarded deliver snippet

The outer VCL is not deployed from git. Follow
[Fastly deploy and rollback](rollback.md): record the active outer version,
clone it, update the `Client-facing headers` snippet from `vcl/deliver.vcl`,
compare hashes, validate, then activate after approval. No Compute publish is
involved, and no cache purge is part of activation.

### Verify from a non-shield POP

Run these from a machine that Fastly routes to a POP other than the shield.
`x-served-by` lists the shield node first and the edge node second when the
request went through the shield; a single node means this machine reached the
shield POP itself, and the check below cannot distinguish the two hops from
there.

```bash
SMOKE_BLOB_HASH=<known-public-video-hash>

# Drop any copy stored before activation at this POP and at the shield.
envchain fastly-global fastly purge --url "https://media.divine.video/${SMOKE_BLOB_HASH}"

# Fill through the shield (MISS), then confirm the edge holds it (HIT).
curl -sSI "https://media.divine.video/${SMOKE_BLOB_HASH}" | grep -iE '^(x-cache|x-served-by|age):'
curl -sSI "https://media.divine.video/${SMOKE_BLOB_HASH}" | grep -iE '^(x-cache|x-served-by|age):'

# Purge by key, the path the vanish and moderation code use.
envchain fastly-global fastly purge --key "${SMOKE_BLOB_HASH}" \
  --service-id ML7R82HKfmTaqTpHExIDVN

# The edge copy must be gone: MISS with age 0.
curl -sSI "https://media.divine.video/${SMOKE_BLOB_HASH}" | grep -iE '^(x-cache|x-served-by|age):'
```

Before the fix the last request returned `X-Cache: HIT` with a growing `age`,
which is the failure #279 reproduced. After the fix it returns `X-Cache: MISS`.
The smoke blob is public, so refilling it costs one origin fetch.

## One-time cleanup of copies filled before activation

Copies stored before activation stay untagged, so a purge by key cannot reach
them. Purge them by URL, which reaches every POP regardless of tags. Do not run
`fastly purge --all` on the outer service for this: it drops the whole
catalogue and refetches every video through Compute and GCS at once.

Create a private hash file outside the repository with one erased content hash
per line, following the same handling as
[erasure evidence](../erasure-evidence.md): never pass hashes on the command
line, commit the file, or paste identifiers into an issue or pull request.

```bash
touch /secure/path/erased-hashes.txt
chmod 600 /secure/path/erased-hashes.txt

envchain fastly-global scripts/purge-erased-edge-copies.sh \
  --hash-file /secure/path/erased-hashes.txt --dry-run

envchain fastly-global scripts/purge-erased-edge-copies.sh \
  --hash-file /secure/path/erased-hashes.txt
```

For each hash the script purges the bare, `.mp4`, and `.jpg` URL forms, then
fetches the bare URL once and requires `404`. It exits non-zero when any purge
or probe fails. `--probe-only` repeats the probe without purging.

The probe observes one POP: the one that answers this machine. It cannot see
copies held by other POPs, so a clean run is evidence for that POP only. The
URL purge itself is global; the probe is a spot check, not proof of global
eviction.

## Retro-check of accounts vanished before the fix

Every account vanished while the unguarded snippet was active may have edge
copies of its media. After a vanish this service holds no account-to-hash
mapping: the owner list and blob metadata are gone, and the durable
`erasure:v1` evidence can only be derived from a hash you already hold. Build
the hash file from the caller's own records of the vanish requests it issued,
then run the cleanup above over that file.

## Known residuals

- Derivative URL forms under the same hash (`.hls`, `/hls/*`, `.vtt`, quality
  variants) that were filled before activation are also untagged. They are not
  enumerable from a hash alone, so they age out at their TTL unless the
  operator knows a specific URL was fetched and purges it by URL.
- A URL purge matches the exact cache key. A copy filled with a query string
  is a different key and is not covered.
- A single-POP probe, whether run here or from a future automated check in the
  vanish path, cannot see other POPs' copies. Global evidence would need a
  probe from every POP or Fastly-side reporting; neither exists today.
