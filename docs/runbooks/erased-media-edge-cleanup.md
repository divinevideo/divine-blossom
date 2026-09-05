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
SMOKE_ADDRESS_FILE=/secure/path/smoke-address.txt

# Drop any copy stored before activation at this POP and at the shield. The
# Fastly CLI's `purge --url` path does not evict this service's URL cache key.
printf '%s\n' "$SMOKE_BLOB_HASH" > "$SMOKE_ADDRESS_FILE"
chmod 600 "$SMOKE_ADDRESS_FILE"
envchain fastly-global scripts/purge-erased-edge-copies.sh \
  --address-file "$SMOKE_ADDRESS_FILE"

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

Create a private address file outside the repository with one exact request path
per line, following the same handling as [erasure evidence](../erasure-evidence.md):
never pass addresses on the command line, commit the file, or paste identifiers
into an issue or pull request. Paths may have one leading slash and must begin
with the content hash. Build this list only from objects confirmed absent at
Compute; an erasure record alone is not sufficient because another account may
still own or have re-uploaded the same content-addressed blob.

```bash
touch /secure/path/erased-addresses.txt
chmod 600 /secure/path/erased-addresses.txt

envchain fastly-global scripts/purge-erased-edge-copies.sh \
  --address-file /secure/path/erased-addresses.txt --dry-run

envchain fastly-global scripts/purge-erased-edge-copies.sh \
  --address-file /secure/path/erased-addresses.txt \
  > /secure/path/erased-address-purge-receipts.log
```

The script sends the `PURGE` method directly to each exact URL. It does not use
`fastly purge --url`, which can report success without evicting this host's
cached object. Every request must return HTTP 200 with a `{"status": "ok"}`
body; the first request or response failure stops the sweep. Requests are capped
at 12 requests per second to stay within the purge budget. Keep the script's
output as the private receipt log: it records a UTC timestamp and Fastly purge ID
for every address without printing the address itself. The script passes the
token to curl through a mode-0600 temporary config rather than a command-line
argument.

The address list is the operational source of truth. Do not expand hashes into
guessed aliases: HLS filenames are free-form, and guessed current forms can miss
real cached addresses while purging unrelated live aliases. A follow-up probe
from one machine would observe only its answering POP, so a clean result would
not prove global eviction and is not part of the sweep.

## Retro-check of accounts vanished before the fix

Every account vanished while the unguarded snippet was active may have edge
copies of its media. After a vanish this service holds no account-to-hash
mapping: the owner list and blob metadata are gone, and the durable
`erasure:v1` evidence can only be derived from a hash you already hold. Build
the address file from durable object-name evidence and confirm each hash is
absent through Compute before running the cleanup.

## Known residuals

- Historical or otherwise unknown aliases are not enumerable from a hash alone.
  The address-list workflow reaches only exact paths backed by retained object
  names or other durable evidence.
- A URL purge matches the exact cache key. A copy filled with a query string
  is a different key and is not covered.
- Issue #279 also asks for an automated post-purge probe in the vanish path
  that surfaces in `vanish_timing`. This change does not deliver it: the
  Compute service declares no backend for the public host, and one has to be
  created on the live service before such a probe can run. That outcome stays
  open on #279 until it lands or is split out. Until then any probe must be run
  by an operator and interpreted as POP-local evidence only.
- A single-POP probe, whether run by an operator or from that future automated
  check, cannot see other POPs' copies. Global evidence would need a probe from
  every POP or Fastly-side reporting; neither exists today.

## Cache-policy behavior after activation

Forwarding `Surrogate-Control` through the shield is also a deliberate behavior
change for responses that Compute marks `private` or `no-store`. Before this
fix, the shield stripped that policy and an edge POP could apply its generic
365-day success TTL. After activation, `vcl/fetch.vcl` sees the policy and
passes the response instead of storing it. This closes the shared-cache gap but
can increase shield-to-edge traffic for those responses.

In addition to the public purge-by-key smoke above, run the existing
[private moderation cache smoke](private-moderation-cache-smoke.md). It covers
restricted, age-restricted, banned, deleted, and authenticated/admin responses,
including repeated requests that would expose an accidental shared-cache hit.
