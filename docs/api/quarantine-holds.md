# Reversible media review holds

Review holds restrict media access independently of its base moderation status.
They do not delete bytes, change the base status, or expire automatically. Any
active hold denies ordinary viewers, including the owner. Authenticated admin
review routes continue to work and return private, non-cacheable responses.

Both endpoints use the existing admin bearer or admin session authentication.

## Add or release one hold

`POST /admin/api/quarantine`

```json
{
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "hold_id": "review:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "version": 1,
  "action": "hold"
}
```

`action` is `hold` or `release`. A hold ID is case-sensitive, contains 1–128
ASCII letters, digits, colons, underscores or hyphens, and should be stable across
retries. `version` is a positive integer no greater than 9007199254740991 and
must increase when changing that hold's intended state. Older versions are
no-ops; an identical retry is idempotent; equal versions with different actions
return HTTP 409. Release removes only its named hold; other holds remain.
Inactive entries retain their version indefinitely so a delayed hold cannot
override a newer release. At most 128 distinct hold IDs may be recorded per hash,
counting both active and released entries. Once full, a request introducing a
new ID returns HTTP 409 without changing the record; updates to existing IDs
still work. Releasing an ID does not free capacity. Callers must use a bounded
set of stable IDs per hash rather than allocate a new ID for every review event.
If capacity is exhausted, treat the failed hold as unapplied and escalate for
operator handling; do not treat a failed request as a delivery restriction.

The endpoint accepts an absent base blob so a hold can cover an orphaned object
or a later upload of the same content hash. Releasing the final hold exposes only
what the current base status permits. A remaining ban, age restriction, shadow
restriction or deletion continues to apply.

## Read current status

`GET /admin/api/quarantine/<sha256>`

Both endpoints return the same private, non-cacheable status shape:

```json
{
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "base_status": "age_restricted",
  "effective_status": "quarantined",
  "quarantined": true,
  "hold_ids": [
    "review:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ],
  "holds": [
    {
      "hold_id": "review:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "version": 1,
      "active": true
    }
  ]
}
```

Without holds, `effective_status` equals `base_status`. An absent base blob has
`base_status: null` and, without holds, `effective_status: "not_found"`.
`hold_ids` contains only active IDs; `holds` also includes released entries for
version-aware readback.

Hold records are stored separately from blob metadata and updated with KV
generation preconditions. Ordinary metadata/status updates cannot clear them.
Serving requests read holds without the POP-local metadata cache; unavailable or
malformed hold state fails closed. The original, thumbnail, HLS, quality variant,
transcript and audio routes share the access decision. Public GET/HEAD responses
recheck holds after routing and origin work, before response headers are emitted.
A hold observed by the final read during a slow origin request drops that
prepared response, preventing that response from refilling a public cache after
the hold's purge. This is not a cross-POP guarantee: a stale KV read may still
permit a public response and refill the cache after the purge. A failed final
hold read also drops the prepared response. An admin bearer token bypasses this final
check only when the prepared response has private, no-store browser headers and
no-store surrogate headers. Public HEAD handlers remain guarded even when the
request contains an admin bearer token.

Changes request a targeted Fastly cache purge. A successful state mutation is
not a delivery verification receipt: existing purge behavior is best effort, and
previously delivered browser copies cannot be recalled. KV propagation and purge
are not atomic: a one-time successful POST does not establish global delivery
denial. Callers must independently verify hold visibility and denied delivery in
the relevant regions, and repeat the same versioned hold POST to request another
targeted purge after stale reads converge. Status reads alone do not purge a
public response cached during propagation. No fixed delay or finite set of POP
probes establishes a global consistency bound; an activation workflow must own
continued verification and retries. Relay event visibility
is a separate control and must be coordinated by the caller. Response bodies
whose headers were already emitted may still be streaming when a hold is applied.
The final KV read and header emission are not an atomic revocation boundary.
The additional uncached hold lookup per public response has not been measured
for production latency.

This is an access restriction rather than a retention hold. Owners may still
delete or erase their own media; releasing a hold cannot recover erased bytes.

Local synthetic verification:

```sh
cargo test -p blossom-core --locked
VICEROY=/path/to/viceroy python3 scripts/run-quarantine-tests.py
VICEROY=/path/to/viceroy python3 scripts/run-quarantine-race-tests.py
```

The original reviewer-route fixture bypasses only the storage HTTP cache under
`cfg(test)`: Viceroy 0.20.1 does not implement that cache API. The fixture still
uses the actual router, admin auth, held metadata, signed origin fetch, original
bytes, Range handling and private response headers. Production cache behavior
requires a separate authorized synthetic canary before rollout, including actual
Fastly purge behavior, hold/release delivery and convergence across POPs.

The delayed-origin regression runs the production WASM binary without that test
seam. It races an authenticated hold against real local origin I/O for quality,
HLS, thumbnail and transcript GET/HEAD requests and checks the private reviewer
bypass. The shared final guard also has synthetic original/audio path and
late malformed-state coverage.
