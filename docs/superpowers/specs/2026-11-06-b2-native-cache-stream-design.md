# Host-native playback cache fills

Live Compute 405 showed that a 256 KiB read request can return about 1 KiB.
The 8 MiB GCS fill exhausted admission CPU after 493 reads/575,531 bytes; B2
failed after 270 reads/1,502,846 bytes. Local large contiguous responses missed
this behavior. The user requires working cache fills through 32 MiB.

Use the existing Core Cache insertion-owned stream and host-native
`StreamingBody::append(origin_body)`. Prepare the cache readback stream before
taking the original response body, then append and finish the writer. The host
continues transferring the source stream after guest exit. There is no guest
origin-body fill loop, allocation proportional to the video, or full-body startup
wait. Failure classification may read one cached byte as described below.

Preserve advertised status/version/length validation before storage, 32 MiB
eligibility, provider/version identity, no early cache length, completed exact
length for future HITs, hash-surrogate purge, fresh policy/erasure authorization,
final delivery gate, TTL/no-stale behavior and outward no-store. Use a v3 key
namespace to make the changed fill lifecycle explicit.

MISS now means an origin stream selected for cache insertion. It does not assert
that an unfinished transfer is complete. A later request can be HIT only when
the host has completed collection with the expected length. Failed/truncated
streams cannot satisfy that gate. Operator acceptance still requires complete
checksum delivery followed by actual HITs and signed erasure.

Early lookup/setup/readback failures leave the source body untouched and bypass
cache. After append transfers ownership, the SDK has no independent source tee:
a finish failure is transient unavailability before delivery, and a later I/O
failure is a stream error. Do not claim uncached replay in those cases. This is
an explicit lifecycle change, not an increase to resource budgets.

The existing total/attempt deadlines still bound policy/header I/O and lookup;
the CPU admission threshold remains 25 ms. The old three-second guest-buffer
deadline no longer applies because there is no guest buffer. The host enforces
the existing backend streaming timeouts, as on ordinary uncached delivery.

Tests must send 1 KiB fragments at 8/16/32 MiB, verify response preparation
before full arrival, complete checksums, later GET/HEAD/range HITs and no partial
HIT on failure. A real Viceroy HTTP-server test must prove collection survives
guest exit, rather than testing only repeated calls inside one test VM.

The host can retain an incomplete entry after its origin fails, without granting
transactional insertion leadership to later requests. There is no failed-body
state bit. Unknown length alone never permits replacement: that would prevent healthy
fills completing under steady traffic. A full GET probes an unbounded cache
stream with one readiness-bounded byte read. An error or terminal empty stream
for a nonempty object is positive failure evidence; a byte or timeout is
inconclusive and preserves the existing producer. Only a positively failed
reader, or completed invalid entry, allows nontransactional replacement and a
bounded readback lookup on the full origin fetch already required. A fresh
128-bit internal insertion nonce binds readback to that writer; a competing
writer or failed prior entry causes untouched-origin bypass. No existing stream
is purged or stolen. An overlapping healthy stream must still finish correctly,
and a truncated fill followed by a healthy fetch must recover to a full HIT.
The nonce is unrelated to playback IDs and is never emitted to clients.

The one-byte probe is deliberately conservative, not a complete portable failed-
stream classifier. A host that replays a cached prefix before exposing failure
can leave that entry bypassed until expiry/invalidation. It never authorizes
replacement from unknown length alone. A ranged end-byte probe is rejected:
the pinned SDK may block inside get_body before a selectable handle exists.
