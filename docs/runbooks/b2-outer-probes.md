# B2 outer execution probes

This source-only diagnostic supplies bounded synthetic evidence for the B2
outer CDN acceptance operator. It is not native playback telemetry, a view
count, a ClickHouse producer, or proof that a user rendered a frame. It does
not create or change a logging endpoint. No activation has been verified by
this document.

## Contract

On a GET/HEAD to a declared B2 delivery host and original path, a request may
carry `X-Divine-B2-Probe: b2outer-<lowercase UUID v4>`. The operator generates a
new random marker for each request and caps its total request/byte budget.
This public marker is an opt-in diagnostic, not an authentication secret or a
rate limit. No records are emitted for requests with Authorization/Cookie,
invalid markers, unrelated hosts, non-original paths or shield delivery hops.

`vcl/recv.vcl` generates a fresh outer UUID at client ingress, overwriting a
caller's request ID. A restart and shield continuation preserve that UUID.
Client-facing `X-Request-Id` correlates with the final record. The probe UUID
is separate from that server UUID; neither is a native adapter's local
request UUID. Native correlation remains load-level and is outside this
synthetic schema.

The new managed `log_b2_probe.vcl` writes
`divine.blossom.b2_outer_probe.v1`, `phase=log`, to the existing
`vcl-error-diagnostics` endpoint. Required operator precondition:
`placement=none`; keep its dedicated topic/permissions and all existing 5xx
snippets intact. The payload contains only timestamp, request/probe UUIDs,
method/status, actual final cache state, backend_fetch, restart count,
client-edge visit count, elapsed milliseconds and observed body bytes. It
contains no URL, content hash, account identity, IP, load ID, cookies, tokens,
raw headers or response body.

`backend_fetch` is a per-request **boolean**, not a count of Compute or B2
calls:

| Final state, with zero restarts | backend_fetch | Meaning |
| --- | --- | --- |
| HIT or HIT-CLUSTER | 0 | This ordinary outer cache hit did not take a backend path. |
| MISS/PASS, optionally -CLUSTER | 1 | This outer request took a backend path, which may target a shield. |
| Any other state, or any restart | null | Unknown; must not pass a zero-fetch assertion. |

WAIT, REFRESH, STALE, SYNTH and error cases remain unknown, even when a
simplified X-Cache header says HIT. An edge MISS can be a shield HIT; 1 never
means one Compute execution. The record is emitted on the client-facing hop
only (`ff_visits=0`). Clustering and shielding are different: a CLUSTER suffix
is not evidence of a shield request.

This deliberately does not initialize a request counter to zero and mutate
it in miss/pass: fetch-node request-header changes do not propagate back to
the clustered delivery node. Such a counter could falsely claim zero.
See Fastly's [request-header semantics](https://www.fastly.com/documentation/reference/vcl/variables/client-request/req-http/)
and [final cache states](https://www.fastly.com/documentation/reference/vcl/variables/miscellaneous/fastly-info-state/).

## Consumers and release checks

Existing error schemas stay unchanged. The repository tail helper accepts
schema-tagged records generically; its combined status/duration totals are
now mixed diagnostic samples, not an error census. Filter by schema before
comparing 5xx counts. This new schema is intentionally incompatible with the
performance subscriber's `divine.media.delivery.v1`; do not send it to the
view/QoE sink or pretend it has durable ClickHouse acceptance. Reconfirm any
out-of-repository consumers before activation.

1. Release owner reviews the complete combined snippet set and validates a
   cloned Fastly draft. Python source contracts do not compile or execute VCL.
2. Preserve existing logging placement/format/permissions; no endpoint write
   is needed. Compare actual current settings before activation.
3. Send one bounded owned-fixture cold request and two warm requests with
   different probe markers but deliberately repeated caller IDs. Correlate
   their distinct returned server IDs with actual final records. A warm pass
   requires ordinary HIT, backend_fetch0, restart0, ff_visits0 and correct
   response SHA/range behavior. Verify shield behavior separately.
4. Confirm invalid/no-probe and unrelated requests do not add probe records;
   existing 5xx records still emit. Log delivery may be delayed, duplicated or
   missing. A missing record is unknown, never zero. Retry log collection only
   within a finite operator budget; do not retry media until green.
5. Exercise restart/error/wait/refresh cases when the controlled harness can
   induce them. They must be null/unknown, never a successful bypass claim.
   Verify the actual Fastly compiler accepts the new snippet before any live
   media acceptance. No provider validation was run for this source patch.

Observed bytes in `vcl_log` are bytes written by Fastly, including partial
responses; they do not prove client receipt, complete download or first
frame. The operator must verify full response size/SHA separately. Cache
purge/erasure and in-flight invalidation have their own acceptance gates.

Offline checks:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.tests.test_b2_outer_probe
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests
```
