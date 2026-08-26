# Cold-fill validation

Use `scripts/probe-cold-blob.sh` to measure the bare-blob cold path from a
representative client location. The probe invalidates three fresh synthetic
objects by surrogate key, measures anonymous and ephemeral-credential requests,
then starts concurrent anonymous requests against a third newly cold object.
It never globally purges a cache and does not print the object hash.

## Prerequisites

- Run from the representative US region being evaluated. Set
  `EXPECTED_POP_REGEX` to the expected `X-Served-By` POP pattern rather than
  accepting an arbitrary location.
- Upload three distinct, non-user synthetic objects that are valid for public
  and NIP-98 GET requests. Do not read them before the probe: an earlier read
  may populate the FOS replica, and a surrogate purge does not delete that
  replica. Each object must be under 32 MiB and uploaded through the normal path
  that writes its size to KV metadata; otherwise write-back is ineligible and
  the probe will fail rather than claim phase coverage. Pass the hashes through `ANONYMOUS_BLOB_HASH`,
  `CREDENTIALED_BLOB_HASH`, and `CONCURRENT_BLOB_HASH`; do not put them in a
  command transcript, result document, or commit.
- Install `curl`, `nak`, and the Fastly CLI. `nak curl` uses an ephemeral signer,
  so no user key or reusable credential is needed.
- Confirm the `compute-diagnostics` sink is configured before the run. Client
  timings alone cannot establish how many requests reached Compute or origin.
- Confirm the outer service has already activated this revision's
  `vcl/deliver.vcl` before publishing the Compute package. Compute emits cached
  `X-Divine-Probe-*` metadata; publishing it before the delivery-time stripping
  logic creates a window where those internal headers can reach clients. Do not
  send any probe request until both versions are active.

## Run

The script performs targeted invalidation against both cache layers because the
outer VCL service and Compute service have separate surrogate-key namespaces.

```bash
ANONYMOUS_BLOB_HASH=<fresh-test-object-a> \
CREDENTIALED_BLOB_HASH=<fresh-test-object-b> \
CONCURRENT_BLOB_HASH=<fresh-test-object-c> \
EXPECTED_POP_REGEX='^(IAD|DFW|SJC)' \
CONCURRENCY=8 \
  scripts/probe-cold-blob.sh
```

The default sends full-object requests so successful FOS-miss/GCS responses are
eligible for body buffering and write-back. Set `RANGE` only for a separate
range-path experiment; doing so intentionally makes those two phases absent.

The output reports only status, timing, fixed source/cache labels, serving POP,
and fixed probe roles. It reports `distinct_compute_fills` and
`distinct_gcs_fills` from all concurrent client responses. `vcl_deliver`
compares each request marker with the cached fill leader and emits only a fixed
`leader` or `follower` role; it strips the marker and cached probe metadata before
delivery. One leader establishes one Compute response filled the request group.
Multiple leaders establish duplicate Compute responses, while the source and FOS
labels identify how many also duplicated the GCS fill. This response set is exhaustive for the requests
the script started and does not depend on Pub/Sub pull completeness.

After the diagnostic records arrive, an authorized operator can read the sink
without acknowledging messages:

```bash
REQUEST_PREFIX=<collapse-prefix> scripts/tail-edge-errors.sh 500
```

Use the sink records for phase durations, not for an exhaustive request count.
Pub/Sub pull can return a subset of available messages, so one matching record
does not prove that no other fill occurred. Zero matching records is likewise
inconclusive and must not be reported as successful telemetry.

## Diagnostic interpretation

Sampled records contain no media path/hash, URL, pubkey, authorization value,
IP, or account identifier. `authorization_present` is only a boolean path label.

- `fos_lookup_ms`: time through the FOS lookup, including its response headers.
- `gcs_fetch_ms`: time to GCS response headers after a mirror miss.
- `buffer_ms`: time spent reading the complete eligible body into Compute memory.
- `write_back_ms`: time spent writing the verified body to FOS.
- `duration_ms`: full Compute request duration, including metadata and access checks.
- `storage_cache`: normalized internal cache state when Fastly exposes one.

The request's syntactically bounded `coldfill-*` marker is an untrusted
measurement hint, not authorization. It is stored as internal metadata on the
shared fill so `vcl_deliver` can compare later requests with the cached leader.
Every delivery strips that marker and the other cached probe metadata. Clients
receive only fixed `role`, `source`, `fos_outcome`, `buffer`, and `write_back`
labels created during delivery; no marker, object identifier, or user identifier
reaches a client.

The sink records every verified FOS-miss/GCS cold fill and every successful
bare-blob response taking at least 750 ms. This captures cold probes even when
they are fast while bounding steady-state diagnostic volume.

Do not select a production change before the representative run. Compare phase
distributions for anonymous and credentialed requests first, then make only the
change supported by the dominant measured phase. If no phase dominates or the
evidence is inconclusive, record that result rather than changing delivery.
