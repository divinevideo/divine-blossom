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
  replica. Pass the hashes through `ANONYMOUS_BLOB_HASH`,
  `CREDENTIALED_BLOB_HASH`, and `CONCURRENT_BLOB_HASH`; do not put them in a
  command transcript, result document, or commit.
- Install `curl`, `nak`, and the Fastly CLI. `nak curl` uses an ephemeral signer,
  so no user key or reusable credential is needed.
- Confirm the `compute-diagnostics` sink is configured before the run. Client
  timings alone cannot establish how many requests reached Compute or origin.

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

The output reports only status, timing, cache state, serving POP, and generated
probe IDs. Keep the final `collapse_prefix`.

After the diagnostic records arrive, an authorized operator can read the sink
without acknowledging messages:

```bash
REQUEST_PREFIX=<collapse-prefix> scripts/tail-edge-errors.sh 500
```

Exactly one `divine.blossom.blob_fetch.v1` record with `sample_reason` equal to
`cold_fill` or `slow_cold_fill` for the concurrent prefix establishes that the
request group produced one GCS fill. More than one establishes duplicate GCS
fills. Zero is inconclusive: it means the sink
or request-ID path did not provide evidence and must not be reported as
successful collapsing.

## Diagnostic interpretation

Sampled records contain no media path/hash, URL, pubkey, authorization value,
IP, or account identifier. `authorization_present` is only a boolean path label.

- `fos_lookup_ms`: time through the FOS lookup, including its response headers.
- `gcs_fetch_ms`: time to GCS response headers after a mirror miss.
- `buffer_ms`: time spent reading the complete eligible body into Compute memory.
- `write_back_ms`: time spent writing the verified body to FOS.
- `duration_ms`: full Compute request duration, including metadata and access checks.
- `storage_cache`: normalized internal cache state when Fastly exposes one.

The sink records every verified FOS-miss/GCS cold fill and every successful
bare-blob response taking at least 750 ms. This captures cold probes even when
they are fast while bounding steady-state diagnostic volume.

Do not select a production change before the representative run. Compare phase
distributions for anonymous and credentialed requests first, then make only the
change supported by the dominant measured phase. If no phase dominates or the
evidence is inconclusive, record that result rather than changing delivery.
