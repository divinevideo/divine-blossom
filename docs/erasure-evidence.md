# Erasure Evidence

Account vanish writes one Fastly KV record after required physical deletion
operations complete and before blob metadata or retry-discovery state is removed.
If that write fails, vanish fails and retains enough state to retry.

The key is `erasure:v1:<digest>`, where `digest` is SHA-256 over the domain
separator `divine-blossom-erasure-v1:` and the lowercase content hash. The value
is the fixed JSON object `{"version":1,"evidence":"vanish_erasure"}`. It stores
no account identifier, original content hash, media bytes, reason, auth event, or
request timestamp. An auditor must already possess a content hash to derive its
evidence key; the evidence namespace cannot be used to reconstruct account blob
lists.

These minimal records have indefinite retention. Their only purpose is to keep
deliberate erasure distinguishable from unrecorded absence, so expiring them
would remove the evidence they exist to preserve. The record is deliberately
small and non-identifying so retention does not preserve the erased account or
content.

Run the read-only audit for one or more already-known content hashes:

```bash
python scripts/audit_erasure.py <sha256> [<sha256> ...]
```

The script requires `FASTLY_API_TOKEN`, `KV_STORE_ID`, Google application
credentials, and optionally `GCS_BUCKET`. It reports:

- `complete`: evidence exists and no deterministic GCS object survives.
- `incomplete`: the canonical object or a deterministic thumbnail, HLS, or
  transcript object exists, whether or not evidence exists. The command exits
  nonzero.
- `not_recorded`: no evidence exists, even if every probed object is absent.

The audit is explicit-hash only. Erasure evidence is intentionally not an
enumerable replacement for deleted blob or account metadata.
