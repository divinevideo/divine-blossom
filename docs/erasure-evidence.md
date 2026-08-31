# Erasure Evidence

Account vanish writes one Fastly KV record after the required main-object origin
and derivative deletes succeed and before blob metadata or retry-discovery state
is removed. If that write fails, vanish fails and retains enough state to retry.
This record is evidence that the valid blob's required physical erasure phase
completed.

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

The record is per valid blob, not per account. It does not encode account-level
completion or malformed-list exceptions. The completion response reports those
exceptions, and a separate best-effort audit-log write records a safe fingerprint,
so this KV evidence alone cannot prove that an account completed without skips.

Create a private hash file outside the repository, with one already-known
content hash per line, then run the read-only audit:

```bash
umask 077
touch /secure/path/vanish-hashes.txt
chmod 600 /secure/path/vanish-hashes.txt
python scripts/audit_erasure.py --hash-file /secure/path/vanish-hashes.txt
```

Do not pass hashes on the command line, commit the file, or paste identifiers
into logs. The audit output is aggregate-only.

The script requires `FASTLY_API_TOKEN`, `KV_STORE_ID`, Google application
credentials, and optionally `GCS_BUCKET`. It reports:

- `complete`: valid evidence exists and no GCS object with the hash prefix
  survives.
- `incomplete`: valid evidence exists but an object survives. The command exits
  nonzero.
- `present_unrecorded`: an object survives without valid evidence. The command
  exits nonzero; this may be content that was never vanished or was re-uploaded.
- `not_recorded`: no evidence exists and every probed object is absent.
- `invalid_evidence`: a record exists but has an unexpected value. The command
  exits nonzero.
- `probe_error`: Fastly or GCS probing failed after retries. The command exits
  nonzero and must be rerun.

The audit is explicit-hash only. Erasure evidence is intentionally not an
enumerable replacement for deleted blob or account metadata.
