# Private archive failure diagnostics

An authenticated archive-control batch item that fails includes an optional `diagnostic` object alongside its existing `error` code. For example:

```json
{"stage":"parent_claim","kv_operation":"insert_add","kv_error":"item_bad_request"}
```

Every field comes from a fixed Rust enum. The diagnostic contains no media hash, owner, source, attempt, credential, provider message, request/response body or generation value. No additional backend read is performed. No diagnostic is added to unauthenticated responses or successful items, and each batch item gets an isolated observation scope. Responses retain the existing private/no-store headers.

The existing new-admission pause branch reports `admission_paused` without exposing the flag value or performing another configuration read.

Stages distinguish policy checks, archive reads, owner-list mutation, parent claim/release, archive admission CAS and blob reads. The operation/provider fields appear only when a typed KV error was observed at the existing I/O boundary; a parsing, policy or other non-provider failure can contain the stage alone. Expected missing-key reads and successfully recovered conflicts do not carry a stale provider class into a later failure.

Existing `retry`, `policy_denied` and `invalid` codes, authorization, reads, writes, retry bounds and generation fences are unchanged. These diagnostics identify an observed failure boundary; they do not establish its underlying cause or grant permission to reset, bypass or replace a gate.
