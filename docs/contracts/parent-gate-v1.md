# Parent storage exclusion v1

Source contract only. `b2_parent_gate_enabled` defaults off. The dedicated
`b2_storage_coordination_token` secret is not provisioned by this code. Only the
durable PostgreSQL authority may hold it; processing workers hold their separate
PG credential. Admin, webhook and purge-drain credentials grant no gate access.

Fixed POST routes: `/admin/api/b2-parent-gate/claim`, `/check`, `/inspect`,
`/release`. Requests and responses are capped at8KiB and private/no-store.
Authentication precedes body reads. Missing config/secret/storage fails closed.
Responses omit raw policy records, provider/SDK errors and credential values.

Common JSON fields: `version:1`, lowercase64hex `parent`, server-issued32hex
`attempt_id`. Claim additionally requires `purpose:"existing_family"` and
`expected:{state:"missing"}` or
`expected:{state:"released",generation:"R",settled_attempt_id:"previous"}`.
Check/release require `generation:"G"`; inspect has only common fields.
Unknown fields/combinations are rejected. `original_write` is unavailable until
a trusted authenticated PG upload-intent hook exists; caller MIME and owner
hints cannot select it. No caller `gate_held` field exists.

The KV key remains `b2-sync:v1:{parent}`. Recognized exact schemas:

```json
{"state":"copying","attempt_id":"A"}
{"state":"erasing"}
{"state":"released","version":1,"settled_attempt_id":"A","released_from_generation":"G"}
```

Legacy copying identities1..128 printable nonspace ASCII bytes remain exclusion.
Generation strings are canonical positive u64 decimals, used only for equality.
Missing is established by actual not-found, never null/empty/malformed bodies.

| From | Transition | Precondition |
| --- | --- | --- |
| Missing | copying A | Add-only + current uncached eligible-family policy |
| Released at R | copying B | exact-generation conditional insert R, different settled identity + policy |
| Copying A at G | released(A,G) | exact owner and conditional insert G, PG has positively settled/drained all effects |
| Missing | erasing | trusted existing erase path, Add-only |
| Released at R | erasing | trusted erase path, conditional insert R |
| Erasing | erasing | recognized permanent intent; provider erasure still needs proof |

No TTL, read/delete sequence or unconditional delete implements these transitions.
Conflicts do not trigger reacquisition loops. Erasing, malformed and unknown
states never grant write authority. Old copying stays reserved until its actual
writer is settled; elapsed lease time does not establish settlement.

Claim/check read canonical video active or legally pending metadata, tombstone,
quarantine and owner/reference vanish gates uncached. This is copy eligibility,
not viewer approval. Claim rechecks policy after mutation; any denial retains
the gate. Release may relinquish a positively settled writer despite policy
revocation, so erasure can proceed. Check/inspect are observations, not ongoing
current-source authority. All original writers/dedupe/promotions must join the
same exclusion before producer activation; canonical HEAD must match the exact
assignment, with pinned bytes, checksum/probe and final policy/source rechecks.

Mutation timeout is uncertain, never proof of nonexecution. PG commits the exact
claim intent before one HTTP send and retains it forever, preventing resurrection
after any intermediate owners. Inspect matching copying can recover its actual
generation; matching released(A,G) can positively observe that release. Missing
or a successor does not acknowledge cancellation or authority over that successor.
No automatic mutation replay. Lease expiry cannot release or settle effects.

The PG successor exposes no worker release or provider-dispatch permit until a
positive settlement/quiescence contract exists. This bridge trusts only that
dedicated PG authority to invoke release after its durable checks, never a worker
boolean or broad admin credential. Deploying the bridge alone does not authorize
the release caller or a runtime flag.

Compatibility: canary delivery accepts strict released as no active copy after
its normal policy checks; erasure CASes released to permanent erasing before
deleting provider versions. The mirror operator CLI has explicit
`--released-parent-gates`, default off; old mode remains pending on sentinels.
New mode uses conditional PUT to release/reacquire and fixes present-null gate
handling. Existing legacy mode retains its generation-conditional control-plane
DELETE until root drains/disables that fleet; it is not protocol compatibility.
Every external runner and all consumer instances must be inventoried/upgraded
before any sentinel emitter is enabled. Source grep is not fleet proof.

Rollback after emission must preserve sentinel readers and CAS erasure support:
stop admissions, retain gates/uncertain effects, positively drain/reconcile.
Never delete sentinels or treat unknown states as absent to recover availability.
Provider-backed privacy/race and paired playback acceptance remain separate.

Run `python3 scripts/run-parent-gate-tests.py` with a local Viceroy binary for
real KV and route proofs. Only synthetic local config/secret/KV stores are used.
