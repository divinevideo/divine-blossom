# Fastly deploy and rollback

Use this runbook for the two Fastly services that serve `media.divine.video`.
The outer VCL service caches responses and forwards misses to the Compute service.

| Layer | Fastly name | Service ID |
| --- | --- | --- |
| Outer VCL | `Divine.Video's website` | `ML7R82HKfmTaqTpHExIDVN` |
| Compute | `fastly-blossom` | `pOvEEWykEbpnylqst1KTrR` |

Run read-only commands with `envchain fastly-readonly`. Run write commands with
`envchain fastly-global` only after the operator approves the exact change.
The `fastly service version validate` command requires Fastly CLI 14.1 or newer;
the first recorded exercise used CLI 15.4.0. Check `fastly version` before
starting and upgrade only through the separately reviewed CLI upgrade process.

## Record rollback targets first

Do this before cloning, activating, or publishing anything:

```bash
envchain fastly-readonly fastly service version list \
  --service-id ML7R82HKfmTaqTpHExIDVN --json \
  | jq -r '.[] | select(.Active == true) | [.Number,.Comment,.UpdatedAt] | @tsv'

envchain fastly-readonly fastly service version list \
  --service-id pOvEEWykEbpnylqst1KTrR --json \
  | jq -r '.[] | select(.Active == true) | [.Number,.Comment,.UpdatedAt] | @tsv'
```

Record both active version numbers in the operator log. Do not assume that the
latest numbered version is active.

## Choose the deployment order

The compatible order depends on the change. When Compute emits metadata that a
new outer VCL version must remove, deploy outer VCL first and Compute second.
Rolling back that pair runs in reverse: Compute first and outer VCL second.

For cold-fill diagnostics, publishing Compute before the stripping VCL creates
a window where `X-Divine-Probe-*` headers can reach clients and shared cache.
The GitHub variable `FASTLY_OUTER_DIAGNOSTICS_ACTIVE=true` is only an operator
acknowledgement. CI does not inspect the live outer service.

For an edge change that depends on a new Cloud Run route or response contract,
deploy and verify the backward-compatible backend first. See
[Deployment](deployment.md#deploy-cleanup-dependencies-before-the-edge).

## Prepare an outer VCL version

Clone the active version. Substitute the active version recorded above rather
than copying the example number:

```bash
envchain fastly-global fastly service version clone \
  --service-id ML7R82HKfmTaqTpHExIDVN \
  --version <active-outer-version> \
  --json
```

Record the returned draft version, then update only the intended snippet. For
the repository's delivery snippet:

```bash
envchain fastly-global fastly service vcl snippet update \
  --service-id ML7R82HKfmTaqTpHExIDVN \
  --version <draft-outer-version> \
  --name "Client-facing headers" \
  --content vcl/deliver.vcl
```

Read the draft back and compare it with the source file:

```bash
envchain fastly-readonly fastly --quiet service vcl snippet describe \
  --service-id ML7R82HKfmTaqTpHExIDVN \
  --version <draft-outer-version> \
  --name "Client-facing headers" --json \
  | jq -j '.Content' | sha256sum

sha256sum vcl/deliver.vcl
```

Validate the complete draft in the service's Fastly configuration context:

```bash
envchain fastly-readonly fastly service version validate \
  --service-id ML7R82HKfmTaqTpHExIDVN \
  --version <draft-outer-version> \
  --json
```

Stop unless the hashes match and validation returns `"valid": true`.

## Define smoke checks before activation

Choose a currently public video that is safe for operational testing. Keep its
hash in the shell, not in the runbook or committed output:

```bash
SMOKE_BLOB_HASH=<known-public-video-hash>
```

The baseline and post-deploy checks are:

```bash
curl -sS -o /dev/null -D - \
  "https://media.divine.video/${SMOKE_BLOB_HASH}"

curl -sS -o /dev/null -D - -H 'Range: bytes=0-1023' \
  "https://media.divine.video/${SMOKE_BLOB_HASH}"

curl -sS -o /dev/null -D - https://media.divine.video/version
```

Require full playback `200`, warm ranged playback `206` with a valid
`Content-Range`, and `/version` `200`. Unmarked responses must contain no
`X-Divine-Probe-*` or `X-Divine-Diagnostic-*` headers.

For a diagnostics deployment, send a marked GET through the public host using a
fresh query key. The public response must never contain `X-Divine-Probe-*`:

```bash
MARKER="coldfill-smoke-$(date -u +%H%M%S)"
curl -sS -o /dev/null -D - \
  -H "X-Divine-Diagnostic-Probe: ${MARKER}" \
  "https://media.divine.video/${SMOKE_BLOB_HASH}?deploy-smoke=${MARKER}"
```

Do not use a marked response as collapse evidence until the outer backend's
shield configuration has been checked. A shield delivery strips the metadata
before edge delivery and prevents the fixed leader/follower labels from being
produced. Follow [Cold-fill validation](cold-fill-validation.md) and stop rather
than changing shielding during a deploy.

## Activate outer VCL

After explicit approval:

```bash
envchain fastly-global fastly service version activate \
  --service-id ML7R82HKfmTaqTpHExIDVN \
  --version <validated-draft-outer-version>
```

Read the active version back, then run all predefined smoke checks. Do not set a
GitHub acknowledgement variable until the live version and checks are correct.

## Publish Compute through CI

For the cold-fill diagnostics gate, set the acknowledgement only after the
outer version is active and verified:

```bash
gh variable set FASTLY_OUTER_DIAGNOSTICS_ACTIVE \
  --body true \
  --repo divinevideo/divine-blossom
```

If a push workflow failed only at that guard, rerun failed jobs on the original
commit rather than publishing a different checkout:

```bash
gh run rerun <workflow-run-id> \
  --repo divinevideo/divine-blossom \
  --failed

gh run watch <workflow-run-id> \
  --repo divinevideo/divine-blossom \
  --exit-status
```

The deploy job must run `fastly compute publish`. Do not replace it with separate
build and deploy commands. A routine publish does not purge the cache.

Treat every merge as a potential Compute deployment, even when no runtime source
changed. The Fastly CLI rebuilds the package and embeds build-time metadata in
the Wasm binary. That metadata can vary across builds and change the package
hash, so changed file paths do not reliably predict whether Fastly will skip an
identical package or activate a new version.

After CI succeeds, distinguish those outcomes explicitly. For a new version,
read the active Compute version and confirm its comment names the intended
commit. For an identical-package skip, confirm the previously active version is
still active; its comment will still name the commit that produced that package.
Both are valid outcomes for a merge with no runtime source changes. Run the
smoke checks in either case before proceeding. A failed job, unexpected active
version or comment, or smoke regression requires investigation. Allow several
minutes for all POPs to converge before treating one location as global
propagation evidence.

## Roll back Fastly

Rollback restores the exact versions recorded before deployment. For a paired
diagnostics change, restore Compute first so new Compute metadata stops before
the non-stripping outer VCL is restored:

```bash
envchain fastly-global fastly service version activate \
  --service-id pOvEEWykEbpnylqst1KTrR \
  --version <previous-compute-version>
```

Confirm the Compute version is active and run the smoke checks. Then, only if
the outer VCL change also needs rollback, remove the CI acknowledgement before
restoring a version that lacks the required stripping. This prevents a later
merge from treating a stale acknowledgement as proof that the VCL is active:

```bash
gh variable delete FASTLY_OUTER_DIAGNOSTICS_ACTIVE \
  --repo divinevideo/divine-blossom
```

After verifying the variable is absent, restore the previous outer version:

```bash
envchain fastly-global fastly service version activate \
  --service-id ML7R82HKfmTaqTpHExIDVN \
  --version <previous-outer-version>
```

Confirm both active versions and run the smoke checks again. Do not globally
purge as a routine rollback step. Blob responses are content-addressed, and a
global purge forces the full catalogue cold.

## 2026-08-31 rehearsal record

This procedure was first exercised while deploying commit `47d7101`:

- Outer VCL moved from version 23 to 24 and Fastly recorded version 24 active at
  `00:55:50Z`. The activation API returned in three seconds, and observed
  playback checks passed 14 seconds after the API response.
- Compute moved from version 361 (`b64db50`) to version 362 (`47d7101`). The
  rerun was requested at `01:03:35Z`; the deploy job ran from `01:03:41Z` to
  `01:04:30Z`; Fastly recorded version 362 active at `01:04:26Z`.
- Full playback returned `200`, a ranged request returned `206`, and public
  marked and unmarked responses exposed no raw probe headers.
- Direct Compute verification established that version 362 emitted the expected
  probe metadata. The public outer service removed it.
- The outer backend was found to have shield `iad-va-us` enabled. This conflicts
  with the cold-fill collapse test prerequisite, so fixed leader/follower labels
  did not appear. Observed public responses remained leak-safe and healthy; the
  collapse test was left blocked rather than changing delivery topology.
- Exact global POP convergence time was not measured. The checks prove the
  observed POPs and active-version API state, not every POP worldwide.
- A follow-up docs-, scripts-, and tests-only merge (`a25cf75`) started CI at
  `01:29:41Z`. The deploy step ran from `01:32:23Z` to `01:32:41Z` and correctly
  skipped deployment because the local and active packages were identical.
  Compute remained on version 362 and outer VCL remained on version 24, so that
  pair also remained the rollback target.
- Post-merge checks at `01:35:41Z` returned `200` for full playback, `206` with
  `Content-Range: bytes 0-1023/1361423` for ranged playback, and `200` for
  `/version`. Unmarked public responses exposed no raw probe or diagnostic
  headers.
- A second docs-, scripts-, and tests-only merge (`3ccf053`) produced the
  opposite publish result despite leaving `src/`, `blossom-core/`, Cargo inputs,
  the Rust toolchain file, and `fastly.toml` unchanged. Fastly activated Compute
  version 363 at `01:40:24Z`; version 362 became its rollback target and outer
  VCL remained on version 24.
- Fastly package metadata identified varying generated content. Version 362 had
  `mem_heap_alloc: 10-20MB`, while version 363 had `mem_heap_alloc: 5-10MB`;
  their package `files_hash` values differed. The Fastly CLI adds this
  build-time annotation to the Wasm binary. Fastly's
  [heap-allocation metadata fix](https://github.com/fastly/cli/pull/1130)
  documents that the metric can fluctuate with zero code changes and alter the
  package hash; bucketing reduces but does not eliminate that risk. Therefore
  file paths must not be used to predict whether a merge will publish.
- Version 363 smoke checks returned `200` for full playback, `206` with
  `Content-Range: bytes 0-1023/1361423` for ranged playback, and `200` for
  `/version`. Unmarked public responses exposed no raw probe or diagnostic
  headers.

No previous-version rollback was executed during this deployment. The rollback
commands above still require a deliberate drill before rollback time can be
claimed as measured.
