# Deployment

Some of this repository deploys itself and some of it does not. After tests pass,
merging upload-service changes to `main` deploys that service, and every merge
verifies its batch-cleanup contract before publishing the Fastly edge service.
Most other Cloud Run services do not ship that way; each one is a script someone
runs by hand.

The VCL caching layer is not Compute. Files under `vcl/` are the source for
snippets on the outer Fastly VCL service; the Compute publish job does not
update them. `python3 scripts/sync_outer_vcl.py diff` compares git to the
active version. `python3 scripts/sync_outer_vcl.py apply` clones that version,
upserts the snippets in `vcl/snippets.json`, and validates the draft. Making
the draft live is a separate operator step; see [Outer VCL snippets](outer-vcl.md).
CI still republishes the Compute service after any merge to `main`, including a
VCL-only merge. It does not purge after a routine publish.

The ordered upload-service job is the exception to that asymmetry. If its deploy
or readiness check fails, the automatic Fastly publish is skipped.

## What ships automatically

`.github/workflows/ci.yml` runs on every push to `main`. After the `test` job
passes, it deploys:

- the upload service to Cloud Run when its source changed
- the upload-service contract readiness check on every edge publish
- the edge service to Fastly (`fastly compute publish`) only after that check
- `process-blob` to Cloud Run
- the container image to GHCR

The Fastly publish targets the Compute service. It does not deploy or purge the
outer VCL caching service. A full purge is a separate manual workflow input.
See [Fastly 5xx diagnostics](fastly-5xx.md) for the separate logging endpoint
and VCL activation work required by the diagnostic sources in this repository.
See [Fastly deploy and rollback](rollback.md) for the two-layer procedure.

## What ships by hand

These services are not deployed by CI. Each is a script you run yourself.

| Service | Script |
| --- | --- |
| `divine-transcoder` | `cloud-run-transcoder/deploy.sh` |
| Parakeet ASR | `cloud-run-asr-parakeet/deploy.sh` |

`process-blob` also has `scripts/deploy-cloud-function.sh` for manual deploys.
It targets the same Cloud Run service that CI deploys on merge, so treat the CI
job and the manual script as competing deploy paths for one service, not two
separate services.

## Deploy cleanup dependencies before the edge

The edge treats Cloud Run's authenticated `/delete-blob` and `/delete-blobs`
responses as required erasure evidence. Account vanish uses `/delete-blobs` and
requires one typed result for every requested hash. For changes to that contract:

1. Verify an authenticated request reaches `/delete-blob/health`, sends the edge
   config store's `gcs_bucket` value in `X-Expected-GCS-Bucket`, and returns a
   typed `completed` response. This verifies route availability, secret parity,
   and bucket parity; it is not a storage-permission probe. A `401` means the
   Fastly `webhook_secret` and Cloud Run `WEBHOOK_SECRET` bindings do not match;
   a `409` means the two services name different buckets. Stop rather than
   merging the edge in either case.
2. The `main` workflow deploys `cloud-run-upload` and verifies
   `/delete-blobs/ready` before publishing edge code that calls it. The same
   readiness body advertises the authenticated `/probe-delivery` endpoint the
   vanish path calls after a purge (`delivery_probe:
   authenticated-v1`); the workflow asserts it before publishing the edge so
   the probe never calls a missing route. Each real cleanup request also
   asserts that Cloud Run and the edge use the same GCS bucket before Cloud
   Run may report deletion complete.

Do not put either secret value in the verification command, logs, screenshots,
or pull-request text. Use the approved secret-injection tooling for the operator
environment.

## `webhook_secret` authority and rotation

GCP Secret Manager secret `webhook_secret` in `rich-compiler-479518-d2` is the
authoritative readable copy. There are three write-only copies:

| Copy | Consumer | Mechanism |
| --- | --- | --- |
| Fastly Secret Store `blossom_secrets` entry `webhook_secret` | the edge itself, which compares against this value | Fastly secret store |
| Cloudflare Worker `divine-moderation-service` binding `BLOSSOM_WEBHOOK_SECRET` | that Worker only | per-Worker secret (`wrangler secret put`) |
| Cloudflare Secrets Store `ef490704b12a4feb91c7feb51229c364` entry `BLOSSOM_WEBHOOK_SECRET` | Worker `divine-relay-manager`, prod and staging | account-level Secrets Store, bound in `worker/wrangler.prod.toml` and `worker/wrangler.staging.toml` |

The two Cloudflare Workers hold the value by *different* mechanisms, so updating
one does not update the other. Read that table before assuming a Cloudflare
update is a single step; it is two, in two different places.

Never generate a replacement in
Fastly or Cloudflare; generate a 64-character lowercase hex value directly into
a new GCP version, without a trailing newline, and pipe that exact version to
every write-only store. The missing newline is required: Fastly trims the value
it reads from its store, while the upload service compares the raw
`WEBHOOK_SECRET` environment value. A newline in GCP would therefore make those
copies disagree.

The rotated value crosses every one of these directions:

- Cloudflare moderation Worker -> Fastly `/admin/moderate`
- Cloudflare `divine-relay-manager` -> Fastly `/admin/api/blob/{sha256}/content`,
  which proxies blocked media to moderators. A stale copy here does not raise an
  alert; it silently breaks moderator preview of blocked media.
- Fastly -> upload service `/delete-blob`
- Fastly -> transcoder `/audio/extract`
- transcoder -> Fastly `/admin/transcode-status`
- transcoder -> Fastly `/admin/transcript-status`

Fastly sends the value as a bearer token to `/audio/extract`, but that handler
does not currently validate the header. An extraction probe verifies that the
direction still works after the Fastly update; it does not prove secret parity
with the transcoder. The value is also admin-equivalent at the edge on routes
protected by `validate_admin_auth`: those bearer clients may use either
`webhook_secret` or `admin_token`. Inventory and move every client that uses
`webhook_secret`, not only the moderation Worker.

The two Fastly callback routes accept either `webhook_secret` or the separate
`transcoder_webhook_secret`, but the transcoder sends its `WEBHOOK_SECRET` value.
`blossom-upload-rust` and `divine-transcoder` resolve the GCP secret as
`WEBHOOK_SECRET` when an instance starts. Updating `:latest` does not change an
already-running instance.

Rotate forward in this order:

1. Record the current GCP version number. Create the new version without a
   trailing newline, keep the old version enabled, and update the canonical
   `blossom-webhook-secret-prod` mirror from that exact new version. Inventory
   every bearer client using `webhook_secret` and prepare each client update.
   Confirm the client list against the repositories, including both Cloudflare
   Workers in the table above and the service callers in the directions list;
   do not assume the moderation Worker is the only Cloudflare consumer.
   Search across the organization's repositories for `BLOSSOM_WEBHOOK_SECRET`,
   `webhook_secret`, and the Cloudflare Secrets Store id in the table, rather
   than limiting the inventory to the already-known Workers.
2. Schedule the rotation for a low-activity window. Before changing any
   write-only copy, read `STATUS_QUEUE_ENABLED` from the serving transcoder
   revision and record active derivative work. If the queue is enabled, capture
   the [derivative-status queue](../derivative-status-queue.md) task names,
   schedule times, depth, and oldest-task age so failures can be mapped back to
   a job. Do not pause that queue: it continues to accept tasks while paused and
   would accumulate rather than drain. This repository has no dispatch-pause
   control, so running old revisions and already-created tasks can retain the
   old credential and later receive `403` from Fastly. Record affected jobs for
   reconciliation. Then update every caller from step 1, starting with
   Cloudflare, and immediately update Fastly from the new GCP version. Record
   all write times.
3. Poll `/admin/moderate` with the new credential and a valid but incomplete
   `{}` payload. Continue only when the edge reaches payload parsing and returns
   `400 Missing 'sha256' field`; `403` means the new Fastly value has not
   converged.
4. Create fresh revisions of both Cloud Run services with a config-only
   `gcloud run services update` that reapplies
   `WEBHOOK_SECRET=webhook_secret:latest` and uses a unique revision suffix.
   Do not run the source deploy scripts for this step. This preserves the
   current images and other configuration while making each new instance
   resolve the new value. Follow [Check live configuration before running a
   deploy script](#check-live-configuration-before-running-a-deploy-script),
   then confirm traffic is serving from the new revisions and is not pinned to
   an older revision.
5. Verify every direction above. Send a real moderation notification; verify
   moderator preview through `divine-relay-manager` exercises the edge's
   `/admin/api/blob/{sha256}/content` route successfully; run the
   authenticated [`/delete-blob/health` parity check](#deploy-cleanup-dependencies-before-the-edge)
   with `X-Expected-GCS-Bucket`; exercise a controlled audio extraction through
   the edge as a reachability check, not a secret-parity check; and confirm new
   transcode and transcript jobs on the fresh revision callback to Fastly
   without `401` or `403`. Also verify the funnelcake janitor's separate
   `admin_token` still authenticates an admin read route. Inspect the edge,
   Worker, upload, and transcoder logs. When `STATUS_QUEUE_ENABLED=true`, inspect
   Cloud Tasks logs and correlate failures with the task list captured in step
   2. A `401` or `403` on moderation, deletion, or a direct callback from a new
   transcoder revision is a rollback signal. A callback from an old revision or
   a task created before the rotation can fail with the stale credential.
   For a lost transcode callback, call the authenticated
   `/admin/api/reset-stuck-transcodes` flow with `older_than_secs: 0`, the full
   affected hash as `hex_prefix`, and `dry_run: true`. Paginate through
   `next_user_offset`; then repeat the matching page with `dry_run: false` and
   request the derivative again if the result reset it to `Pending`. For a lost
   transcript callback, confirm the affected hash in the admin dashboard and use
   its **Regenerate Transcript** action, which posts that exact hash with
   `force: true`. Observe a successful fresh callback before considering either
   job reconciled. Do not use rollback as a retry for a callback that has
   already been lost.
6. Disable the old GCP version only after every probe passes and every stale
   callback observed in step 5 has been reconciled. If reconciliation is still
   incomplete, leave the old GCP version enabled and escalate that job. Roll
   back the rotation only when a new-credential path fails.

There is no zero-mismatch order because these consumers do not all accept both
old and new values. Cloudflare goes first so both callers stop sending the old
value before Fastly can begin accepting the new one. This deliberately makes
moderation and relay-manager's moderator media preview fail closed until Fastly
accepts the new callers; it does not promise a shorter outage. Moving Fastly
first would instead leave an unpredictable
window in which the edge may switch while a Cloudflare caller still sends the old value.
Once Fastly converges, accept a bounded edge-to-Cloud-Run mismatch while the two
fresh revisions start; keeping the old GCP version enabled preserves rollback
but does not make running services dual-accept both values.

Rollback disables the new GCP version, re-enables the recorded old version,
restores all three write-only copies and the `blossom-webhook-secret-prod` mirror from
that exact old version, and creates fresh revisions of both Cloud Run services
again. Repeat the same direction checks before disabling any superseded version.

The 2026-08-31 rotation's Cloudflare and Fastly API writes were 18 seconds
apart, but the edge did not accept the new value until a probe 88 seconds after
the Cloudflare write. Plan the mismatch window around verified edge acceptance,
not the secret-store API completion time.

On 2026-09-30 `divine-relay-manager` was found holding a stale copy. It has
bound the Cloudflare Secrets Store entry since 2026-05-13
(divinevideo/divine-relay-manager#63) and was missed by both the 2026-07-24 and
2026-08-31 rotations, so its moderator media preview had been failing
authentication for roughly ten weeks with no alert. The cause was the inventory
above naming only one Cloudflare consumer. That is why the copy table is now
explicit about mechanism, and why step 1 says to confirm the list against the
repositories.

Mirror the canonical value in `dv-platform-prod` Secret Manager as
`blossom-webhook-secret-prod` for the platform secret convention. That mirror is
not a fourth independently generated value. `admin_token`,
`transcoder_webhook_secret`, and process-blob's `METADATA_WEBHOOK_SECRET` are
separate credentials and must not be changed during this rotation.

## Do not create a readable copy for humans

Requests to put this value in a password manager, a shared vault, or a document
are reasonable-sounding and must be declined. `validate_bearer_token`
(`src/admin.rs`) accepts either `admin_token` or `webhook_secret`, so this value
is admin-equivalent on every route behind `validate_admin_auth`. A vault item is
readable by everyone granted access to that vault item, whereas the design above
keeps GCP Secret Manager as the authoritative readable source, with the canonical
platform mirror described above, and makes the downstream store copies
write-only. Do not add an independently maintained human-readable copy.

A human-readable copy also becomes another thing each rotation has to chase,
which is the failure this section exists to prevent. When someone needs to set a
downstream copy, ask the downstream store owner to approve write access to that
specific store rather than distributing the value. An operator who already has
authorized GCP Secret Manager read access and destination write access should
pipe the value straight into the downstream store; do not stage it anywhere in
between, including a clipboard. Do not grant the requester additional GCP
Secret Manager read access merely to set a downstream copy.

## The edge Cloud Run backends are not in the production project

The edge hardcodes its backends to project number `149672065768`:

```rust
const CLOUD_RUN_TRANSCODER_HOST: &str = "divine-transcoder-149672065768.us-central1.run.app";
const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
```

That is the proof-of-concept project `rich-compiler-479518-d2`, not
`dv-platform-prod`. See issue #32, which is open and tracks moving them.

Most deploy scripts default `PROJECT_ID` to whatever your active `gcloud`
configuration points at. `scripts/deploy-cloud-function.sh` is the exception: it
requires `GCP_PROJECT_ID` and exits if it is unset. If your context is
`dv-platform-prod` — the normal case — running a script that reads the active
context without an explicit project may build and deploy into the wrong project.
The edge keeps calling the old service, and nothing changes except a stray
service in production. The transcoder script is especially easy to mis-run this
way because it derives its runtime service account from the target project.

Always pass the project explicitly, using the variable the script reads:

```bash
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-transcoder/deploy.sh
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-upload/deploy.sh
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-asr-parakeet/deploy.sh
GCP_PROJECT_ID=rich-compiler-479518-d2 ./scripts/deploy-cloud-function.sh
```

## Check live configuration before running a deploy script

`cloud-run-transcoder/deploy.sh`, `cloud-run-upload/deploy.sh`, and the CI
`process-blob` job use `--update-env-vars`; the service scripts also use
`--update-secrets`. Unnamed keys are therefore preserved for those deploys.
Keys they *do* name are overwritten with the deploy path's values, which may
not match what is running.

`gcloud run deploy` creates or updates the *service*, and `--update-env-vars`
merges its pairs onto the service's `spec.template`. The template is therefore
the baseline the next deploy merges onto, and it is what this check has to read.
Read names rather than values:

```bash
gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --format=json \
  | python3 -c "
import json,sys
c=json.load(sys.stdin)['spec']['template']['spec']['containers'][0]
print('image:', c['image'])
print('env:', sorted(e['name'] for e in c.get('env',[]) if 'value' in e))
print('secrets:', sorted(e['name'] for e in c.get('env',[]) if 'valueFrom' in e))
"
```

The template is not necessarily what production is running: after a traffic
rollback the two diverge. See [A traffic rollback pins the
service](#a-traffic-rollback-pins-the-service) for that case, and read the
serving revision when the question is what production is answering with rather
than what the next deploy will merge onto.

Current configuration-preservation status by deploy path:

- `cloud-run-upload/deploy.sh` uses `--update-env-vars` and `--update-secrets`.
- `cloud-run-asr-parakeet/deploy.sh` still uses `--set-env-vars`.
- `scripts/deploy-cloud-function.sh` still uses `--set-env-vars`.
- `.github/workflows/ci.yml` deploys `process-blob` with `--update-env-vars`,
  preserving keys that the workflow does not manage.

Never add new `--set-env-vars` or `--set-secrets` usage unless the command owns
the complete live configuration. Both replace the entire configuration and
silently drop live settings the deploy path does not name. PR #153 fixed the
transcoder script; the remaining manual deploy paths still need the same
treatment; see issue #171.

The CI `process-blob` job also sets the service's runtime identity explicitly:
it deploys with `--service-account="$GCP_RUNTIME_SERVICE_ACCOUNT"`, read from
the `GCP_RUNTIME_SERVICE_ACCOUNT` repository secret, and the step fails before
`gcloud` runs when that secret is unset. The deploy job cannot succeed until
the secret is created and the paired IaC change (divine-iac-coreconfig#1767)
is applied.

## Exported shell variables override script defaults

The three hand-run Cloud Run deploy scripts resolve most settings as
`VAR="${VAR:-production-default}"`, so an exported shell variable silently wins
over the production default. `scripts/deploy-cloud-function.sh` resolves its
project differently — it requires `GCP_PROJECT_ID` and exits if it is unset — but
it is not exempt from the trap: its bucket and region come from exported
`GCS_BUCKET_NAME` and `GCS_REGION`. A different variable name is not immunity,
it is the same trap wearing a different name, and it lands on the one service
with two competing deploy paths.

On 2026-08-07 a shell with `GCS_BUCKET=divine-blossom-media-staging` exported
pointed the production transcoder at the staging bucket, where its service
account has no read access; every transcode failed with 403 for four and a
half hours.

Do not export deploy-time variables (`GCS_BUCKET`, `PROJECT_ID`, and friends)
from a shell profile. Set them inline on the one command that needs them.

The transcoder deploy script has one narrow automated backstop: before starting
Cloud Build, it refuses to deploy the production service in the production
project with any bucket other than `divine-blossom-media`. The configuration
check above would not catch this by itself because it deliberately reads names
and not values. Other resolved deploy variables are still unchecked.

What does catch it is checking your own shell before you deploy. Read the
variable names straight out of the scripts so the list cannot drift, and test
whether each one is exported without printing any value. Run this from the
repository root:

```bash
for script in cloud-run-transcoder/deploy.sh cloud-run-upload/deploy.sh \
              cloud-run-asr-parakeet/deploy.sh scripts/deploy-cloud-function.sh; do
  for v in $(sed -n 's/^[A-Z_][A-Z0-9_]*="\{0,1\}\${\([A-Z_][A-Z0-9_]*\):-.*/\1/p' "$script"); do
    printenv "$v" >/dev/null && echo "$v is exported — $script would use your value"
  done
done
```

That captures the name on the *right* of the `:-`, which is the name `printenv`
is being asked about. It matters: `scripts/deploy-cloud-function.sh` assigns
`BUCKET_NAME="${GCS_BUCKET_NAME:-blossom-media}"`, where the two sides differ, so
a pattern keyed to the left-hand name would miss exactly the variable that can
misdirect `process-blob`.

`GCS_BUCKET` is not the only variable that can bite this way. The transcoder
script alone resolves 27 settings from the environment, and several have names
generic enough to be sitting exported in a working shell for unrelated reasons —
an exported `MAX_INSTANCES` or `CONCURRENCY` silently reshapes production
capacity exactly the way the exported `GCS_BUCKET` silently redirected storage.
Deriving the list is what keeps this check honest as the scripts grow.

Whoever adds the broader automated guard: it has to compare *fully resolved*
values, and it has to run after the script resolves its variables and before it
builds anything. A check that parses the *defaults* out of the script text cannot
catch this failure mode, because the whole failure is the default not applying.
(Reading variable *names* out of the script, as the shell check above does, is a
different and safe operation: what it looks for lives in the operator's
environment, not in the script's text.)

Such a guard's comparison baseline is the revision currently serving traffic, not
`spec.template` — the question it asks is "am I about to change what production
is running?", which is the serving revision's question, not the merge baseline's.

## Staged rollout when the edge and a backend change together

The edge is already live by the time you start deploying the backend, so the
compatibility question is always "what does new edge do when the old backend
answers?" Where the edge has a receiver-side switch, set it before merging, not
after.

The derivative status generation guard is one such switch. See
[derivative-status-queue.md](../derivative-status-queue.md) for its rollout,
including the `REQUIRE_DERIVATIVE_STATUS_GENERATION` config-store key that must
be `false` while the transcoder is still an image that does not send
`generation`.

## Verifying a transcoder deploy landed

The transcoder does not report its version anywhere the edge can see. Confirm
from the Cloud Run side that the image tag on the revision serving traffic
matches the commit you deployed:

```bash
REVISION="$(gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --format=json \
  | python3 -c "
import json,sys
traffic=json.load(sys.stdin).get('status',{}).get('traffic',[])
serving=[t for t in traffic if t.get('percent')]
print(max(serving,key=lambda t:t['percent']).get('revisionName','') if serving else '')
")"

if [ -z "$REVISION" ]; then
  echo 'no revision is serving traffic'
else
  printf 'serving revision: %s\n' "$REVISION"
  gcloud run revisions describe "$REVISION" \
    --project rich-compiler-479518-d2 --region us-central1 \
    --format='value(spec.containers[0].image)'
fi
```

## A traffic rollback pins the service

`gcloud run services update-traffic --to-revisions=<revision>=100` rolls back
by pointing traffic at an explicit revision, and in doing so stops the service
from migrating to the latest revision. A later `gcloud run deploy` then creates
the new revision at 0% traffic while reporting success — the rollback target
keeps serving.

After any rollback, restore migration to latest explicitly:

```bash
gcloud run services update-traffic divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --to-latest
```

Until that runs, check where traffic actually is after every deploy:

```bash
gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 \
  --format='json(status.traffic)'
```

This pinning is also why the two checks above read different places. After a
rollback, the service's `spec.template` describes the newest revision *created*,
which is not the one serving traffic. The pre-deploy configuration check reads
`spec.template`, because that is the baseline the next deploy merges onto. The
deploy-landed check reads the serving revision, because that is what production
is answering with. Do not substitute one for the other — during a pinned window
they give different answers, and each is the wrong answer to the other's
question.
