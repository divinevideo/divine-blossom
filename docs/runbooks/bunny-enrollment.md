# Automatic Bunny enrollment and recursive acceptance

This runs only when an operator invokes it. Complete the private origin, worker,
moderation/erasure and outer VCL prerequisites in
[bunny-playback-pilot.md](bunny-playback-pilot.md) first. Keep publication and server
playback selection off until the isolated fixture drills pass. Canonical uploads
and event URLs remain unchanged.

## Configure a bounded pass

Copy `scripts/examples/bunny-enrollment.json` into the private operator directory
and replace every example with the current original/derived primary, bucket,
region, metadata KV store and transcoder coordination bucket from deployed
configuration. GCS and B2 sources are supported independently. The coordination
bucket is the existing transcoder's `GCS_BUCKET`, including when media itself is
B2-primary. No future completion receipt or producer migration is assumed.

Load credentials with the approved secret runner, without values in command
arguments, shell history or logs:

- `FASTLY_API_TOKEN`: metadata KV read/list access.
- `BUNNY_PILOT_ADMIN_TOKEN`: existing canonical administrative credential.
- `B2_APPLICATION_KEY_ID` and `B2_APPLICATION_KEY`: canonical source read access,
  only when a configured source uses B2. These are not Bunny's restricted key.
- Google Application Default Credentials for GCS source reads and the existing
  producer coordination bucket. Use the intended operator/service account.

The CDN origin reader and publisher writer must be separate keys, restricted to
`bunny-delivery/`. Retain the independent cleanup capability and CDN purge
credentials required by the pilot runbook. Never give Bunny a canonical writer
or canonical bucket-wide credential. This script never receives worker or
origin-write credentials and never creates provider keys.

Run from the repository root in the declared operator environment. The state
and export directory must be private; the script refuses public directories.
`--max-bytes` is required and is a conservative upper reservation of media I/O,
including the remote worker's source/dependency/destination/readback work and
family finalization. It reserves protocol maximum sizes, even for tiny sources,
because conflicting old destination objects can be larger. One complete maximum
family fits a 1 GiB reservation. Control-plane JSON/header overhead is separate.

```sh
mkdir -m 700 "$HOME/.config/divine-cdn/enrollment-state"
uv run --no-project --with-requirements scripts/requirements-b2-sync.txt \
  python scripts/publish_bunny_media.py \
  --config "$HOME/.config/divine-cdn/enrollment.json" \
  --state-dir "$HOME/.config/divine-cdn/enrollment-state" \
  --max-pages 1 --page-size 100 --max-parents 1 \
  --max-bytes 1073741824 --dry-run
```

Remove `--dry-run` only for an explicitly configured test pass. Optionally add
`--export-ready "$HOME/.config/divine-cdn/fixture.json"` to export the most recent
verified family's paths, delivery digests and sizes for acceptance probes. An
export is private (0600); it can identify media and must never be committed or
pasted into public issues, CI logs or PRs. Aggregate output contains no fixture
paths or owner data.

## Discovery, completion and recovery

Metadata discovery is paginated with an atomic SQLite queue/cursor checkpoint.
A pass is bounded to 100 pages of 100 names, 1,000 processed parents and a supplied
byte ceiling, with one family in flight at a time. The queue retains at most
10,000 parents, reuses completed slots and stops advancing a saturated page while
continuing previously committed work. An expired provider cursor restarts discovery without discarding committed jobs.
Repeated passes wrap the scan to discover
new completed clips and source changes. Stable ready source identities avoid
local re-download and republishing, but still request server re-verification of
source/destination bytes and current scope. A confirmed missing/changed delivery
family resets acknowledged copy progress for a subsequent bounded repair pass;
conflicting existing bytes are never overwritten.

Eligibility requires current active/complete metadata, no existing
`.internal/hls-claims/<parent>` object and stable immutable source versions,
checked again after reads and before each publication/finalization. Five HLS
objects are required; original and progressive MP4s are optional and must fit
the bounds. Dependencies publish before their playlists, with the master last.
Canonical absolute references are normalized to relative references. The server
independently rechecks current policy, source/destination bytes, scope and gates;
only its verified finalization response grants readiness. No client inventory
can assert readiness on its own.

The journal binds its schema and source scope and persists acknowledged object
receipts. Restarting between acknowledged objects resumes that family. A crash
or lost response during an external write/finalization becomes `uncertain` and
is never automatically retried or cleared. A source read timeout before a write
can retry. A confirmed immutable-object conflict is reported and never
overwritten. Inspect the private journal and the existing gate/outbox recovery
procedure, establish the settled provider outcome, finish any required eviction,
and only then explicitly repair local progress. Do not delete the journal or
release a server gate to make an uncertain pass appear successful.

Schedule the same bounded command periodically through the existing operator
runner after fixture acceptance. Its lock prevents overlapping invocations.
Monitor aggregate ready/unchanged, deferred, refused, uncertain, errors,
saturated and reservation counts plus the existing durable erasure outbox.
Nonzero exit signals refusal, uncertainty or error. Deferred clips and queued
work are reconsidered; a persistent producer claim or unsupported family needs
investigation. Disable enrollment before repairing provider configuration.

## Prove media and withdrawal

The original `scripts/probe_bunny_delivery.py` retains its MP4 parity and guard
checks; its exact root GET/HEAD now expects the matching public landing page.
The recursive probe additionally pins all HLS/MP4 bytes from a verified private
inventory on both the custom and vendor hostnames:

```sh
python scripts/probe_bunny_hls_delivery.py \
  --inventory "$HOME/.config/divine-cdn/fixture.json" \
  --vendor-host example-pilot.b-cdn.net \
  --max-bytes 1073741824 --require-cold
```

Use a fresh fixture or targeted invalidation for cold proof. It verifies the
informational HTML against canonical root, CDN identity, MIME, full body digests,
HEAD length, warm hits, byte ranges and every referenced HLS segment range.
Incomplete trees, foreign references, bad bytes, redirects and ignored ranges
fail. There are at most 5,000 requests by default (hard ceiling 10,000); request
and body-byte budgets span the whole invocation. No probe sends authorization,
cookies or purge requests. The original MP4 probe still covers its exact
query/encoding/auth/cookie/method guards; live zone settings must enforce those
same boundaries for HLS children.

After proving that exact fixture ready and warm, withdraw it through the existing
authorized moderation/cleanup path. Then monitor every known object, including
child playlists and segments, on both hostnames over the complete configured
edge TTL plus propagation margin:

```sh
python scripts/probe_bunny_hls_delivery.py \
  --inventory "$HOME/.config/divine-cdn/fixture.json" \
  --vendor-host example-pilot.b-cdn.net \
  --max-bytes 67108864 --denied --watch-denied-seconds 330
```

The 330-second example assumes a 300-second edge TTL plus 30 seconds of margin;
use the actual configured window and adequate budgets. GET, HEAD and Range must
all deny each known object; a denied master alone is insufficient. Repeat from
independent regions/POPs and record aggregate evidence. One vantage, local
fixtures or closed-zone denials cannot establish global live revocation.

Turn the server cohort to zero and the mobile flag off for rollback; stop new
enrollment and retain the private origin, worker, eraser and purge bindings
until durable cleanup and the full cache window have completed. No global purge
or canonical DNS cutover is part of these tools.
