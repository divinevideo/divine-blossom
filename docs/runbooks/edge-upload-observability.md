# Edge Upload Observability

Structured logging for upload requests that pass through `media.divine.video`.

Pipeline: Fastly Compute (`fastly-blossom`) → Google Cloud Pub/Sub →
`edge-upload-log-subscriber` (Cloud Run) → ClickHouse `nostr.edge_upload_logs`

Upload 5xx responses are also recorded on the separate `compute-diagnostics`
sink with a route category rather than the upload-specific fields; see the
[Fastly 5xx diagnostics runbook](fastly-5xx.md). Both records carry the same
correlation value, keyed `req_id` here and `request_id` there.

## Why this exists

`media.divine.video` proxied upload request bodies to origin and kept no durable
record of doing so. Every measurement channel was missing at once:

- Crashlytics suppresses `TIMEOUT` (mobile reports only `OUT_OF_MEMORY` and
  `UNKNOWN`)
- `/api/analytics/events` does not exist server-side; mobile and web both ship
  clients for a route nobody built
- `divine-upload-server` exposes no `/metrics`
- this service logged only via `eprintln!`, which reaches `fastly log-tail` and
  nothing else

Origin-side counters cannot account for requests that fail at the edge before a
complete origin response is received. The single most important field is
`send_error`: it records those edge-visible failures independently of origin
logging. A send error does not prove whether origin received or processed some
or all of the request; correlate it with origin logs before drawing that
conclusion.

## Scope

| flow | route | through Fastly? | logged here? |
|---|---|---|---|
| direct `PUT /upload` | via `media.divine.video`; body proxied to origin only above 500 KB or for video, otherwise stored inline by the edge | yes | **yes** (`direct_put`) |
| resumable `POST /upload/init` | via `media.divine.video` | yes | **yes** (`resumable_init`) |
| resumable `POST /upload/{id}/complete` | via `media.divine.video` | yes | **yes** (`resumable_complete`) |
| resumable chunk `PUT /sessions/{id}` | client → `upload.divine.video` direct | **no** | no — bypasses the edge entirely |

Chunk appends never traverse this service, so they are already fully visible in
origin logs and are deliberately out of scope. Corroboration: the edge proxy
forwards only `Host`, `Authorization`, `Content-Type`, `Content-Length`,
`X-Request-Id` — notably not `User-Agent`. Origin nginx logs show
`Dart/3.12 (dart:io)` on chunk PUTs (client direct) and `-` on direct PUTs
(edge-proxied).

Sampling is not applied; every request on the listed routes is logged.

## Where the config lives — read this before trusting the data

**The logging endpoint is Fastly service configuration, not code. It is not in
this repo and not in any version control.**

`fastly.toml` already warns that backends, KV stores, config stores, and secrets
are dashboard-managed. The logging endpoint is the same. Consequences:

- a service rebuilt from scratch has **no** endpoint, and nothing in CI notices
- if the endpoint is deleted, Fastly drops writes to the unknown endpoint name
  **silently** — the guest sees no error, the deploy stays green, and the data
  just stops

There is no automated backstop for this today. The mitigation in code is that
every line is also written to stderr, so `fastly log-tail` still shows the lines.

**Do not over-trust that mitigation.** `log-tail` is both ephemeral *and* lossy —
measured, see the note under Verification. It is enough to confirm the guest is
still emitting, and not enough to notice that the sink stopped receiving. If the
endpoint is deleted, the realistic detection path is someone querying the sink
and finding a gap, which is exactly the delayed, manual detection this warning
exists to flag.

To check the endpoint still exists on the active version:

```bash
fastly logging googlepubsub list --service-id pOvEEWykEbpnylqst1KTrR --version active
```

### Recreating it from scratch

```bash
umask 077
PROJECT=rich-compiler-479518-d2
SERVICE=pOvEEWykEbpnylqst1KTrR

gcloud pubsub topics create edge-upload-logs --project="$PROJECT"

gcloud pubsub subscriptions create edge-upload-logs-sub \
  --topic=edge-upload-logs \
  --ack-deadline=60 \
  --message-retention-duration=7d \
  --project="$PROJECT"

gcloud iam service-accounts create fastly-edge-upload-logs \
  --display-name="Fastly Edge Upload Log Writer" \
  --project="$PROJECT"

gcloud pubsub topics add-iam-policy-binding edge-upload-logs \
  --member="serviceAccount:fastly-edge-upload-logs@${PROJECT}.iam.gserviceaccount.com" \
  --role="roles/pubsub.publisher" \
  --project="$PROJECT"

KEY_FILE=$(mktemp)
trap 'rm -f "$KEY_FILE"' EXIT

gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="fastly-edge-upload-logs@${PROJECT}.iam.gserviceaccount.com" \
  --project="$PROJECT"

chmod 600 "$KEY_FILE"
```

Create the `edge_upload_logs` Google Cloud Pub/Sub endpoint in the Fastly
dashboard using the JSON file's `client_email` and `private_key` fields, then
activate that service version. Immediately delete the local key and disarm the
normal-exit cleanup after it succeeds:

```bash
rm -f "$KEY_FILE" && trap - EXIT
```

The EXIT trap remains the abnormal-path backstop until those commands run. Do
not pass the private key to `fastly logging googlepubsub create`: that command
accepts the key only as an argument, which exposes it in process metadata.

The endpoint name **must** be `edge_upload_logs`; it is matched by
`UPLOAD_LOG_ENDPOINT` in `src/upload_log.rs`.

A dedicated service account is used rather than the existing
`fastly-pubsub-writer` (see `cdn-view-counting.md`), so this key can only publish
to this one topic.

### Traps

- **Do not use the CLI's `--secret-key` flag.** It has no file or stdin form, so
  the private key would be visible in process metadata.
- **`fastly logging googlepubsub describe` prints the full private key** to
  stdout, in both the default and `--json` output. Never paste its output into a
  PR, an issue, a ticket, or a shared transcript. Use `list` when you only need
  to confirm the endpoint exists.

  Filtering the output is easy to get wrong: the JSON field is `SecretKey`, not
  `secret_key`, so a filter keyed on the snake_case name strips nothing and
  succeeds silently. This has already caused one key rotation. If you must
  inspect the config, allow-list the fields you want rather than deny-listing
  the one you don't:

  ```bash
  fastly logging googlepubsub describe --service-id "$SERVICE" \
    --version active --name edge_upload_logs --json \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print(json.dumps({k:d[k] for k in ('Name','Topic','ProjectID','User','Placement','ResponseCondition','ServiceVersion')},indent=2))"
  ```
- **Activate the endpoint's version before `fastly compute publish`.**
  `publish` clones the *active* version. Creating the endpoint with `--autoclone`
  leaves it on a draft version; publishing before activating that draft clones
  the older active version instead and silently drops the endpoint.
- **`fastly compute publish` will try to create a brand-new service** if no
  service ID resolves. `fastly.toml` carries no `service_id` and CI supplies
  `FASTLY_SERVICE_ID` from the workflow env, so a hand-run publish needs
  `--service-id pOvEEWykEbpnylqst1KTrR` passed inline. Without it the command
  reaches "Creating service" and only fails because the service *name* collides.
  Pass the ID inline rather than exporting it — see the exported-variable trap in
  `deployment.md`.
- **The endpoint carries a default VCL log format template.** It is inert on a
  Compute service: the Wasm guest writes the line itself and Fastly does not
  apply the template. Verified on 2026-08-13 — the payloads arriving in Pub/Sub
  are the guest's raw JSON, with none of the template's fields. Do not edit it
  expecting the output to change.

- **Delivery is not immediate. Do not conclude it is broken for at least 15
  minutes.** Fastly batches log delivery, and at this volume the first lines
  after a config change took several minutes to arrive — a three-minute poll
  window showed an empty subscription while delivery was in fact working. Two
  delays stack here: POP propagation of the new service version, and the log
  batch flush. Confirm with `fastly log-tail` first (see below); that is
  immediate and tells you whether the *guest* is emitting, which separates a
  code problem from a delivery problem.

## Sink status — live

Pipeline, end to end and running as of 2026-08-17:

```
Fastly Compute (fastly-blossom) → Pub/Sub topic edge-upload-logs
  → Cloud Run edge-upload-log-subscriber → nostr.edge_upload_logs
```

The subscriber lives in `divine-funnelcake` at
`bin/edge-upload-log-subscriber` (PR #1017), deployed to Cloud Run in
`rich-compiler-479518-d2`. The table was created by migration
`000231_edge_upload_logs`.

Query it directly:

```sql
SELECT count(), max(occurred_at) FROM nostr.edge_upload_logs FINAL;
```

Expect the newest row to lag real time by roughly ten minutes. That is Fastly's
log-batching delay, not subscriber lag — the Pub/Sub backlog normally sits at 0.

### Delivery semantics that affect your queries

- **At-least-once, deduplicated in the table.** The table is a
  `ReplacingMergeTree` sorted by `(route, outcome, occurred_at, req_id)`. A
  redelivered message is byte-identical and collapses on merge. A count taken
  before a merge can include duplicates — use `FINAL` or group by the sorting
  key if that matters.
- **The subscriber acks only after a successful insert.** A ClickHouse outage
  stalls the pipeline rather than losing records.
- **Schema 1 timestamps are approximate.** Version 1 carried no event time, so
  its `occurred_at` is the Pub/Sub publish time and is late by the batching
  delay. Filter to `schema = 2` for time-sensitive analysis.

### The shipped table

This is what exists, which differs from the shape originally proposed here.
Booleans are `UInt8` rather than `Bool` (this database has no `Bool` columns),
there is no `PARTITION BY` (only 4 of 344 tables partition), and the engine
deduplicates.

```sql
CREATE TABLE nostr.edge_upload_logs (
    occurred_at        DateTime64(3),
    schema             UInt32,
    route              LowCardinality(String),
    outcome            LowCardinality(String),
    req_id             String,
    content_length     Nullable(UInt64),
    content_type       Nullable(String),
    proxied_body       UInt8,
    origin_responded   UInt8,
    origin_status      Nullable(UInt16),
    send_error         Nullable(String),
    proxy_duration_ms  Nullable(UInt64),
    duration_ms        UInt64,
    response_status    UInt16,
    error_kind         Nullable(String),
    error_message      Nullable(String),
    client_ip_present  UInt8,
    client_geo_country Nullable(String)
) ENGINE = ReplacingMergeTree()
ORDER BY (route, outcome, occurred_at, req_id);
```

Note the column is `occurred_at`, not `timestamp` or `occurred_at_ms` — queries
written against the earlier proposal in this file will not run.

### Archived backlog

The records published before the subscriber existed were exported to
`gs://divine-edge-upload-log-archive/edge_upload_logs_2026-08-13_to_2026-08-16_20260816T233153Z.jsonl.gz`
as gzipped JSONL. The subscriber backfilled that object into ClickHouse; verify
the table has rows from that window before treating the archive as redundant:

```sql
SELECT min(occurred_at), max(occurred_at), count()
FROM nostr.edge_upload_logs FINAL
WHERE schema = 1;
```

## Schema

One JSON object per line, one line per request. Emitted by
`blossom_core::upload_log::format_upload_log`. Every field is always present;
absent values are `null` rather than omitted, so a fixed-column table can ingest
the stream without per-row key checks.

| field | type | meaning |
|---|---|---|
| `schema` | int | Field-set version. Bumped on incompatible changes. Currently `2`; version 1 named `origin_responded` as `origin_reached`. |
| `occurred_at_ms` | int | Request occurrence time in Unix epoch milliseconds; use this rather than delayed sink insertion time |
| `route` | string | `direct_put`, `resumable_init`, `resumable_complete` |
| `outcome` | string | see below |
| `req_id` | string | Correlation ID, also sent to origin as `X-Request-Id` |
| `content_length` | int? | **Declared** size, not measured — the body is never buffered. On `resumable_init` this is the declared *upload* size from the JSON body, not the control message's own length. |
| `content_type` | string? | Separates video uploads from avatars and thumbnails |
| `proxied_body` | bool | Whether a request body was streamed through the edge to origin |
| `origin_responded` | bool | Whether origin returned a complete HTTP response. `false` does not prove origin received none of the request. |
| `origin_status` | int? | Origin's HTTP status, when it replied at all |
| `send_error` | string? | The error from `.send()` when no complete origin response was received |
| `proxy_duration_ms` | int? | Wall time around the origin send, present whenever a send was attempted — including when it failed |
| `duration_ms` | int | Wall time for the whole request at the edge |
| `response_status` | int | What the edge returned to the client |
| `error_kind` | string? | Stable `BlossomError` variant label, e.g. `bad_request` |
| `error_message` | string? | Sanitized error text (see below) |
| `client_ip_present` | bool | Whether a client IP was resolvable |
| `client_geo_country` | string? | Two-letter country code only |

### Outcomes

| outcome | meaning |
|---|---|
| `ok` | Edge returned a success status. On `direct_put` this includes uploads handled entirely at the edge, which have `origin_responded = false` — see the inline-path note under Verification. |
| `send_failed` | The send did not yield a complete origin response. Origin may still have received or processed the request. |
| `origin_status_error` | Origin replied with a non-success status |
| `validation_rejected` | Edge returned a 4xx of its own |
| `edge_error` | Edge returned a 5xx of its own. With `origin_responded = true` this is a *post-response* failure: origin replied successfully but the edge failed afterwards. |

Classification is ordered: a failed send outranks everything, then a non-2xx
origin status, then the edge's own status. This matters because both a failed
send and an origin rejection get wrapped into a generic `BlossomError` before the
handler returns; without the ordering, every origin 413 would be miscounted as an
edge-side validation failure.

### What is deliberately not logged

- the `Authorization` header, in any form — it carries Nostr auth
- request or response bodies
- pubkeys, event IDs, or blob hashes
- client IP; only presence and country code

Free-text fields (`error_message`, `send_error`, `content_type`, `req_id`,
`client_geo_country`) are passed through a sanitizer that replaces control
characters with spaces, caps length at 200 characters, and replaces any token
following a `Nostr` or `Bearer` scheme keyword with `[redacted]`. The control
character stripping is not cosmetic: a raw newline in an error message would
split one record into two on a line-delimited sink.

No auth error message currently echoes the `Authorization` header — they are all
fixed strings — so the credential redaction is defence in depth rather than a fix
for a known leak. The field that genuinely carries external content is
`error_message` on `origin_status_error`: `extract_upload_service_error_message`
falls back to the raw origin response body when it cannot parse an `error` field
out of it. That body is upstream text this service does not control, which is why
it is capped and scrubbed rather than logged verbatim.

## Correlation with origin logs

The edge sends its `req_id` to origin as an `X-Request-Id` header on all three
proxied upload routes. This is a change to what origin receives.

`req_id::for_request` prefers `x-divine-edge-request-id` once the outer VCL
service is chained in front of Compute (trustworthy only after that service is
activated), then an inbound `X-Request-Id`, then the leading segment of
`cf-ray`, and otherwise generates one.

**Origin nginx does not log this header yet.** To close the loop, add
`$http_x_request_id` to the `divine-upload-server` access log format. Until that
lands, the header is forwarded and available but the join is not possible.

## Verification

### Confirm raw lines and subscriber health

```bash
gcloud pubsub subscriptions pull edge-upload-logs-sub \
  --project=rich-compiler-479518-d2 \
  --limit=10 --format=json | python3 -m json.tool
```

Without `--auto-ack` this does not consume messages, but it does make any pulled
messages invisible for the 60s ack deadline. With the deployed subscriber
draining normally, this pull often returns nothing because the messages have
already been inserted and acked. Treat it as a raw-payload spot check only, not
as a count or health signal.

ClickHouse is the place to count delivered rows. Pub/Sub backlog is a subscriber
health signal; it should stay near 0:

```bash
START="$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
END="$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"

curl -sS -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  --get "https://monitoring.googleapis.com/v3/projects/rich-compiler-479518-d2/timeSeries" \
  --data-urlencode 'filter=metric.type="pubsub.googleapis.com/subscription/num_undelivered_messages" AND resource.labels.subscription_id="edge-upload-logs-sub"' \
  --data-urlencode "interval.startTime=${START}" \
  --data-urlencode "interval.endTime=${END}" \
  --data-urlencode 'view=FULL' \
  | jq -r '.timeSeries[0].points[0].value.int64Value // "0"'
```

If backlog rises and stays non-zero, inspect the subscriber first:

```bash
gcloud run services logs read edge-upload-log-subscriber \
  --project=rich-compiler-479518-d2 \
  --region=us-central1
```

The subscriber's deploy and configuration notes live in
`divine-funnelcake/bin/edge-upload-log-subscriber/README.md`.

### Spot-checking the guest directly

```bash
fastly log-tail --service-id pOvEEWykEbpnylqst1KTrR | grep '\[UPLOAD\]'
```

**`log-tail` is lossy. Never count with it.** Measured on 2026-08-13: five
`POST /upload/{id}/complete` requests issued during an active `log-tail` produced
**no output at all** — not even the `[BLOSSOM ROUTE]` line that `handle_request`
emitted unconditionally for every request at the time of the measurement. (That
line is removed on this branch: route visibility now exists only as the route
category in persisted 5xx records; see the [Fastly 5xx diagnostics
runbook](fastly-5xx.md).) All five were
present in Pub/Sub. The tail samples across POPs and can drop lines under load.

Use `log-tail` to answer "is the guest emitting the shape I expect?", which it
does well and immediately. Use ClickHouse to answer "how many?". An absence in
`log-tail` is not evidence of anything.

### Mind the inline path when comparing datasets

`handle_upload` proxies to the upload service only when the upload is larger
than 500 KB *or* has a video MIME type (`UPLOAD_SERVICE_THRESHOLD`,
`src/main.rs`). Everything else is buffered and stored by the edge itself and
**never contacts origin at all**, so those requests are absent from origin's
direct-PUT counts by design.

Such a request logs `outcome = ok`, `origin_responded = false`,
`proxied_body = false`, `origin_status = null`, `proxy_duration_ms = null`. That
is **normal, not a failure**, and it is not a `send_failed`. Any query comparing
edge to origin counts must filter on `proxied_body = true` to compare like with
like:

```sql
-- edge requests that should have a matching origin access-log entry
SELECT count() FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND route = 'direct_put'
  AND proxied_body
  AND occurred_at >= today();
```

Note that the video MIME check fires at *any* size, so 5 KB `video/mp4` files
proxy while a 100 KB `image/jpeg` does not. Size alone does not predict which
path a request took — read `proxied_body`.

## Worked queries

These assume the ClickHouse table above. They use `FINAL` so pre-merge duplicate
deliveries do not inflate counts, and `schema = 2` so time windows use edge event
time rather than Pub/Sub publish time. Remove the schema filter only when you
intentionally want to include the schema-1 backfill window.

### 1. What fraction of edge upload attempts fail?

```sql
SELECT
    route,
    outcome,
    count()                                        AS n,
    round(100 * count() / sum(count()) OVER (PARTITION BY route), 2) AS pct
FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND occurred_at >= now() - INTERVAL 7 DAY
GROUP BY route, outcome
ORDER BY route, n DESC;
```

Compare the `direct_put` non-`ok` share with origin-side counters, while treating
the two datasets as overlapping rather than disjoint. A send error may have a
corresponding partial or complete origin request even though the edge received
no complete response.

For a like-for-like comparison against origin, add `AND proxied_body` — without
it the denominator includes inline uploads that origin never sees by design, and
the edge failure rate comes out artificially *low*.

### 2. How many receive no complete origin response?

```sql
SELECT
    toDate(occurred_at)                            AS day,
    countIf(outcome = 'send_failed')               AS no_complete_origin_response,
    count()                                        AS attempts,
    round(100 * countIf(outcome = 'send_failed') / count(), 3) AS pct_send_failed
FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND route = 'direct_put'
  AND occurred_at >= now() - INTERVAL 30 DAY
GROUP BY day
ORDER BY day;
```

Break the failures down by cause:

```sql
SELECT send_error, count() AS n, round(avg(proxy_duration_ms)) AS avg_ms
FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND outcome = 'send_failed'
  AND occurred_at >= now() - INTERVAL 7 DAY
GROUP BY send_error
ORDER BY n DESC;
```

### 3. What does the duration distribution look like against the 120s ceiling?

Fastly's request timeout is 120s. Whether real uploads approach it is the open
question this investigation keeps circling.

```sql
SELECT
    outcome,
    count()                                   AS n,
    quantile(0.50)(duration_ms)               AS p50,
    quantile(0.95)(duration_ms)               AS p95,
    quantile(0.99)(duration_ms)               AS p99,
    max(duration_ms)                          AS max_ms,
    countIf(duration_ms > 110000)             AS within_10s_of_ceiling,
    countIf(duration_ms >= 120000)            AS at_or_past_ceiling
FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND route = 'direct_put'
  AND occurred_at >= now() - INTERVAL 7 DAY
GROUP BY outcome
ORDER BY n DESC;
```

A cluster of `send_failed` rows with `proxy_duration_ms` near 120000 is evidence
that the edge did not receive complete responses before its timeout. It does not
by itself establish whether the client, edge-to-origin stream, or origin stalled.

**Caveat on this query.** It can only count requests whose handler returned. If
Fastly terminates the guest outright at the timeout, or the client disconnects
mid-upload and the instance is torn down, no line is emitted at all. So
`at_or_past_ceiling` is a **floor**, not a complete measurement. Cross-check it
against origin logs and total attempts to look for requests missing from the
edge dataset.

### 4. Does failure concentrate in large uploads or particular networks?

```sql
SELECT
    multiIf(content_length < 262144,   '<256KB',
            content_length < 1048576,  '256KB-1MB',
            content_length < 8388608,  '1-8MB',
            content_length < 33554432, '8-32MB',
                                       '>32MB')    AS size_bucket,
    count()                                        AS attempts,
    countIf(outcome != 'ok')                       AS failures,
    round(100 * countIf(outcome != 'ok') / count(), 2) AS pct_failed,
    quantile(0.95)(duration_ms)                    AS p95_ms
FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND route = 'direct_put'
  AND occurred_at >= now() - INTERVAL 7 DAY
GROUP BY size_bucket
ORDER BY min(content_length);
```

A failure rate that climbs with size is evidence for investigating slow or
interrupted request streams, not proof of which hop caused them.

By country, to separate "one network is bad" from "everything is bad":

```sql
SELECT client_geo_country, count() AS attempts,
       round(100 * countIf(outcome != 'ok') / count(), 2) AS pct_failed
FROM nostr.edge_upload_logs FINAL
WHERE schema = 2
  AND route = 'direct_put'
  AND occurred_at >= now() - INTERVAL 7 DAY
GROUP BY client_geo_country
HAVING attempts > 50
ORDER BY pct_failed DESC;
```

## Related

- `docs/runbooks/cdn-view-counting.md` — the existing Fastly → Pub/Sub →
  ClickHouse pipeline this one is modelled on (different service:
  `ML7R82HKfmTaqTpHExIDVN`, the VCL service)
- divine-iac-core PR #1618 — origin-side log-based metrics and Grafana dashboard,
  which this sits in front of
- `divine-funnelcake/bin/edge-upload-log-subscriber/README.md` — subscriber
  configuration, delivery semantics, and deploy command
- `docs/runbooks/deployment.md` — deploy traps
