# Edge Upload Observability

Structured logging for upload requests that pass through `media.divine.video`.

Pipeline: Fastly Compute (`fastly-blossom`) → Google Cloud Pub/Sub → *(subscriber
not yet built)* → ClickHouse

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

Origin-side counters (divine-iac-core PR #1618) show ~94–96% of upload attempts
succeeding, which does not match the volume of user complaints. The leading
explanation is that failures at the edge are invisible: anything Fastly rejects
or times out never reaches origin and therefore appears in no origin metric.

The single most important field is `send_error`. When the proxy `send` to origin
fails, the request never reached `divine-upload-server`, so it appears in no
origin access log and in none of PR #1618's log-based metrics. Before this
change that case had **zero** record anywhere.

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

Sampling is not applied. Volume is a few hundred requests per day; every request
is logged.

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

gcloud iam service-accounts keys create /tmp/edge-upload-logs-key.json \
  --iam-account="fastly-edge-upload-logs@${PROJECT}.iam.gserviceaccount.com" \
  --project="$PROJECT"

python3 -c "import json;k=json.load(open('/tmp/edge-upload-logs-key.json'));open('/tmp/pk.pem','w').write(k['private_key'])"

fastly logging googlepubsub create \
  --service-id "$SERVICE" \
  --version active --autoclone \
  --name edge_upload_logs \
  --project-id "$PROJECT" \
  --topic edge-upload-logs \
  --user "fastly-edge-upload-logs@${PROJECT}.iam.gserviceaccount.com" \
  --secret-key="$(cat /tmp/pk.pem)" \
  --non-interactive

rm -f /tmp/edge-upload-logs-key.json /tmp/pk.pem
```

The endpoint name **must** be `edge_upload_logs`; it is matched by
`UPLOAD_LOG_ENDPOINT` in `src/upload_log.rs`.

A dedicated service account is used rather than the existing
`fastly-pubsub-writer` (see `cdn-view-counting.md`), so this key can only publish
to this one topic.

### Traps

- **`--secret-key` must use the `=` form.** The PEM body begins with `-----`, and
  the CLI's argument parser reads a space-separated value starting with dashes as
  a flag. `--secret-key "$(cat pk.pem)"` fails with
  `expected argument for flag '--secret-key'`; `--secret-key="$(cat pk.pem)"`
  works.
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

## Sink status — incomplete, read before querying

Fastly publishes to the `edge-upload-logs` topic and the
`edge-upload-logs-sub` subscription retains messages for **7 days**.

**The ClickHouse half of this pipeline does not exist yet.** There is no
subscriber and no table. That work lives in `divine-funnelcake`, alongside the
existing `cdn-view-subscriber`, and is out of scope for the divine-blossom PR
that shipped the edge instrumentation.

Until it ships:

- data is durable for 7 days in the subscription and no longer
- messages accumulate as unacked; nothing is consuming them
- **if the subscriber is not built within 7 days, the oldest data is lost**

Proposed table for whoever picks this up:

```sql
CREATE TABLE nostr.edge_upload_logs
(
    timestamp         DateTime DEFAULT now(),
    schema            UInt32,
    route             LowCardinality(String),
    outcome           LowCardinality(String),
    req_id            String,
    content_length    Nullable(UInt64),
    content_type      LowCardinality(Nullable(String)),
    proxied_body      Bool,
    origin_reached    Bool,
    origin_status     Nullable(UInt16),
    send_error        Nullable(String),
    proxy_duration_ms Nullable(UInt64),
    duration_ms       UInt64,
    response_status   UInt16,
    error_kind        LowCardinality(Nullable(String)),
    error_message     Nullable(String),
    client_ip_present Bool,
    client_geo_country LowCardinality(Nullable(String))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (route, outcome, timestamp);
```

## Schema

One JSON object per line, one line per request. Emitted by
`blossom_core::upload_log::format_upload_log`. Every field is always present;
absent values are `null` rather than omitted, so a fixed-column table can ingest
the stream without per-row key checks.

| field | type | meaning |
|---|---|---|
| `schema` | int | Field-set version. Bumped on incompatible changes. Currently `1`. |
| `route` | string | `direct_put`, `resumable_init`, `resumable_complete` |
| `outcome` | string | see below |
| `req_id` | string | Correlation ID, also sent to origin as `X-Request-Id` |
| `content_length` | int? | **Declared** size, not measured — the body is never buffered. On `resumable_init` this is the declared *upload* size from the JSON body, not the control message's own length. |
| `content_type` | string? | Separates video uploads from avatars and thumbnails |
| `proxied_body` | bool | Whether a request body was streamed through the edge to origin |
| `origin_reached` | bool | Whether origin was asked and answered |
| `origin_status` | int? | Origin's HTTP status, when it replied at all |
| `send_error` | string? | The error from `.send()`. **Populated only when origin was never reached.** |
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
| `ok` | Edge returned a success status. On `direct_put` this includes uploads handled entirely at the edge, which have `origin_reached = false` — see the inline-path note under Verification. |
| `send_failed` | The send to origin failed. **The request never reached origin**, so nothing origin-side accounts for it. |
| `origin_status_error` | Origin replied with a non-success status |
| `validation_rejected` | Edge returned a 4xx of its own |
| `edge_error` | Edge returned a 5xx of its own. With `origin_reached = true` this is a *post-origin* failure: the upload landed but the edge failed afterwards. |

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

`req_id::for_request` prefers an inbound `X-Request-Id`, falls back to the
leading segment of `cf-ray`, and otherwise generates one.

**Origin nginx does not log this header yet.** To close the loop, add
`$http_x_request_id` to the `divine-upload-server` access log format. Until that
lands, the header is forwarded and available but the join is not possible.

## Verification

### Confirm lines are reaching Pub/Sub

```bash
gcloud pubsub subscriptions pull edge-upload-logs-sub \
  --project=rich-compiler-479518-d2 \
  --limit=10 --format=json | python3 -m json.tool
```

Without `--auto-ack` this does not consume messages, but it does make them
invisible for the 60s ack deadline. A second pull run immediately after the
first therefore returns almost nothing — that is the deadline, not an empty
subscription. Wait out the deadline before concluding anything from a small
result.

Because nothing is acking, this is also destructive to no one: the backlog keeps
growing until the subscriber exists or the 7-day retention expires.

Undelivered count:

```bash
gcloud pubsub subscriptions describe edge-upload-logs-sub \
  --project=rich-compiler-479518-d2 \
  --format="value(numUndeliveredMessages)"
```

### Fallback while the subscriber does not exist

```bash
fastly log-tail --service-id pOvEEWykEbpnylqst1KTrR | grep '\[UPLOAD\]'
```

**`log-tail` is lossy. Never count with it.** Measured on 2026-08-13: five
`POST /upload/{id}/complete` requests issued during an active `log-tail` produced
**no output at all** — not even the `[BLOSSOM ROUTE]` line that `handle_request`
emits unconditionally for every request before any routing runs. All five were
present in Pub/Sub. The tail samples across POPs and drops under load; the
service handles thousands of requests per minute, of which uploads are a
handful.

Use `log-tail` to answer "is the guest emitting the shape I expect?", which it
does well and immediately. Use Pub/Sub to answer "how many?", which `log-tail`
cannot answer at all. An absence in `log-tail` is not evidence of anything.

### Sanity-check the volume — and mind the inline path

Direct `PUT /upload` reaching *origin* runs 241–523/day. Edge `direct_put` lines
should be **materially higher**, and not only because of edge failures.

`handle_upload` proxies to the upload service only when the upload is larger
than 500 KB *or* has a video MIME type (`UPLOAD_SERVICE_THRESHOLD`,
`src/main.rs`). Everything else is buffered and stored by the edge itself and
**never contacts origin at all**. Origin session records put p50 upload size at
0.09 MB with 92% `image/jpeg`, so the majority of direct PUTs take the inline
path and are absent from origin's direct-PUT counts by design.

Such a request logs `outcome = ok`, `origin_reached = false`,
`proxied_body = false`, `origin_status = null`, `proxy_duration_ms = null`. That
is **normal, not a failure**, and it is not a `send_failed`. Any query comparing
edge to origin counts must filter on `proxied_body = true` to compare like with
like:

```sql
-- edge requests that should have a matching origin access-log entry
SELECT count() FROM nostr.edge_upload_logs
WHERE route = 'direct_put' AND proxied_body AND timestamp >= today();
```

Observed on 2026-08-13: one `PUT /upload` in a five-minute window against 2963
total routed requests, i.e. roughly 12/hour or ~290/day of direct PUTs at the
edge. That is consistent with the 241–523/day origin figure, but it is a
five-minute sample taken through `log-tail` — which is itself lossy, see below —
and should not be treated as a rate measurement.

Both branches of the threshold were seen in real traffic the same day, which is
worth knowing when reading the data:

| observed | `content_length` | `content_type` | `proxied_body` | `origin_status` | `proxy_duration_ms` |
|---|---|---|---|---|---|
| proxied because video | 5016 | `video/mp4` | true | 200 | 757 |
| proxied because video | 5016 | `video/mp4` | true | 200 | 617 |
| inline, under threshold | 100126 | `image/jpeg` | false | null | null |

Note the 5 KB `video/mp4` files: the video MIME check fires at *any* size, so
small videos proxy while much larger images do not. Size alone does not predict
which path a request took — read `proxied_body`.

Other origin-side baselines for comparison: ~96–98% of direct PUTs return 200;
408s run 1–6/day, 400s 4–10/day, 413s 1–5/day; client aborts mid-upload
("prematurely closed connection") run 6–14/day. Resumable sessions run
62–103/day at 96.8–100% completion. Upload sizes are p50 0.09 MB, p99 7.94 MB,
max 18.47 MB; 92% `image/jpeg`, 8% `video/mp4`.

## Worked queries

These assume the ClickHouse table above. Until the subscriber exists, the same
questions can be answered by pulling from the subscription and aggregating
locally.

### 1. What fraction of edge upload attempts fail?

```sql
SELECT
    route,
    outcome,
    count()                                        AS n,
    round(100 * count() / sum(count()) OVER (PARTITION BY route), 2) AS pct
FROM nostr.edge_upload_logs
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY route, outcome
ORDER BY route, n DESC;
```

Compare the `direct_put` non-`ok` share against the ~4–6% failure rate the
origin-side counters report. **An edge failure rate materially above the origin
rate is the finding this whole pipeline exists to produce**: it is the share of
attempts that origin never saw.

For a like-for-like comparison against origin, add `AND proxied_body` — without
it the denominator includes inline uploads that origin never sees by design, and
the edge failure rate comes out artificially *low*.

### 2. How many die before ever reaching origin?

This is the population that has no record anywhere else.

```sql
SELECT
    toDate(timestamp)                              AS day,
    countIf(outcome = 'send_failed')               AS never_reached_origin,
    count()                                        AS attempts,
    round(100 * countIf(outcome = 'send_failed') / count(), 3) AS pct_invisible
FROM nostr.edge_upload_logs
WHERE route = 'direct_put'
  AND timestamp >= now() - INTERVAL 30 DAY
GROUP BY day
ORDER BY day;
```

Break the failures down by cause:

```sql
SELECT send_error, count() AS n, round(avg(proxy_duration_ms)) AS avg_ms
FROM nostr.edge_upload_logs
WHERE outcome = 'send_failed'
  AND timestamp >= now() - INTERVAL 7 DAY
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
FROM nostr.edge_upload_logs
WHERE route = 'direct_put'
  AND timestamp >= now() - INTERVAL 7 DAY
GROUP BY outcome
ORDER BY n DESC;
```

A cluster of `send_failed` rows with `proxy_duration_ms` near 120000 is direct
evidence of edge timeouts. A `p99` far below it rules the theory out. Either
result settles the question.

**Caveat on this query.** It can only count requests whose handler returned. If
Fastly terminates the guest outright at the timeout, or the client disconnects
mid-upload and the instance is torn down, no line is emitted at all. So
`at_or_past_ceiling` is a **floor**, not a measurement — the true number of
timeout deaths is at least this, possibly higher. Cross-check against origin's
"prematurely closed connection" count (6–14/day) and against total attempts: a
`direct_put` line count *below* the origin-side count of direct PUTs reaching
origin would indicate exactly this kind of silent loss.

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
FROM nostr.edge_upload_logs
WHERE route = 'direct_put'
  AND timestamp >= now() - INTERVAL 7 DAY
GROUP BY size_bucket
ORDER BY min(content_length);
```

Origin session records put p50 at 0.09 MB and p99 at 7.94 MB, so most traffic
lands in the smallest two buckets; a failure rate that climbs with size is the
"bad connections" hypothesis showing up in data.

By country, to separate "one network is bad" from "everything is bad":

```sql
SELECT client_geo_country, count() AS attempts,
       round(100 * countIf(outcome != 'ok') / count(), 2) AS pct_failed
FROM nostr.edge_upload_logs
WHERE route = 'direct_put'
  AND timestamp >= now() - INTERVAL 7 DAY
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
- `docs/runbooks/deployment.md` — deploy traps
