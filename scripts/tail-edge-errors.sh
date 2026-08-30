#!/bin/bash
# ABOUTME: Summarises the edge errors and sampled blob-fetch diagnostics Fastly publishes to Pub/Sub.
# ABOUTME: Read-only -- pulls without acking, so records stay for the next reader.
#
# Both diagnostic sinks write to Pub/Sub and nothing consumes them, so the records
# sit unread for the 7-day retention and then expire. This makes reading them a
# single command instead of a research exercise.
#
#   vcl-error-diagnostics  Fastly-generated 5xx -- backend timeouts, unreachable
#                          origin. These never reached Compute.
#   compute-diagnostics    Errors Compute returned itself, with a route and an
#                          error category.
#
# Messages are pulled WITHOUT --auto-ack, so they return to the subscription after
# the ack deadline and remain available. Safe to run repeatedly; it does not drain
# the backlog for whoever looks next.
#
# Usage:
#   scripts/tail-edge-errors.sh            # both sinks, 100 records each
#   scripts/tail-edge-errors.sh 500        # deeper pull
#
# Requires gcloud authenticated against the project holding the topics.

set -euo pipefail

PROJECT="${PUBSUB_PROJECT:-rich-compiler-479518-d2}"
LIMIT="${1:-100}"
REQUEST_PREFIX="${REQUEST_PREFIX:-}"

summarise() {
  local sub="$1" label="$2"
  echo "=== ${label} (${sub}) ==="
  gcloud pubsub subscriptions pull "$sub" --project "$PROJECT" \
    --limit "$LIMIT" --format=json 2>/dev/null \
  | python3 -c "
import json,sys,base64,collections,os
prefix=os.environ.get('REQUEST_PREFIX','')
raw=sys.stdin.read()
try: msgs=json.loads(raw)
except Exception:
    print('  could not read subscription -- check gcloud auth and project access'); sys.exit()
if not msgs:
    print('  no records'); sys.exit()
recs=[]
for m in msgs:
    b=m.get('message',{}).get('data','')
    try: b=base64.b64decode(b).decode()
    except Exception: continue
    try: recs.append(json.loads(b))
    except Exception: pass
if prefix:
    recs=[r for r in recs if str(r.get('probe_id','')).startswith(prefix)]
print(f'  {len(recs)} record(s)')
def tally(field):
    c=collections.Counter(r.get(field) for r in recs if r.get(field) is not None)
    return ', '.join(f'{k}={v}' for k,v in c.most_common()) or '-'
for f in ('schema','status','sample_reason','error_category','route','backend','pop','method'):
    if any(f in r for r in recs):
        print(f'  {f:<15}{tally(f)}')
durs=sorted(int(r[k]) for r in recs for k in ('elapsed_ms','duration_ms') if str(r.get(k,'')).isdigit())
if durs:
    p=lambda q: durs[min(len(durs)-1,int(q*len(durs)))]
    print(f'  duration_ms    min={durs[0]} p50={p(0.5)} p90={p(0.9)} max={durs[-1]}')
ids=[r.get('request_id') for r in recs if r.get('request_id')]
if ids: print(f'  request_ids    {len(set(ids))} distinct (correlate across sinks)')
probe_ids=[r.get('probe_id') for r in recs if r.get('probe_id')]
if probe_ids: print(f'  probe_ids      {len(set(probe_ids))} distinct')
for phase in ('fos_lookup_ms','gcs_fetch_ms','buffer_ms','write_back_ms'):
    values=sorted(int(r['blob_phases'][phase]) for r in recs
                  if str(r.get('blob_phases',{}).get(phase,'')).isdigit())
    if values: print(f'  {phase:<15}min={values[0]} max={values[-1]}')
"
  echo
}

echo "project ${PROJECT}, up to ${LIMIT} records per sink"
echo "records are NOT acked -- they remain available for the next reader"
[ -z "$REQUEST_PREFIX" ] || echo "request prefix filter: $REQUEST_PREFIX"
echo
summarise vcl-error-diagnostics-sub "Fastly-generated 5xx (never reached Compute)"
summarise compute-diagnostics-sub   "Compute errors and sampled blob fetches"
