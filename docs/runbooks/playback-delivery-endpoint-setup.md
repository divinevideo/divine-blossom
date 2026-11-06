# Provision the Compute playback delivery endpoint

The producer is source code only until an operator provisions its endpoint.
As of the 2026-11-06 read-only preflight reported by the coordinating agent,
Compute service pOvEEWykEbpnylqst1KTrR active version 403 had
compute-diagnostics and edge_upload_logs only. The existing cdn-view-logs
endpoint belongs to outer VCL service ML7R82HKfmTaqTpHExIDVN. Each service
needs its own logging endpoint.

No infrastructure change was performed by the producer implementation. Endpoint
configuration is dashboard-managed, as documented in fastly.toml and
[Edge Upload Observability](edge-upload-observability.md); this repository has
no endpoint/IAM/credential provisioning resource to update. Recheck the current
active version before executing these steps. Keep
b2_playback_telemetry_enabled absent or false throughout provisioning.

## 1. Confirm the existing transport and backend

An explicitly authorized operator records these non-secret attributes:

| Attribute | Required value |
|---|---|
| Compute service | pOvEEWykEbpnylqst1KTrR |
| Compute endpoint name/type | cdn-view-logs / Google Cloud Pub/Sub |
| GCP project | rich-compiler-479518-d2 |
| Existing topic | projects/rich-compiler-479518-d2/topics/cdn-view-logs |
| Existing consumer subscription | cdn-view-logs-sub |
| Publisher principal from existing transport runbook | fastly-pubsub-writer@rich-compiler-479518-d2.iam.gserviceaccount.com |
| Required IAM | roles/pubsub.publisher on that topic only |
| Approved credential reference | Fastly/ML7R82HKfmTaqTpHExIDVN/version/26/logging/pubsub/cdn-view-logs |

The coordinating agent verified this existing credential reference read-only on
2026-11-06, with no secret values exposed and no configuration writes. Its
publisher has an unconditioned direct roles/pubsub.publisher binding on the
existing cdn-view-logs topic. No new credential, user refresh, or IAM grant is
needed for that existing principal. Revalidate the reference and binding freshly
before provisioning. The Compute diagnostics credential has no direct publisher
binding on this topic and is not the credential for this endpoint.

The authorized operator can read the referenced endpoint and copy its existing
user and secret_key fields strictly in process memory into the new Compute
endpoint, together with project/topic settings. Keep the key out of stdout,
stderr, command arguments, files, screenshots, reports and Git. Copy no VCL
format or response-condition fields. This source task does not read or copy key
values and does not perform endpoint creation or activation. The assigned live
cache operator owns any later authorized infrastructure execution.

Read-only checks (do not create a replacement topic/subscription):

```sh
gcloud pubsub topics describe cdn-view-logs \
  --project=rich-compiler-479518-d2 --format='value(name)'

gcloud pubsub topics get-iam-policy cdn-view-logs \
  --project=rich-compiler-479518-d2 \
  --flatten='bindings[].members' \
  --filter='bindings.role=roles/pubsub.publisher AND bindings.members=serviceAccount:fastly-pubsub-writer@rich-compiler-479518-d2.iam.gserviceaccount.com' \
  --format='json(bindings.role,bindings.members,bindings.condition)'
```

The second command must return the intended principal with an unconditioned
publisher binding. A changed or missing binding is a new operator finding;
revalidate the approved reference before proposing any IAM change. No
project-wide publisher grant is needed. Verify the deployed cdn-view subscriber
accepts the explicit
`divine.media.delivery.v1` schema, including nullable origin_attempted, and
acknowledges inserts into nostr.media_delivery_performance_events before
emitting from Compute. Use the matching backend runbook and its synthetic
storage/dedup acceptance first. Preserve legacy view and recommendation fan-out.

## 2. Add the endpoint on a Compute draft

In the Fastly dashboard, inspect Compute service pOvEEWykEbpnylqst1KTrR and
clone its current active version. Add Google Cloud Pub/Sub logging to that draft
through the authorized secret-safe API process so the existing key remains in
memory; use the dashboard for non-secret inspection and draft validation:

1. Name the endpoint exactly cdn-view-logs.
2. Set project rich-compiler-479518-d2 and topic cdn-view-logs.
3. Read the exact approved credential reference from step 1 through the
   authenticated API in a secret-safe process. Copy only user, secret_key,
   project and topic into the new endpoint, in memory. Inspect/store only
   non-secret metadata in the change record; never dump the API response or
   request. Preserve compute-diagnostics, edge_upload_logs and all other
   existing service configuration.
4. Preserve raw guest-written JSON. Compute sends one complete
   divine.media.delivery.v1 object in exactly one endpoint write, without a
   newline. Fastly defines a log record at each write call; a separate newline
   write would create an additional non-JSON record. Its logging endpoint
   template is inert on Compute; leave the default/empty template and validate
   actual message bytes during readback. Apply no VCL view-count template,
   response condition, success-only filter, wrapper, or field transformation.
5. Save and validate the draft. An authorized operator activates that endpoint
   configuration before any Compute package publish that must retain it:
   publish clones the active version, so an unactivated endpoint draft can be
   lost. Use the normal rollback/deployment runbooks for those separate steps.

Do not use fastly logging googlepubsub list --json or describe: those commands
expose SecretKey. Do not supply private keys in CLI arguments. Do not copy or
alter the outer endpoint or its view-count format/condition.

## 3. Bounded readback before ongoing enablement

Endpoint existence and IAM are required preconditions, but successful guest
writes cannot acknowledge Pub/Sub delivery or ClickHouse insertion. Fastly can
silently accept a write to an unknown endpoint. Complete an explicitly
approved, bounded canary verification window only after steps 1 and 2:

1. Record the Compute active version, approved backend revision, endpoint's
   non-secret topic/principal attributes, UTC window, and one fresh synthetic
   lowercase UUID v4 load ID in the private operator record.
2. Temporarily enable b2_playback_telemetry_enabled for the verified configured
   canary host. Issue exactly one HEAD request with that synthetic
   X-Playback-Load-Id to a non-media probe path on that host. Expect 404 and a
   fresh X-Playback-Request-Id. This performs no media upload/fill or source
   read. Keep cache-warming/operator probes free of playback correlation
   headers; this separate, named server probe is not a native QoE sample.
3. Use the backend runbook's UTC-day/cohort-bounded, deduplicated diagnostic
   read restricted to this load ID, with its resource/time caps. Poll at most
   once per minute for 15 minutes, allowing normal Fastly batching. Confirm one
   operational delivery record: method HEAD, status 404, compute_headers,
   origin_attempted=false, provider=none, and null transfer_ms/bytes_sent.
   Check its request_id against the response. Verify legacy view/Gorse counts
   are unaffected and no client performance event was invented. Exclude this
   named synthetic server probe from subsequent cohort analysis.
4. Stop the window and restore the telemetry flag to absent/false if any
   precondition, schema, sink, or isolation check fails, or the deadline expires.
   Record an incomplete acceptance result rather than widening the probe. Keep
   source/cache/media configuration unchanged. Ongoing enablement is a separate
   operator decision after evidence is reviewed.

A failed or missing row requires checking endpoint existence, credential scope,
logging diagnostics and subscriber health. Repeated media downloads, cache
purges and broad Pub/Sub pulls are not required. Avoid pulling from the shared
consumer subscription: that hides live messages for their ack deadline.

## Safe producer diagnostics

The producer emits only this finite stderr counter family for its logging
attempts, without correlation IDs, event payloads, headers or raw errors:

```text
playback_delivery_log outcome=host_accepted count=1
playback_delivery_log outcome=endpoint_unavailable count=1
playback_delivery_log outcome=write_failed count=1
```

Aggregate by outcome when the logging surface supports it. host_accepted means
the guest write returned successfully; it does not prove endpoint existence,
publication or storage. endpoint_unavailable/write_failed expose failures that
the host reports, while playback remains fail-open. Fastly log-tail is lossy
and ephemeral, so these counters support diagnosis and cannot establish
complete delivery counts. The bounded sink readback remains the acceptance
signal. No live setup or enablement was performed by this source change.
