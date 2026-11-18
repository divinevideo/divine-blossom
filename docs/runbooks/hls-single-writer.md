# HLS single-writer rollout and rollback

Ordinary `POST /transcode` accepts a job with HTTP 202 after Cloud Tasks
accepts it. `POST /transcode/queue` is the queue-only producer route.
The task owns retries and calls the authenticated
`POST /internal/transcode` worker. A worker returns 409 on contention so
Cloud Tasks retains the delivery. Forced HLS and MP4 repairs keep their
operator credential and synchronous results. On-demand MP4 remux uses the
same per-hash claim.

After successful playback admission, the edge records `Processing` so later
requests do not enqueue the same hash throughout a queue backlog. It leaves
the status unchanged on failed admission and does not overwrite a worker
callback that arrived before the admission response. The short POP-local
cache is only a secondary guard. Completion remains worker-owned.

The trusted archive import `process-transcode` operation also enters this
queue. Its `accepted:true` response confirms admission, not HLS readiness;
the worker callback records completion. Include archive followup traffic in
the representative queue-load check below and control importer admission
before rollout; synchronous encode latency no longer paces that producer.

## Storage and recovery

The transcoder creates `.internal/hls-claims/{hash}` in the configured
GCS bucket with `ifGenerationMatch=0`. Every renewal, state transition,
and release compares the live GCS generation. This namespace is outside the
media prefix. Exclude it from age-based deletion and manual cleanup while
writers are active.

Preparation has a renewable 90-second lease, with 20-second heartbeats
during long operations. Each stable-key PUT is journaled before it is sent,
with an attempt marker carried on the object. A stale journal with a PUT in
flight can be replaced when the recorded provider and key show that marker.
An explicit rejection allows the same owner to release immediately. An
ambiguous write with no matching marker stays fenced. The provider may still
commit it after the client times out.

Keep the queue's retries, and alert on `recovery_failed`, `release_failed`,
`admission_failed`, and exhausted task delivery. If automatic retries run
out, use the normal transcode admission path for the affected item once the
failure is resolved. Uploads still preserve the original even when the
initial derivative handoff fails. Bounded upload admission retries run before
the publisher logs an error. An operator can replay that hash through ordinary
admission, and a subsequent HLS playback request can admit a pending item.
For a fenced ambiguous write, inspect the exact provider
object and attempt marker privately. Allow automatic recovery if the marker
appears. Otherwise keep the item fenced until the old worker has stopped and
the provider confirms the write cannot still commit. Any manual reset must
compare the exact current claim generation and preserve its dirty state as
`Retry`. An ordinary job must re-verify or regenerate the set before it sends
a completion callback. Treat a CDN response, a missing object, and elapsed
time as insufficient evidence for clearing an uncertain write.

## Rollout

1. Validate with synthetic short, rotated, silent, audio-bearing, and
   variable-frame-rate sources in an isolated service with isolated buckets and
   a test queue. Exercise simultaneous independent dispatch, completion replay,
   forced repair, MP4 aliases, a worker killed before publication, and a backup
   write failure. Verify both provider copies, provenance, and callback order.
   Test the queue admission and retry behavior under representative burst
   concurrency, including queue depth and oldest task age.
2. Confirm the existing transcode queue is dedicated to HLS and its runtime
   identity can create tasks. Check the serving revision's queue, status
   callbacks, storage mode, bindings, and tagged callers without looking up
   secret values. Set `TRANSCODE_QUEUE` to the existing fully qualified queue
   path and `TRANSCODE_WORKER_URL` to the stable HTTPS service origin on the
   candidate. Bind `TRANSCODE_DISPATCH_SECRET` to a pinned version of a
   dedicated Secret Manager resource. The deploy script requires
   `TRANSCODE_DISPATCH_SECRET_NAME` and `TRANSCODE_DISPATCH_SECRET_VERSION`.
   Keep that version enabled and keep
   producer and worker on the same version until tasks signed with it are
   drained. Assess any existing queued payloads before switching the target.
   Drain legacy deliveries or account for each retained delivery in the
   transition. The new upload producer calls the queue-only route directly.
   Confirm a queue-enabled legacy producer has been updated before resuming
   dispatch, to avoid two queue deliveries per upload. Keep the queue's
   configured rates and retry policy.
3. Merging this change triggers the normal upload and edge deployment. Treat
   the merge as part of a separately authorized rollout. The upload deploy
   preserves omitted derivative bindings and its new caller supports the
   legacy transcoder until the writer cutover. Ship the playback handler before
   enabling the new writer. It keeps
   serving readable HLS while leaving completion to the verified worker
   callback. The updated reset-stuck sweep sends a verification request when
   it sees a master. It does not infer completion from the master.
4. The deployment script creates a revision with no traffic and defaults to
   `TRANSCODE_WRITES_PAUSED=true`. Prepare the paused candidate and verify
   its bindings without reading secret values. Pause queue
   dispatch, switch all ordinary intake to the paused candidate, and hold
   operator jobs. The candidate continues to admit ordinary requests
   durably and keeps subtitle routes serving. Remove or retarget every
   legacy writer tag, including tags used by other routes. Verify those
   callers retain their original behavior and that no old derivative
   endpoint is externally reachable. Confirm old revisions have no running
   instances and no remaining unconfirmed provider writes. A traffic
   percentage of zero or the Cloud Run request timeout alone does not show
   that a legacy writer stopped. Keep writes paused if a legacy writer's
   termination or publication outcome is unresolved.
5. Route all writer traffic to the new unpaused revision. Resume existing queue
   dispatch. Use synthetic and sampled authorized read-only checks to verify
   serving revision, durable dispatch, publication and backup readiness,
   playback, subtitles, and terminal callbacks. Keep old writer revisions
   off all usable write paths. Existing originals, derivatives, and CDN URLs
   are used in place. No backfill is part of this rollout.

## Rollback

Prefer a rollback build that retains the claim protocol and queue endpoint.
Return traffic to the paused candidate and pause dispatch if a problem affects
publication integrity. Verify the previous writers have stopped and reconcile
any uncertain PUT before allowing a different protocol to write.

For an emergency rollback to the legacy image, preserve every queued job.
While dispatch is paused, route retained HTTP tasks on the dedicated queue
to the legacy `/transcode` path using a tested queue-level URI override, or
keep the queue paused for replay through a compatible worker. Confirm the
override targets only the intended service. Google requires waiting a minute
after a queue routing update before resuming dispatch. Switch writer traffic
to the legacy revision only after the new writers are fully drained, then
resume the intended route. Never purge the queue or discard a write journal
blindly. Legacy behavior permits duplicate encodes, so monitor them during
the rollback. Before the next forward cutover, remove the temporary override
and repeat the drain procedure.

## Measuring the result

Use matched active windows with similar media duration, source format, traffic
mix, and task arrival rate. Report privately:

- Successful encodes minus distinct successfully encoded hashes. Keep
  per-hash reconciliation within access-controlled logs. Identify intentional
  repairs separately and count verified cache reuse separately from encodes.
- Cloud Run allocated vCPU-seconds and outbound internet bytes per distinct
  successful item. Use provider destination and billing SKUs to attribute
  egress. Compare B2 reads as well as writes so repeated verification reads
  are visible. Keep service-wide CPU and network metrics labeled as such.
- Distinct verified deliveries per minute, queue age and depth, upload-to-ready
  p50/p95/p99, backup verification failures, and HLS/MP4 playback errors. Check
  new user-upload subtitle completion without initiating archive subtitles.
- Cash savings from incremental billed compute and transfer, with Cloud Tasks
  and GCS coordination requests included. Keep the two charge categories distinct.
  Apply contractual credits and committed usage before estimating avoided
  spend. Report freed committed capacity separately from cash savings.

A lower duplicate count accompanied by falling distinct throughput, rising
queue age, slower playback readiness, or weaker backup verification fails
the rollout acceptance check. The existing dispatch limit and added storage
operations must be exercised under representative load before promotion.
