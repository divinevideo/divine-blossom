# Route canonical uploads through the provider-aware upload service

`upload_service_all_uploads=true` sends every canonical direct `PUT /upload`
through the existing authenticated `upload_service` backend, including small
images. Missing configuration or exact `false` retains the current policy:
all recognized video types and nonvideo above 500 KiB are proxied; smaller
nonvideo is handled inline. Any other value or unavailable configuration
store fails before upload body forwarding/storage. Explicit local synthetic
mode retains its inline behavior.

The existing BUD authentication check runs first. Proxy requests retain the
same auth, content type, size, body and request correlation. The existing
upload-service response validation/public descriptor publication is reused.
An upstream failure never selects inline GCS as a retry or fallback. The flag
does not alter resumable sessions or internal thumbnail/VTT/audio/audit writes.

## Reuse existing writer and finalization support

The upload service already implements provider selection, multipart uploads,
provider-pinned sessions and a durable processing outbox in
[upload-server31](https://github.com/divinevideo/divine-upload-server/pull/31).
[Upload-server32](https://github.com/divinevideo/divine-upload-server/pull/32)
preserves unfinished direct/mirror provider policies across mode changes and
adds atomic resumable completion receipts. Reuse these implementations rather
than adding another B2 SDK or outbox to the edge.

Routing through this service does not itself enable B2 storage. Its default
`MEDIA_WRITE_PROVIDER` is GCS. B2/dual activation requires scoped raw-upload
storage authority, coordination database and an actually compatible durable
finalization consumer. The approved-only playback replica is not an upload
destination. Existing GCS-finalize processing/transcoding consumers must not
be assumed to implement the upload server's `media-finalized-v1` contract.

The inline route previously performed checks after buffering/hash calculation;
this mode uses the existing proxy's policy/publication boundaries. Complete
writer/processing erasure exclusion and durable finalization remain required
before B2 activation. This routing flag alone does not prove migration safety.

## Staged rollout

This source change is default-off and performs no provider configuration.
Before enabling, verify the actual `upload_service` backend, service image,
write mode and required storage/consumer bindings; retain accepted session
provider mappings during rollback. Test representative small image, audio,
video, direct and resumable clients with the service's actual admission limits.
The upload server's bounded concurrency defaults are not a production capacity
measurement. Additional small requests previously handled inline increase its
load; verify saturation, Retry-After behavior and recovery with real clients.

Use owned fixtures to verify SHA/size, descriptors, publication/ownership,
processing completion, ordinary rendition playback and full erasure, including
GCS-denied integration tests for B2-only uploads. Retrying a failed write on a
different provider is not rollback. Disable only this routing flag to restore
new-request selection; already accepted resumable/provider-pinned work must
still complete against its recorded providers.

## Offline validation

```sh
cargo test -p blossom-core --locked upload_routing
VICEROY=<local-viceroy> python3 scripts/run-upload-routing-tests.py
```

The loopback fixture executes the real canonical handler with signed synthetic
auth and verifies a small image reaches the service exactly once, byte-for-byte,
without GCS credentials configured. It preserves upstream failure, rejects
invalid config/auth before dispatch and checks default/disabled routing and
missing-store failure. These tests do not establish live storage, processing,
capacity or native playback parity.
