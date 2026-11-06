# Verified playback artifact families

The approved first family is the existing two-rendition single-file VOD HLS output plus progressive MP4: under the full parent SHA-256 /hls/ prefix, master.m3u8 and stream_720p/stream_480p each with .m3u8, .ts and .mp4. Public /720p.mp4 and /480p.mp4 aliases map to these stream filenames (blossom-core/src/types.rs). The transcoder's FFmpeg command uses hls_flags single_file; upload_hls_to_gcs currently uploads arbitrary directory order and metadata patch errors are nonfatal. Existence alone therefore cannot prove a complete producer revision.

## Approved slices

1. Pure identity, size and manifest-closure validation, independently testable without storage credentials. No writer-marker schema is guessed or enabled in this slice.
2. Durable bounded replication using a verified producer completion inventory, immutable destination revision namespace, pinned object versions, the unchanged parent copy/erase gate and completion publication last. This requires the producer marker contract being implemented by the producer owner. Missing/stale marker stays pending.
3. Reader revision integration: canonical aliases select a verified family; HLS child URLs bind to that revision. Version-qualified reads never fall back to latest keys. MP4 range/If-Range and native seek tests must prevent cross-revision byte mixing. PR338's latest-key reader is insufficient for activation.

No provider changes or activation are included. Mutable transcript coordination remains separate. Parent policy uses the existing approved_metadata semantics, including legal pending media, quarantine, tombstone and owner/reference vanish checks; copying never grants publication approval.

## Slice 1 contract

Create scripts/b2_playback_family.py with frozen ObjectIdentity(provider,bucket,key,version), validate_source_identity(value, expected_key), family_keys(parent), and validate_playback_family(parent, manifests, sizes). ObjectRef shape follows divine-upload-server docs/contracts/media-finalized-v1.md: version is an exact opaque provider generation/version, never an ETag or URL. The expected object key is supplied by the trusted inventory consumer; source identities cannot retarget it. Parent SHA and artifact SHA remain distinct; the latter is supplied and independently verified by the later replica, not inferred from the filename.

Accept exactly seven positive-size files, at most 32 MiB per artifact and 64 MiB per family. These are bounded replication admission limits, not claims about CDN cache capacity. Manifest bodies are at most 64 KiB and there are at most 1024 segment references per rendition. Only current two-variant, unencrypted, single-file VOD HLS is supported. Require complete master closure over both known variant playlists, complete ENDLIST media playlists, matching TS references, and explicit/inherited byte ranges within the referenced TS size. Reject foreign/absolute/query/traversal URIs, encryption/maps/media or other unimplemented tags, malformed ordering, duplicate variants, invalid UTF-8 and unfinished playlists. Unsupported families stay unready; no input URI is fetched.

The returned upload order is payloads first, variant playlists next, master last. Returning an order does not publish readiness or prove producer completion; later slices must require the writer inventory, independent checksums, policy and source identity rechecks, destination pinned rereads and durable completion.

## Remaining schema coordination

The producer marker must carry producer_job_id, pipeline_version, parent identity and original size, revision identity (never UUID ordering), exact seven artifact identities/checksums/sizes/types and explicitly allowlisted metadata. Existing media-finalized-v1 source ObjectRef is provider-neutral. The consumer does not yet implement that finalization event; do not invent a legacy job generation. Marker publication belongs to the assigned producer workstream. Detailed persistent state and reader routes will be reviewed in their own slices after this contract.

## Parser references and verification

Line syntax and byte-range inheritance follow [RFC 8216 section 4.1](https://www.rfc-editor.org/rfc/rfc8216#section-4.1) and [section 4.3.2.2](https://www.rfc-editor.org/rfc/rfc8216#section-4.3.2.2). This is a deliberately narrow validator for the existing producer shape, not a general HLS implementation. It preserves actual URI line bytes, accepts LF/CRLF and blank lines, rejects other line-ending interpretations, and requires version 4 or newer for byte ranges.

Fourteen focused tests pass after observed RED failures. An independent review found whitespace/Unicode-line normalization could validate different references from copied bytes; the regression was reproduced, fixed, and re-reviewed clear. A locally generated FFmpeg 8.1.2 single_file VOD family plus remuxed MP4s passed. This does not establish deployed FFmpeg 4.4 compatibility or live provider behavior.

## Private control erasure

The reserved parent control namespace is `_private/artifact-families/v1/{parent}/`,
including `complete.json`. Physical erasure must confirm this namespace absent
alongside the parent media prefix. B2 deletes retained uploads and hide markers by
file ID under the permanent parent erasing gate. A shared four-version delete cap
and at most four listings retain the existing eight-request per-hash ceiling;
remaining history stays pending across caller retries. Completion and purge
receipts must wait for both namespace confirmations.

Cloud Run cleanup lists all private control generations and deletes by exact
GCS generation, sharing its existing 25-object slice and 30-second deadline with
parent cleanup. The HTTP request and response contract is unchanged. The service
cleanup change must be deployed before relying on this private-generation cleanup
in edge completion. Existing GCS parent-media generation and retention semantics
are unchanged; this does not establish historical GCS retirement or remove
provider retention and legal holds. Listing, deletion, or verification uncertainty
keeps cleanup retryable.
