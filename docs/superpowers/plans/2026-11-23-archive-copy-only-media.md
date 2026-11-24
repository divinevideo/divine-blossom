# Archive copy-only delivery implementation plan

**Goal:** Only new authenticated user uploads receive permission to encode video. Classic Vine delivery may package existing compressed streams into HLS/MP4, but never re-encode video or audio as a delivery fallback. Preserve original bytes, B2 verification, ownership/erasure rules and existing archive publishing holds.

**Approach:** Keep the existing queue and worker. Persist a server-owned `video_encoding_allowed` boolean on new upload metadata; missing legacy permission means copy-only. Trusted archive storage always overrides permission. Archive publisher upload requests opt out through `X-Divine-Video-Processing: copy-only`, which only reduces processing and never asserts provenance or elevates authorization. Duplicate uploads preserve policy. A narrow uncached authenticated policy endpoint informs every worker execution, including old queued jobs, repair and MP4 backfill. Unknown metadata retries. Existing derivatives remain readable; copy-incompatible jobs terminate with the existing 422/original fallback contract.

This avoids an expensive historical hash-classification backfill and avoids guessing from creator identity, dimensions or timestamps. Older user uploads without existing derivatives may be copy-only until explicitly granted permission; no automatic bulk upgrades are part of this change. Standalone audio extraction, subtitles, moderation and thumbnails are separate operations.

- [x] Add metadata default/serialization and archive-precedence tests, then explicit encode permission.
- [x] Grant permission only in new authenticated upload publication paths; honor restrictive opt-out and preserve duplicate/read-through policy.
- [x] Add private no-store metadata-policy route with existing webhook authentication, full-hash validation and unavailable retry semantics.
- [x] Ensure missing progressive aliases for copy-only sources fall back to original without repeated remux polling.
- [x] Worker: fetch policy with bounded authenticated request; enforce copy-only for ordinary, force, and audio-remux fallback; preserve publication fencing.
- [x] Publisher: opt out on both PUT sites, test all wrappers, preserve holds and original authentication/content.
- [ ] Run core, edge/Viceroy, worker real-FFmpeg, publisher tests and CI; independently review exact combined heads.
- [ ] Coordinate one Hetzner deployment owner. Verify real storage, callbacks and playback on staged worker before changing queue target. No duplicate server provisioning or archive publishing resume.

**Rollout:** Publish the archive opt-out producer before resuming any held archive uploads. Deploy edge permission/lookup before enabling policy-aware workers; worker missing URL remains copy-only. Keep new-user upload metadata creation and queue execution ordering covered by retries. Integrate the currently deployed OwnershipLost fix before promotion. Hetzner migration and the publishing hold are owned independently; do not overwrite either.
