# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed
- Fixed HTTP Range request handling for quality variant endpoints (`/{hash}/720p`, `/{hash}/480p`)
  - iOS AVPlayer `CoreMediaErrorDomain -12939` ("byte range length mismatch") caused by returning full file instead of requested byte range
  - Quality variant handler now forwards client `Range` header to GCS and returns proper `206 Partial Content` responses
  - Fixes video playback on iOS for transcoded quality variants

### Added
- MIME type inference from file extension when metadata is missing
  - Supports video (mp4, webm, mov, avi, mkv, ogv), image (jpg, png, gif, webp, svg, avif), and audio (mp3, wav, ogg, flac, m4a) formats

### Fixed
- Added `Content-Length` header to GET responses (was missing)
- Added `Accept-Ranges: bytes` header to all blob responses for proper video streaming support
- Added `X-Content-Length` header as workaround for HTTP/2 stripping Content-Length on HEAD responses
- Fixed range requests (206 Partial Content) - no longer overwrites Content-Length with full file size
- Improved header consistency between GET and HEAD responses

### Added (previous)
- Cloud Run upload service for handling large file uploads (>500KB)
  - Rust-based service with Nostr auth validation
  - Streaming upload to GCS with SHA-256 hashing
  - HTTP/2 support to bypass Fastly 32MB body size limit
- Fastly proxy to Cloud Run for large uploads
  - Files <500KB handled in-process via AWS v4 signed GCS uploads
  - Files >500KB proxied to Cloud Run service
- Migration scripts for blob data migration
  - Bucket-to-bucket copy script using HMAC/S3 API for GCS
- Cloud Functions for content moderation (process-blob)
- BUD-04 mirroring with automatic blob retrieval from fallback CDNs
- BUD-06 pre-upload validation support
- CDN fallback chain (cdn.divine.video, blossom.divine.video, cdn.satellite.earth, image.nostr.build)

### Changed
- Fastly Compute now routes large uploads to Cloud Run instead of streaming in-process
  - Fixes WASM memory OOM issues with large files
- Updated .gitignore to exclude Rust target directories in subdirectories
- Switched from staging to production GCS bucket (divine-blossom-media)

### Fixed
- WASM out-of-memory errors when uploading files >5MB
- Production GCS bucket IAM permissions for public read access and Cloud Run uploads
- Cloud Run upload proxy returning 404 errors due to incorrect Host header
  - Fastly was sending `Host: media-backend.divine.video` but Cloud Run domain mapping wasn't configured
  - Fixed by using actual Cloud Run hostname `blossom-upload-rust-*.us-central1.run.app` in Host header
