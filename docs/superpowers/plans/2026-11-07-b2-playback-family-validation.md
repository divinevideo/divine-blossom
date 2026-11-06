# B2 playback family validation implementation plan

> **For agentic workers:** Use superpowers:executing-plans task by task.

**Goal:** Reject incomplete or unsafe current playback families before any replication or readiness publication.
**Architecture:** A pure bounded parser validates the exact producer file layout and versioned object identities. Provider calls, persistence and reader routes are separate subsequent slices.
**Tech Stack:** Python standard library and unittest.
**Spec:** ../specs/2026-11-07-b2-playback-family-design.md

## Global constraints

Seven files; 32 MiB per file; 64 MiB total; 64 KiB per manifest; 1024 segment references per variant. Full lowercase SHA-256 parent identities. Preserve provider-neutral ObjectRef. No network, credentials, provider changes or mutable transcript state.

## Review focus

URI traversal/foreign references, missing/duplicate files, malformed byte-range inheritance, incomplete VOD output, and provider/version identity confusion must all fail before publication.

## Task 1: Implement the pure family contract

Files: scripts/b2_playback_family.py; scripts/tests/test_b2_playback_family.py.
Interfaces: family_keys(parent: str) -> tuple[str,...]; validate_source_identity(value: dict, expected_key: str) -> ObjectIdentity; validate_playback_family(parent: str, manifests: dict[str,bytes], sizes: dict[str,int]) -> tuple[str,...].

- [x] Write valid two-rendition fixtures and rejection tests covering each boundary in the spec.
- [x] Run python3 -m unittest scripts.tests.test_b2_playback_family -v; observe missing implementation failure.
- [x] Implement identity and manifest validation without fetching any URI or accepting unknown tags.
- [x] Run the focused tests and existing original-worker tests; verify unchanged original key/gate contracts.
- [ ] Obtain fresh independent review, fix test-backed findings, commit and open source PR. Inspect CI and leave provider activation off.

## Later slices

Implement durable replication and revision readers separately after producer contract coordination. This validation slice alone does not migrate any object, establish readiness or solve client parity.

## Verification record

2026-11-07: 14 focused tests pass; full repository script suite passes 416 tests in the requirements-b2-sync virtual environment. Initial broad run encountered missing SDK dependencies and local disk exhaustion; rerun after installing the existing requirements and reclaiming only this agent’s completed build cache passed. Fresh independent review is clear after the line-byte normalization regression was reproduced and fixed. PR delivery and CI follow.
