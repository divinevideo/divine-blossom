# Recent Bad VTT Repair Script Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a script that fetches recent videos from `relay.divine.video`, detects corrupted VTT responses, and force-retranscribes only the bad ones.

**Architecture:** Use a standalone Python script in `cloud-run-transcoder/` with stdlib HTTP calls so it can run from the repo without extra dependencies. Keep the core detection and recent-video filtering logic as pure functions covered by unit tests, and use the existing `/v1/subtitles/jobs` force path for repair.

**Tech Stack:** Python 3 stdlib, `unittest`, relay API, Blossom subtitles API

---

## Chunk 1: Test And Script

### Task 1: Lock core detection behavior with a failing test

**Files:**
- Create: `cloud-run-transcoder/tests/test_repair_recent_bad_vtts.py`
- Create: `cloud-run-transcoder/repair_recent_bad_vtts.py`

- [ ] **Step 1: Write the failing test**

Add tests for:
- JSON-corrupted VTT detection
- valid VTT rejection
- recent relay video hash extraction with age filtering and dedupe

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest discover -s cloud-run-transcoder/tests -p 'test_repair_recent_bad_vtts.py'`
Expected: FAIL because the script module and helpers do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement:
- `is_bad_vtt_body`
- `collect_recent_media_hashes`
- the CLI flow to fetch relay videos, check VTTs, and force-retranscribe bad hashes

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s cloud-run-transcoder/tests -p 'test_repair_recent_bad_vtts.py'`
Expected: PASS

### Task 2: Verify the live dry-run path

**Files:**
- Modify: `cloud-run-transcoder/repair_recent_bad_vtts.py`

- [ ] **Step 1: Run a live dry-run against relay**

Run: `python3 cloud-run-transcoder/repair_recent_bad_vtts.py --days 7 --limit-videos 10 --dry-run`
Expected: script fetches recent relay videos, checks VTTs, and prints a summary without submitting repairs.

- [ ] **Step 2: Tighten output only if needed**

Adjust logging or request handling if the dry-run reveals a concrete issue.

- [ ] **Step 3: Re-run tests and dry-run**

Run:
- `python3 -m unittest discover -s cloud-run-transcoder/tests -p 'test_repair_recent_bad_vtts.py'`
- `python3 cloud-run-transcoder/repair_recent_bad_vtts.py --days 7 --limit-videos 10 --dry-run`

Expected: unit tests pass and dry-run completes successfully.
