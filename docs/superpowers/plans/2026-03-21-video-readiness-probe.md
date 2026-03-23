# Video Readiness Probe Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add live probe scripts and unit-tested diagnosis logic for the progressive MP4 vs HLS readiness hypothesis.

**Architecture:** Keep the network probing in Python scripts under `scripts/` and keep the diagnosis logic pure and reusable so both scripts can share it. Cover the shared logic with direct unit tests under `cloud-run-transcoder/tests/`.

**Tech Stack:** Python standard library, `unittest`, HTTPS `HEAD` requests

---

## Chunk 1: Shared Probe Logic And Tests

### Task 1: Add failing tests for verdict classification and hash parsing

**Files:**
- Test: `cloud-run-transcoder/tests/test_video_readiness_probe.py`
- Create: `scripts/probe_video_readiness.py`

- [ ] **Step 1: Write the failing test**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Add minimal shared helpers to make the test pass**
- [ ] **Step 4: Run test to verify it passes**

### Task 2: Build the single-hash readiness probe CLI

**Files:**
- Modify: `scripts/probe_video_readiness.py`

- [ ] **Step 1: Add CLI parsing and URL builders**
- [ ] **Step 2: Add HTTP probe execution and timestamped output**
- [ ] **Step 3: Add final verdict rendering**
- [ ] **Step 4: Run tests and a live probe sanity check**

## Chunk 2: Batch Coverage Script

### Task 3: Build the batch progressive coverage checker

**Files:**
- Create: `scripts/check_progressive_coverage.py`
- Modify: `scripts/probe_video_readiness.py`

- [ ] **Step 1: Add reusable input hash loading helpers**
- [ ] **Step 2: Build the one-shot batch probe CLI**
- [ ] **Step 3: Add summary reporting for MP4 vs HLS availability**
- [ ] **Step 4: Run a small live sample against known hashes**
