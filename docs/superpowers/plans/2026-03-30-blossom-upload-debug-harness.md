# Blossom Upload Debug Harness Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python debug harness that can reproduce the Divine upload flow up to upload completion, print the exact HTTP traffic for each stage, and let us toggle resumable vs legacy upload plus ProofMode headers during incident debugging.

**Architecture:** Add a small script-oriented Python module under `scripts/` that owns request construction, request/response logging, and CLI argument parsing. Keep the first version focused on upload completion only, not publish-event creation, so it mirrors the failing path we are currently debugging: `HEAD /upload`, `POST /upload/init`, chunk `PUT /sessions/{id}`, `HEAD /sessions/{id}`, and `POST /upload/{id}/complete`.

**Tech Stack:** Python 3 stdlib (`argparse`, `hashlib`, `json`, `urllib`, `http.client`, `mimetypes`, `time`, `pathlib`), existing `scripts/` conventions, stdlib `unittest`.

---

## File Structure

- Create: `scripts/debug_upload_harness.py`
  - CLI entrypoint for legacy and resumable upload debugging.
  - Reads a local file, computes `sha256`, drives the upload flow, prints a readable transcript, and exits non-zero on server failure.
- Create: `scripts/tests/test_debug_upload_harness.py`
  - Unit tests for URL building, header shaping, chunk planning, ProofMode parsing, and response formatting.
- Modify: `README.md`
  - Add a short “debug upload harness” section under scripts or operations tooling with one resumable example and one ProofMode example.

## Chunk 1: Build the Scriptable Core

### Task 1: Define the harness surface and pure helpers

**Files:**
- Create: `scripts/debug_upload_harness.py`
- Test: `scripts/tests/test_debug_upload_harness.py`

- [ ] **Step 1: Write the failing tests for pure helper behavior**

```python
import unittest

from scripts.debug_upload_harness import (
    build_complete_body,
    build_proof_headers,
    chunk_ranges,
    normalize_server_url,
)


class DebugUploadHarnessTests(unittest.TestCase):
    def test_normalize_server_url_strips_trailing_slash(self) -> None:
        self.assertEqual(
            normalize_server_url("https://media.divine.video/"),
            "https://media.divine.video",
        )

    def test_chunk_ranges_cover_full_file(self) -> None:
        self.assertEqual(
            chunk_ranges(file_size=10, chunk_size=4),
            [(0, 4), (4, 8), (8, 10)],
        )

    def test_build_complete_body_includes_sha256(self) -> None:
        self.assertEqual(
            build_complete_body("ab" * 32),
            {"sha256": "ab" * 32},
        )

    def test_build_proof_headers_maps_expected_fields(self) -> None:
        proof = {
            "signature": "sig",
            "deviceAttestation": "att",
            "c2pa": {"manifest": "value"},
        }
        headers = build_proof_headers(proof)
        self.assertEqual(headers["X-ProofMode-Signature"], "sig")
        self.assertEqual(headers["X-ProofMode-Attestation"], "att")
        self.assertIn("X-ProofMode-C2PA", headers)
```

- [ ] **Step 2: Run the helper tests to verify they fail**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: FAIL with `ModuleNotFoundError` or missing symbol errors because the harness module does not exist yet.

- [ ] **Step 3: Write the minimal pure helpers in the new script**

```python
def normalize_server_url(server_url: str) -> str:
    return server_url.strip().rstrip("/")


def chunk_ranges(file_size: int, chunk_size: int) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    start = 0
    while start < file_size:
        end = min(start + chunk_size, file_size)
        ranges.append((start, end))
        start = end
    return ranges


def build_complete_body(file_hash: str) -> dict[str, str]:
    return {"sha256": file_hash}


def build_proof_headers(proof: dict[str, object]) -> dict[str, str]:
    headers: dict[str, str] = {}
    if "signature" in proof:
        headers["X-ProofMode-Signature"] = str(proof["signature"])
    if "deviceAttestation" in proof:
        headers["X-ProofMode-Attestation"] = str(proof["deviceAttestation"])
    if "manifest" in proof:
        headers["X-ProofMode-Manifest"] = str(proof["manifest"])
    if "c2pa" in proof:
        headers["X-ProofMode-C2PA"] = json.dumps(proof["c2pa"], separators=(",", ":"))
    return headers
```

- [ ] **Step 4: Re-run the helper tests to verify they pass**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: PASS for the helper tests above.

- [ ] **Step 5: Commit the helper-only scaffold**

```bash
git add scripts/debug_upload_harness.py scripts/tests/test_debug_upload_harness.py
git commit -m "feat: scaffold upload debug harness helpers"
```

### Task 2: Add an HTTP tracing client for upload endpoints

**Files:**
- Modify: `scripts/debug_upload_harness.py`
- Test: `scripts/tests/test_debug_upload_harness.py`

- [ ] **Step 1: Write failing tests for response summarization and transcript formatting**

```python
from scripts.debug_upload_harness import summarize_response


def test_summarize_response_truncates_large_bodies(self) -> None:
    summary = summarize_response(
        method="POST",
        url="https://media.divine.video/upload/init",
        status=500,
        headers={"content-type": "application/json"},
        body=b'{"error":"' + b"x" * 400 + b'"}',
    )
    self.assertIn("500", summary)
    self.assertIn("content-type", summary)
    self.assertIn("...", summary)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: FAIL because `summarize_response` does not exist yet.

- [ ] **Step 3: Add a tiny HTTP client wrapper that records every request/response**

```python
@dataclass
class Exchange:
    method: str
    url: str
    request_headers: dict[str, str]
    status: int
    response_headers: dict[str, str]
    response_body: bytes


def summarize_response(...):
    ...


class UploadHttpClient:
    def request(self, method: str, url: str, *, headers: dict[str, str], body: bytes | None) -> Exchange:
        ...
```

Implementation requirements:
- Print one block per exchange with method, URL, request headers, response status, response headers, and a truncated body preview.
- Preserve raw status and body for later failure analysis.
- Avoid logging file bytes; print lengths and hashes instead.

- [ ] **Step 4: Re-run tests to verify the transcript helper passes**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: PASS for helper and summarization tests.

- [ ] **Step 5: Commit the HTTP tracing layer**

```bash
git add scripts/debug_upload_harness.py scripts/tests/test_debug_upload_harness.py
git commit -m "feat: add traced HTTP client for upload debugging"
```

## Chunk 2: Drive the Actual Upload Flows

### Task 3: Implement legacy and resumable execution paths

**Files:**
- Modify: `scripts/debug_upload_harness.py`
- Test: `scripts/tests/test_debug_upload_harness.py`

- [ ] **Step 1: Write failing tests for chunk-planning and resumable request selection**

```python
from scripts.debug_upload_harness import should_use_resumable, chunk_ranges


def test_should_use_resumable_only_when_requested(self) -> None:
    self.assertTrue(should_use_resumable(mode="resumable"))
    self.assertFalse(should_use_resumable(mode="legacy"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: FAIL because the flow-selection helper does not exist yet.

- [ ] **Step 3: Implement the execution pipeline**

Required CLI shape:

```text
python3 scripts/debug_upload_harness.py \
  --server https://media.divine.video \
  --file /abs/path/video.mp4 \
  --mode resumable \
  --auth-header 'Nostr <signed-event>' \
  --proof-json /abs/path/proofmode.json
```

Required behavior:
- `HEAD /upload` to print advertised upload extensions and limits.
- `POST /upload/init` for resumable mode.
- Read `chunkSize`, `uploadId`, `uploadUrl`, and any required headers from the init response.
- Upload chunks with `Content-Length` and `Content-Range`.
- `HEAD /sessions/{uploadId}` after chunk upload and after failures.
- `POST /upload/{uploadId}/complete` with `{"sha256": "<hash>"}`.
- `PUT /upload` legacy path when `--mode legacy`.
- Optional `--proof-json` injects ProofMode headers only on completion for resumable mode, matching the mobile behavior we are debugging now.

- [ ] **Step 4: Re-run tests and a local help smoke check**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: PASS

Run: `python3 scripts/debug_upload_harness.py --help`
Expected: CLI usage output with `--server`, `--file`, `--mode`, `--auth-header`, `--proof-json`, `--chunk-size-override`, and `--timeout-seconds`.

- [ ] **Step 5: Commit the flow implementation**

```bash
git add scripts/debug_upload_harness.py scripts/tests/test_debug_upload_harness.py
git commit -m "feat: add legacy and resumable upload debug flow"
```

### Task 4: Add replay and debugging affordances for incident work

**Files:**
- Modify: `scripts/debug_upload_harness.py`
- Modify: `README.md`
- Test: `scripts/tests/test_debug_upload_harness.py`

- [ ] **Step 1: Write failing tests for optional incident helpers**

```python
from scripts.debug_upload_harness import load_proof_json


def test_load_proof_json_accepts_mobile_style_manifest(self) -> None:
    proof = load_proof_json("scripts/tests/fixtures/proofmode.json")
    self.assertIn("deviceAttestation", proof)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: FAIL because the loader and fixtures do not exist yet.

- [ ] **Step 3: Add the incident-focused options**

Required options:
- `--proof-json PATH` to load a captured ProofMode JSON file.
- `--complete-only --upload-id ID --file-hash HASH --file-size BYTES` to replay only the completion request for an existing session.
- `--chunk-size-override N` to reproduce chunk-size mismatches without relying on server-advertised values.
- `--dump-json PATH` to save the full transcript as machine-readable JSON for attaching to incidents.

Required transcript fields:
- file hash
- file size
- upload id
- each request URL
- each request headers set by the script
- each response status
- truncated response body preview
- final verdict (`success`, `init_failed`, `chunk_failed`, `session_head_failed`, `complete_failed`)

- [ ] **Step 4: Document the harness**

Add a short section to `README.md` that includes:
- one resumable example
- one `--proof-json` example
- one `--complete-only` replay example
- a note that v1 stops at upload completion and does not create the publish event

- [ ] **Step 5: Run end-to-end verification**

Run: `python3 -m unittest scripts.tests.test_debug_upload_harness -v`
Expected: PASS

Run: `python3 scripts/debug_upload_harness.py --help`
Expected: PASS

Run: `python3 scripts/debug_upload_harness.py --server https://media.divine.video --file /tmp/sample.mp4 --mode resumable --auth-header 'REPLACE_ME'`
Expected: The script should print a full request transcript and fail fast with the real server error if auth is invalid or completion fails.

- [ ] **Step 6: Commit the incident tooling polish**

```bash
git add scripts/debug_upload_harness.py scripts/tests/test_debug_upload_harness.py README.md
git commit -m "docs: add upload debug harness usage"
```

## Notes for the Implementer

- Keep the implementation script-first. Do not introduce a package install step or new third-party dependency unless a hard blocker appears.
- Use stdlib `unittest` so the harness can run anywhere we already have Python 3.
- Keep request/response logging explicit and boring. This tool exists for incidents, not ergonomics.
- Match current mobile completion behavior exactly:
  - resumable completion sends `{"sha256": fileHash}`
  - ProofMode headers are attached only on completion for resumable mode
- Defer publish-event creation to a later phase. That is a separate boundary from the current upload failure.

Plan complete and saved to `docs/superpowers/plans/2026-03-30-blossom-upload-debug-harness.md`. Ready to execute?
