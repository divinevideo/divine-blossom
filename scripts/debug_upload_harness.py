#!/usr/bin/env python3
"""Debug the Divine Blossom upload flow up to upload completion."""

from __future__ import annotations

import json


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
