#!/usr/bin/env python3
"""Debug the Divine Blossom upload flow up to upload completion."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import mimetypes
from pathlib import Path
import sys
from typing import Any, BinaryIO, Callable, TextIO
import urllib.error
import urllib.request


DEFAULT_TIMEOUT_SECONDS = 30
SUCCESS_STATUSES = {200, 201, 204}


class HarnessError(RuntimeError):
    """Raised when the harness cannot execute a request or parse a response."""


@dataclass
class FileContext:
    path: Path
    file_hash: str
    file_size: int
    content_type: str
    file_name: str


@dataclass
class Exchange:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body_summary: str
    status: int
    response_headers: dict[str, str]
    response_body: bytes
    response_body_preview: str

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "requestHeaders": self.request_headers,
            "requestBodySummary": self.request_body_summary,
            "status": self.status,
            "responseHeaders": self.response_headers,
            "responseBodyPreview": self.response_body_preview,
        }


@dataclass
class HarnessResult:
    verdict: str
    mode: str
    server: str
    file_hash: str
    file_size: int
    upload_id: str | None
    exchanges: list[Exchange]

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "server": self.server,
            "fileHash": self.file_hash,
            "fileSize": self.file_size,
            "uploadId": self.upload_id,
            "verdict": self.verdict,
            "exchanges": [exchange.to_dict() for exchange in self.exchanges],
        }


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


def should_use_resumable(*, mode: str) -> bool:
    return mode == "resumable"


def load_proof_json(path: str | Path) -> dict[str, object]:
    proof_path = Path(path)
    return json.loads(proof_path.read_text(encoding="utf-8"))


def _encode_proof_header_value(value: object) -> str:
    string_value = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return base64.b64encode(string_value.encode("utf-8")).decode("ascii")


def build_proof_headers(proof: dict[str, object]) -> dict[str, str]:
    headers: dict[str, str] = {}
    manifest_json = json.dumps(proof, separators=(",", ":"))
    headers["X-ProofMode-Manifest"] = base64.b64encode(
        manifest_json.encode("utf-8")
    ).decode("ascii")
    if "pgpSignature" in proof:
        headers["X-ProofMode-Signature"] = _encode_proof_header_value(
            proof["pgpSignature"]
        )
    if "deviceAttestation" in proof:
        headers["X-ProofMode-Attestation"] = _encode_proof_header_value(
            proof["deviceAttestation"]
        )
    c2pa_manifest_id = proof.get("c2paManifestId") or proof.get("c2pa_manifest_id")
    if c2pa_manifest_id is not None:
        headers["X-ProofMode-C2PA"] = _encode_proof_header_value(c2pa_manifest_id)
    return headers


def summarize_request_body(
    *,
    body: bytes | None,
    headers: dict[str, str],
    max_body_chars: int = 160,
) -> str:
    if body is None or len(body) == 0:
        return "(empty)"

    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    if "json" in content_type or content_type.startswith("text/"):
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = repr(body)
        if len(body_text) > max_body_chars:
            body_text = f"{body_text[:max_body_chars]}..."
        return body_text

    body_hash = hashlib.sha256(body).hexdigest()
    return f"<binary bytes={len(body)} sha256={body_hash}>"


def summarize_response(
    *,
    method: str,
    url: str,
    status: int,
    headers: dict[str, str],
    body: bytes,
    max_body_chars: int = 160,
) -> str:
    try:
        body_text = body.decode("utf-8", errors="replace")
    except Exception:
        body_text = repr(body)
    if len(body_text) > max_body_chars:
        body_text = f"{body_text[:max_body_chars]}..."
    return (
        f"{method} {url}\n"
        f"status: {status}\n"
        f"headers: {headers}\n"
        f"body: {body_text}"
    )


def format_exchange(exchange: Exchange) -> str:
    return (
        f"{exchange.method} {exchange.url}\n"
        f"request headers: {exchange.request_headers}\n"
        f"request body: {exchange.request_body_summary}\n"
        f"status: {exchange.status}\n"
        f"response headers: {exchange.response_headers}\n"
        f"response body: {exchange.response_body_preview}\n"
    )


class UploadHttpClient:
    def __init__(
        self,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        opener: Callable[..., Any] | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self._opener = opener or urllib.request.urlopen
        self._output_stream = output_stream or sys.stdout
        self.exchanges: list[Exchange] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
    ) -> Exchange:
        normalized_headers = {str(key): str(value) for key, value in headers.items()}
        request_body_summary = summarize_request_body(body=body, headers=normalized_headers)
        request = urllib.request.Request(
            url=url,
            data=body,
            headers=normalized_headers,
            method=method.upper(),
        )

        try:
            response = self._opener(request, timeout=self.timeout_seconds)
            status = int(response.getcode())
            response_headers = {key: value for key, value in response.headers.items()}
            response_body = response.read()
            if hasattr(response, "close"):
                response.close()
        except urllib.error.HTTPError as error:
            status = int(error.code)
            response_headers = (
                {key: value for key, value in error.headers.items()}
                if error.headers is not None
                else {}
            )
            response_body = error.read()
            if hasattr(error, "close"):
                error.close()
        except urllib.error.URLError as error:
            raise HarnessError(f"{method.upper()} {url} failed: {error.reason}") from error

        response_body_preview = summarize_response(
            method=method.upper(),
            url=url,
            status=status,
            headers=response_headers,
            body=response_body,
        ).split("body: ", 1)[1]
        exchange = Exchange(
            method=method.upper(),
            url=url,
            request_headers=normalized_headers,
            request_body_summary=request_body_summary,
            status=status,
            response_headers=response_headers,
            response_body=response_body,
            response_body_preview=response_body_preview,
        )
        self.exchanges.append(exchange)
        self._output_stream.write(format_exchange(exchange))
        self._output_stream.flush()
        return exchange


def parse_json_object(body: bytes, *, context: str) -> dict[str, object]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise HarnessError(f"{context} returned invalid JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise HarnessError(f"{context} returned a non-object JSON payload")
    return parsed


def compute_file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_content_type(path: Path, override: str | None) -> str:
    if override:
        return override
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def resolve_file_context(file_path: Path, content_type_override: str | None) -> FileContext:
    return FileContext(
        path=file_path,
        file_hash=compute_file_sha256(file_path),
        file_size=file_path.stat().st_size,
        content_type=resolve_content_type(file_path, content_type_override),
        file_name=file_path.name,
    )


def read_chunk(path: Path, start: int, end: int) -> bytes:
    with path.open("rb") as handle:
        handle.seek(start)
        return handle.read(end - start)


def build_init_request_body(file_context: FileContext) -> bytes:
    payload = {
        "sha256": file_context.file_hash,
        "size": file_context.file_size,
        "contentType": file_context.content_type,
        "fileName": file_context.file_name,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def build_complete_request_body(file_hash: str) -> bytes:
    return json.dumps(build_complete_body(file_hash), separators=(",", ":")).encode(
        "utf-8"
    )


def read_required_string(payload: dict[str, object], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise HarnessError(f"Missing or invalid {field_name!r} in init response")
    return value


def read_required_int(payload: dict[str, object], field_name: str) -> int:
    value = payload.get(field_name)
    if not isinstance(value, int):
        raise HarnessError(f"Missing or invalid {field_name!r} in init response")
    return value


def read_required_headers(payload: dict[str, object]) -> dict[str, str]:
    required_headers = payload.get("requiredHeaders", {})
    if not isinstance(required_headers, dict):
        raise HarnessError("Init response contained invalid requiredHeaders")
    return {str(key): str(value) for key, value in required_headers.items()}


def run_head_upload(client: UploadHttpClient, server_url: str) -> Exchange:
    return client.request("HEAD", f"{server_url}/upload", headers={}, body=None)


def run_session_head(
    client: UploadHttpClient, upload_url: str, required_headers: dict[str, str]
) -> Exchange:
    return client.request("HEAD", upload_url, headers=required_headers, body=None)


def request_complete(
    *,
    client: UploadHttpClient,
    server_url: str,
    upload_id: str,
    auth_header: str,
    file_hash: str,
    proof_headers: dict[str, str] | None,
) -> Exchange:
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
    }
    if proof_headers:
        headers.update(proof_headers)
    body = build_complete_request_body(file_hash)
    headers["Content-Length"] = str(len(body))
    return client.request(
        "POST",
        f"{server_url}/upload/{upload_id}/complete",
        headers=headers,
        body=body,
    )


def run_resumable_upload(
    *,
    client: UploadHttpClient,
    server_url: str,
    file_context: FileContext,
    auth_header: str,
    proof_headers: dict[str, str] | None,
    chunk_size_override: int | None,
) -> HarnessResult:
    run_head_upload(client, server_url)

    init_body = build_init_request_body(file_context)
    init_exchange = client.request(
        "POST",
        f"{server_url}/upload/init",
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "Content-Length": str(len(init_body)),
        },
        body=init_body,
    )
    if init_exchange.status not in {200, 201}:
        return HarnessResult(
            verdict="init_failed",
            mode="resumable",
            server=server_url,
            file_hash=file_context.file_hash,
            file_size=file_context.file_size,
            upload_id=None,
            exchanges=list(client.exchanges),
        )

    init_payload = parse_json_object(init_exchange.response_body, context="/upload/init")
    upload_id = read_required_string(init_payload, "uploadId")
    upload_url = read_required_string(init_payload, "uploadUrl")
    chunk_size = chunk_size_override or read_required_int(init_payload, "chunkSize")
    required_headers = read_required_headers(init_payload)

    for start, end in chunk_ranges(file_context.file_size, chunk_size):
        chunk_body = read_chunk(file_context.path, start, end)
        chunk_headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(chunk_body)),
            "Content-Range": f"bytes {start}-{end - 1}/{file_context.file_size}",
        }
        chunk_headers.update(required_headers)
        chunk_exchange = client.request(
            "PUT",
            upload_url,
            headers=chunk_headers,
            body=chunk_body,
        )
        if chunk_exchange.status not in SUCCESS_STATUSES:
            run_session_head(client, upload_url, required_headers)
            return HarnessResult(
                verdict="chunk_failed",
                mode="resumable",
                server=server_url,
                file_hash=file_context.file_hash,
                file_size=file_context.file_size,
                upload_id=upload_id,
                exchanges=list(client.exchanges),
            )

    session_head_exchange = run_session_head(client, upload_url, required_headers)
    if session_head_exchange.status not in SUCCESS_STATUSES:
        return HarnessResult(
            verdict="session_head_failed",
            mode="resumable",
            server=server_url,
            file_hash=file_context.file_hash,
            file_size=file_context.file_size,
            upload_id=upload_id,
            exchanges=list(client.exchanges),
        )

    complete_exchange = request_complete(
        client=client,
        server_url=server_url,
        upload_id=upload_id,
        auth_header=auth_header,
        file_hash=file_context.file_hash,
        proof_headers=proof_headers,
    )
    verdict = "success" if complete_exchange.status in {200, 201} else "complete_failed"
    return HarnessResult(
        verdict=verdict,
        mode="resumable",
        server=server_url,
        file_hash=file_context.file_hash,
        file_size=file_context.file_size,
        upload_id=upload_id,
        exchanges=list(client.exchanges),
    )


def run_complete_only(
    *,
    client: UploadHttpClient,
    server_url: str,
    upload_id: str,
    auth_header: str,
    file_hash: str,
    file_size: int,
    proof_headers: dict[str, str] | None,
) -> HarnessResult:
    complete_exchange = request_complete(
        client=client,
        server_url=server_url,
        upload_id=upload_id,
        auth_header=auth_header,
        file_hash=file_hash,
        proof_headers=proof_headers,
    )
    verdict = "success" if complete_exchange.status in {200, 201} else "complete_failed"
    return HarnessResult(
        verdict=verdict,
        mode="resumable",
        server=server_url,
        file_hash=file_hash,
        file_size=file_size,
        upload_id=upload_id,
        exchanges=list(client.exchanges),
    )


def run_legacy_upload(
    *,
    client: UploadHttpClient,
    server_url: str,
    file_context: FileContext,
    auth_header: str,
    proof_headers: dict[str, str] | None,
) -> HarnessResult:
    run_head_upload(client, server_url)

    body = file_context.path.read_bytes()
    headers = {
        "Authorization": auth_header,
        "Content-Type": file_context.content_type,
        "Content-Length": str(file_context.file_size),
    }
    if proof_headers:
        headers.update(proof_headers)

    upload_exchange = client.request(
        "PUT",
        f"{server_url}/upload",
        headers=headers,
        body=body,
    )
    verdict = "success" if upload_exchange.status in {200, 201} else "upload_failed"
    return HarnessResult(
        verdict=verdict,
        mode="legacy",
        server=server_url,
        file_hash=file_context.file_hash,
        file_size=file_context.file_size,
        upload_id=None,
        exchanges=list(client.exchanges),
    )


def dump_result_json(result: HarnessResult, path: Path) -> None:
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace Blossom upload requests through init, chunk upload, and completion."
    )
    parser.add_argument("--server", required=True, help="Base Blossom server URL")
    parser.add_argument("--file", type=Path, help="Local file to upload")
    parser.add_argument(
        "--mode",
        choices=("resumable", "legacy"),
        default="resumable",
        help="Upload mode to exercise",
    )
    parser.add_argument(
        "--auth-header",
        required=True,
        help="Precomputed Authorization header value",
    )
    parser.add_argument(
        "--proof-json",
        type=Path,
        help="Path to a ProofMode manifest JSON file",
    )
    parser.add_argument(
        "--complete-only",
        action="store_true",
        help="Replay only POST /upload/{id}/complete for an existing session",
    )
    parser.add_argument("--upload-id", help="Existing resumable upload id for --complete-only")
    parser.add_argument("--file-hash", help="Known sha256 for --complete-only")
    parser.add_argument("--file-size", type=int, help="Known file size for --complete-only")
    parser.add_argument(
        "--chunk-size-override",
        type=int,
        help="Override the chunk size used for PUT /sessions/* requests",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-request timeout in seconds",
    )
    parser.add_argument(
        "--dump-json",
        type=Path,
        help="Write a machine-readable transcript to this path",
    )
    parser.add_argument(
        "--content-type",
        help="Override the inferred content type for the local file",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.complete_only:
        if not args.upload_id:
            raise HarnessError("--complete-only requires --upload-id")
        if not args.file_hash:
            raise HarnessError("--complete-only requires --file-hash")
        if args.file_size is None:
            raise HarnessError("--complete-only requires --file-size")
        return

    if args.file is None:
        raise HarnessError("--file is required unless --complete-only is set")
    if not args.file.exists():
        raise HarnessError(f"File not found: {args.file}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        validate_args(args)
        server_url = normalize_server_url(args.server)
        proof_headers = (
            build_proof_headers(load_proof_json(args.proof_json))
            if args.proof_json is not None
            else None
        )
        client = UploadHttpClient(timeout_seconds=args.timeout_seconds)

        if args.complete_only:
            result = run_complete_only(
                client=client,
                server_url=server_url,
                upload_id=args.upload_id,
                auth_header=args.auth_header,
                file_hash=args.file_hash,
                file_size=args.file_size,
                proof_headers=proof_headers,
            )
        else:
            file_context = resolve_file_context(args.file, args.content_type)
            if should_use_resumable(mode=args.mode):
                result = run_resumable_upload(
                    client=client,
                    server_url=server_url,
                    file_context=file_context,
                    auth_header=args.auth_header,
                    proof_headers=proof_headers,
                    chunk_size_override=args.chunk_size_override,
                )
            else:
                result = run_legacy_upload(
                    client=client,
                    server_url=server_url,
                    file_context=file_context,
                    auth_header=args.auth_header,
                    proof_headers=proof_headers,
                )

        if args.dump_json is not None:
            dump_result_json(result, args.dump_json)

        print(
            json.dumps(
                {
                    "verdict": result.verdict,
                    "fileHash": result.file_hash,
                    "fileSize": result.file_size,
                    "uploadId": result.upload_id,
                },
                indent=2,
            )
        )
        return 0 if result.verdict == "success" else 1
    except HarnessError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
