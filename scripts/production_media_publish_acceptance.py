#!/usr/bin/env python3
"""Exercise upload, readiness, publish, relay, and REST production boundaries."""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass
import io
import json
import math
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from typing import Callable, Iterable
import urllib.error
import urllib.request

try:
    from debug_upload_harness import (
        HarnessError,
        UploadHttpClient,
        resolve_file_context,
        run_legacy_upload,
    )
    from probe_video_readiness import EXIT_READY, assert_readiness, build_target_urls
except ModuleNotFoundError:  # Imported as scripts.production_media_publish_acceptance.
    from scripts.debug_upload_harness import (
        HarnessError,
        UploadHttpClient,
        resolve_file_context,
        run_legacy_upload,
    )
    from scripts.probe_video_readiness import EXIT_READY, assert_readiness, build_target_urls


DEFAULT_FIXTURE = Path(__file__).parent / "tests" / "fixtures" / "readiness_ok.mp4"
DEFAULT_D_TAG = "divine-production-media-acceptance"
DEFAULT_MEDIA_URL = "https://media.divine.video"
DEFAULT_RELAY_URL = "wss://relay.divine.video"
DEFAULT_API_URL = "https://api.divine.video"
FEED_EXCLUSION_ENV = "DIVINE_ACCEPTANCE_FEED_EXCLUSION_CONFIRMED"
SECRET_KEY_ENV = "DIVINE_ACCEPTANCE_NSEC"
REQUIRED_ENDPOINTS = ("mp4_720", "hls_master")


class AcceptanceError(RuntimeError):
    """A production acceptance stage could not prove its contract."""


@dataclass(frozen=True)
class StageResult:
    name: str
    elapsed_seconds: float
    detail: str


@dataclass(frozen=True)
class AcceptanceResult:
    verdict: str
    media_hash: str
    event_id: str
    coordinate: str
    stages: tuple[StageResult, ...]

    def automation_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "media_hash": self.media_hash,
            "event_id": self.event_id,
            "coordinate": self.coordinate,
            "stages": [asdict(stage) for stage in self.stages],
        }


def require_feed_exclusion(environment: dict[str, str]) -> None:
    if environment.get(FEED_EXCLUSION_ENV) != "1":
        raise AcceptanceError(
            f"refusing to publish without {FEED_EXCLUSION_ENV}=1; confirm the "
            "synthetic pubkey is excluded from production discovery first"
        )


def parse_json_object(raw: bytes | str, context: str) -> dict[str, object]:
    try:
        payload = json.loads(raw)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"{context} returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise AcceptanceError(f"{context} returned a non-object JSON value")
    return payload


def build_video_tags(
    *,
    d_tag: str,
    media_url: str,
    thumbnail_url: str,
    media_hash: str,
    media_size: int,
    mime_type: str,
    dimensions: str,
    title: str,
    run_nonce: str,
) -> list[list[str]]:
    if not d_tag or not title or not run_nonce:
        raise AcceptanceError("d tag, title, and run nonce must be non-empty")
    if len(media_hash) != 64 or any(char not in "0123456789abcdef" for char in media_hash):
        raise AcceptanceError("media hash must be 64 lowercase hexadecimal characters")
    if media_size <= 0:
        raise AcceptanceError("media size must be positive")
    if not dimensions or "x" not in dimensions:
        raise AcceptanceError("video dimensions must use WIDTHxHEIGHT format")
    if not media_url.startswith("https://") or not thumbnail_url.startswith("https://"):
        raise AcceptanceError("media and thumbnail URLs must use HTTPS")
    imeta = [
        "imeta",
        f"url {media_url}",
        f"m {mime_type}",
        f"x {media_hash}",
        f"size {media_size}",
        f"dim {dimensions}",
        f"image {thumbnail_url}",
    ]
    return [
        ["d", d_tag],
        ["title", title],
        ["client", "divine-production-acceptance"],
        ["nonce", run_nonce],
        imeta,
    ]


def validate_signed_event(
    event: dict[str, object], *, d_tag: str, media_hash: str
) -> None:
    if event.get("kind") != 34236:
        raise AcceptanceError("signer returned the wrong event kind")
    for field, length in (("id", 64), ("pubkey", 64), ("sig", 128)):
        value = event.get(field)
        if not isinstance(value, str) or len(value) != length:
            raise AcceptanceError(f"signer returned an invalid {field}")
    tags = event.get("tags")
    if not isinstance(tags, list):
        raise AcceptanceError("signer returned invalid tags")
    if ["d", d_tag] not in tags or not any(
        isinstance(tag, list)
        and tag
        and tag[0] == "imeta"
        and f"x {media_hash}" in tag[1:]
        for tag in tags
    ):
        raise AcceptanceError("signed event does not preserve its coordinate and media hash")


class NakClient:
    def __init__(
        self,
        executable: str,
        secret_key: str,
        timeout_seconds: float,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.executable = executable
        self.secret_key = secret_key
        self.timeout_seconds = timeout_seconds
        self.runner = runner

    def _run(self, arguments: list[str], input_text: str | None = None) -> str:
        environment = os.environ.copy()
        environment["NOSTR_SECRET_KEY"] = self.secret_key
        try:
            completed = self.runner(
                [self.executable, *arguments],
                input=input_text,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                env=environment,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AcceptanceError(f"Nostr command failed: {type(exc).__name__}") from exc
        if completed.returncode != 0:
            raise AcceptanceError(
                f"Nostr command exited {completed.returncode}; verify the official nak binary and endpoints"
            )
        return completed.stdout.strip()

    def validate_binary(self) -> None:
        output = self._run(["--help"])
        if "nostr army knife" not in output.lower():
            raise AcceptanceError("nak executable is not fiatjaf/nak (the Nostr Army Knife)")

    def sign_event(self, kind: int, content: str, tags: Iterable[Iterable[str]]) -> dict[str, object]:
        partial_event = {
            "kind": kind,
            "content": content,
            "tags": [list(tag) for tag in tags],
        }
        return parse_json_object(
            self._run(["event"], json.dumps(partial_event, separators=(",", ":"))),
            "nak event",
        )

    def blossom_upload_auth(self, media_hash: str, expiration: int) -> tuple[str, str]:
        event = self.sign_event(
            24242,
            "Upload synthetic production acceptance fixture",
            (("t", "upload"), ("x", media_hash), ("expiration", str(expiration))),
        )
        pubkey = event.get("pubkey")
        if not isinstance(pubkey, str) or len(pubkey) != 64:
            raise AcceptanceError("upload signer returned an invalid pubkey")
        compact = json.dumps(event, separators=(",", ":")).encode("utf-8")
        return f"Nostr {base64.b64encode(compact).decode('ascii')}", pubkey

    def publish(self, event: dict[str, object], relay_url: str) -> None:
        self._run(["event", relay_url], json.dumps(event, separators=(",", ":")))

    def query_coordinate(
        self, relay_url: str, pubkey: str, d_tag: str
    ) -> list[dict[str, object]]:
        output = self._run(
            ["req", "--kind", "34236", "--author", pubkey, "--tag", f"d={d_tag}", relay_url]
        )
        events: list[dict[str, object]] = []
        for line in output.splitlines():
            if line.strip():
                events.append(parse_json_object(line, "nak req"))
        return events


def validate_upload_descriptor(
    descriptor: dict[str, object], *, media_hash: str, size: int, mime_type: str
) -> tuple[str, str]:
    expected = {"sha256": media_hash, "size": size, "type": mime_type}
    for key, value in expected.items():
        if descriptor.get(key) != value:
            raise AcceptanceError(f"upload descriptor {key} did not match the local fixture")
    media_url = descriptor.get("url")
    thumbnail_url = descriptor.get("thumbnail")
    dimensions = descriptor.get("dim")
    if not isinstance(media_url, str) or not isinstance(thumbnail_url, str):
        raise AcceptanceError("upload descriptor did not include media and thumbnail URLs")
    if not isinstance(dimensions, str):
        raise AcceptanceError("upload descriptor did not include video dimensions")
    return thumbnail_url, dimensions


def rest_event_matches(api_url: str, event_id: str, timeout_seconds: float) -> bool:
    request = urllib.request.Request(f"{api_url.rstrip('/')}/api/event/{event_id}")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = parse_json_object(response.read(1_000_000), "REST event lookup")
            return response.status == 200 and payload.get("id") == event_id
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404:
            return False
        raise AcceptanceError(f"REST event lookup returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise AcceptanceError(f"REST event lookup failed: {type(exc.reason).__name__}") from exc


def anonymous_head_status(url: str, timeout_seconds: float, stage: str) -> int:
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code
    except urllib.error.URLError as exc:
        raise AcceptanceError(f"{stage} failed: {type(exc.reason).__name__}") from exc


def poll_until(
    check: Callable[[], bool], *, stage: str, deadline_seconds: float, interval_seconds: float,
    clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
) -> None:
    deadline = clock() + deadline_seconds
    while True:
        if check():
            return
        remaining = deadline - clock()
        if remaining <= 0:
            raise AcceptanceError(f"{stage} bounded poll expired")
        sleep(min(interval_seconds, remaining))


def run_acceptance(args: argparse.Namespace, environment: dict[str, str]) -> AcceptanceResult:
    require_feed_exclusion(environment)
    secret_key = environment.get(SECRET_KEY_ENV)
    if not secret_key:
        raise AcceptanceError(f"{SECRET_KEY_ENV} is required")
    timings = (
        args.readiness_deadline_seconds,
        args.stage_deadline_seconds,
        args.request_timeout_seconds,
        args.poll_interval_seconds,
    )
    if not all(math.isfinite(value) for value in timings) or any(value <= 0 for value in timings):
        raise AcceptanceError("all deadlines, timeouts, and polling intervals must be positive and finite")
    for name, url, scheme in (
        ("media", args.media_url, "https://"),
        ("relay", args.relay_url, "wss://"),
        ("API", args.api_url, "https://"),
    ):
        if not url.startswith(scheme):
            raise AcceptanceError(f"{name} URL must start with {scheme}")
    if not args.fixture.is_file():
        raise AcceptanceError("fixture is not a readable file")
    fixture = resolve_file_context(args.fixture, "video/mp4")
    nak = NakClient(args.nak, secret_key, args.stage_deadline_seconds)
    nak.validate_binary()
    stages: list[StageResult] = []

    started = time.monotonic()
    direct_url = f"{args.media_url.rstrip('/')}/{fixture.file_hash}"
    preupload_status = anonymous_head_status(
        direct_url, args.request_timeout_seconds, "pre-upload media check"
    )
    if preupload_status not in {200, 401, 404}:
        raise AcceptanceError(f"pre-upload media check returned HTTP {preupload_status}")
    preupload_detail = (
        "existing and anonymously servable"
        if preupload_status == 200
        else f"unavailable or hidden (HTTP {preupload_status})"
    )
    stages.append(StageResult("preupload", time.monotonic() - started, preupload_detail))

    started = time.monotonic()
    auth_header, pubkey = nak.blossom_upload_auth(
        fixture.file_hash, int(time.time() + args.stage_deadline_seconds)
    )
    upload = run_legacy_upload(
        client=UploadHttpClient(
            timeout_seconds=int(args.stage_deadline_seconds), output_stream=io.StringIO()
        ),
        server_url=args.media_url.rstrip("/"), file_context=fixture,
        auth_header=auth_header, proof_headers=None,
    )
    if upload.verdict != "success" or not upload.exchanges:
        raise AcceptanceError(f"production upload failed at {upload.verdict}")
    descriptor = parse_json_object(upload.exchanges[-1].response_body, "upload")
    thumbnail_url, dimensions = validate_upload_descriptor(
        descriptor, media_hash=fixture.file_hash, size=fixture.file_size,
        mime_type=fixture.content_type,
    )
    stages.append(StageResult("upload", time.monotonic() - started, "descriptor validated"))

    started = time.monotonic()
    direct_status = anonymous_head_status(
        str(descriptor["url"]), args.request_timeout_seconds, "uploaded media check"
    )
    if direct_status != 200:
        raise AcceptanceError(f"uploaded media is not anonymously servable: HTTP {direct_status}")
    stages.append(StageResult("direct_media", time.monotonic() - started, "HTTP 200"))

    started = time.monotonic()
    readiness = assert_readiness(
        build_target_urls(args.media_url.removeprefix("https://"), fixture.file_hash),
        required_endpoints=REQUIRED_ENDPOINTS,
        deadline_seconds=args.readiness_deadline_seconds,
        interval_seconds=args.poll_interval_seconds,
    )
    if readiness.exit_code != EXIT_READY:
        raise AcceptanceError(f"media readiness failed: {readiness.reason}")
    stages.append(StageResult("readiness", time.monotonic() - started, readiness.reason))

    media_url = str(descriptor["url"])
    tags = build_video_tags(
        d_tag=args.d_tag, media_url=media_url, thumbnail_url=thumbnail_url,
        media_hash=fixture.file_hash, media_size=fixture.file_size,
        mime_type=fixture.content_type, dimensions=dimensions, title=args.title,
        run_nonce=secrets.token_hex(16),
    )
    event = nak.sign_event(34236, args.content, tags)
    validate_signed_event(event, d_tag=args.d_tag, media_hash=fixture.file_hash)
    if event["pubkey"] != pubkey:
        raise AcceptanceError("upload and event signing identities differ")
    event_id = str(event["id"])

    started = time.monotonic()
    nak.publish(event, args.relay_url)
    stages.append(StageResult("publish", time.monotonic() - started, "relay accepted command"))

    started = time.monotonic()
    matched: dict[str, object] = {}
    def relay_check() -> bool:
        nonlocal matched
        events = nak.query_coordinate(args.relay_url, pubkey, args.d_tag)
        matches = [candidate for candidate in events if candidate.get("id") == event_id]
        if not matches:
            return False
        matched = matches[0]
        return True
    poll_until(relay_check, stage="relay read-back", deadline_seconds=args.stage_deadline_seconds,
               interval_seconds=args.poll_interval_seconds)
    validate_signed_event(matched, d_tag=args.d_tag, media_hash=fixture.file_hash)
    stages.append(StageResult("relay_read", time.monotonic() - started, "exact event returned"))

    started = time.monotonic()
    poll_until(
        lambda: rest_event_matches(args.api_url, event_id, args.request_timeout_seconds),
        stage="REST read-back",
        deadline_seconds=args.stage_deadline_seconds,
        interval_seconds=args.poll_interval_seconds,
    )
    stages.append(StageResult("rest_read", time.monotonic() - started, "exact event returned"))
    return AcceptanceResult(
        "pass", fixture.file_hash, event_id, f"34236:{pubkey}:{args.d_tag}", tuple(stages)
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--media-url", default=DEFAULT_MEDIA_URL)
    parser.add_argument("--relay-url", default=DEFAULT_RELAY_URL)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--d-tag", default=DEFAULT_D_TAG)
    parser.add_argument("--title", default="Divine production media acceptance")
    parser.add_argument("--content", default="Synthetic production acceptance event")
    parser.add_argument("--nak", default="nak")
    parser.add_argument("--readiness-deadline-seconds", type=float, default=180)
    parser.add_argument("--stage-deadline-seconds", type=float, default=60)
    parser.add_argument("--request-timeout-seconds", type=float, default=10)
    parser.add_argument("--poll-interval-seconds", type=float, default=2)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_acceptance(args, dict(os.environ))
    except (AcceptanceError, HarnessError, ValueError) as exc:
        payload = {"verdict": "fail", "reason": str(exc)}
        if args.json:
            print(json.dumps(payload, separators=(",", ":")))
        else:
            print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    payload = result.automation_dict()
    if args.json:
        print(json.dumps(payload, separators=(",", ":")))
    else:
        print("PASS: production media publishing acceptance")
        for stage in result.stages:
            print(f"{stage.name}: {stage.elapsed_seconds:.3f}s ({stage.detail})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
