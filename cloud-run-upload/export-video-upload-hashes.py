#!/usr/bin/env python3
"""Export unique video upload hashes from Cloud Logging."""

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request


DEFAULT_PROJECT = "rich-compiler-479518-d2"
DEFAULT_SERVICE = "blossom-upload-rust"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export unique video upload hashes from Cloud Logging."
    )
    parser.add_argument(
        "--since",
        required=True,
        help="Lower timestamp bound, inclusive, in RFC3339 form. Example: 2026-03-01T03:33:49Z",
    )
    parser.add_argument(
        "--until",
        help="Upper timestamp bound, exclusive, in RFC3339 form.",
    )
    parser.add_argument(
        "--project",
        default=DEFAULT_PROJECT,
        help=f"GCP project id. Default: {DEFAULT_PROJECT}",
    )
    parser.add_argument(
        "--service-name",
        default=DEFAULT_SERVICE,
        help=f"Cloud Run service name to query. Default: {DEFAULT_SERVICE}",
    )
    parser.add_argument(
        "--output",
        help="Write results to this file instead of stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("hashes", "ndjson"),
        default="hashes",
        help="Output plain hashes or NDJSON metadata records. Default: hashes",
    )
    return parser.parse_args()


def get_access_token() -> str:
    return subprocess.check_output(
        ["gcloud", "auth", "print-access-token"], text=True
    ).strip()


def build_filter(service_name: str, since: str, until: str | None) -> str:
    clauses = [
        'resource.type="cloud_run_revision"',
        f'resource.labels.service_name="{service_name}"',
        'labels.service="divine-blossom"',
        'labels.component="audit"',
        'jsonPayload.action="upload"',
        'jsonPayload.metadata_snapshot.type="video/mp4"',
        f'timestamp>="{since}"',
    ]
    if until:
        clauses.append(f'timestamp<"{until}"')
    return " AND ".join(clauses)


def list_entries(project: str, log_filter: str):
    token = get_access_token()
    url = "https://logging.googleapis.com/v2/entries:list"
    page_token = None

    while True:
        payload = {
            "resourceNames": [f"projects/{project}"],
            "filter": log_filter,
            "orderBy": "timestamp desc",
            "pageSize": 1000,
        }
        if page_token:
            payload["pageToken"] = page_token

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise SystemExit(f"Logging API error {exc.code}: {body}") from exc

        for entry in data.get("entries", []):
            yield entry

        page_token = data.get("nextPageToken")
        if not page_token:
            break


def extract_record(entry: dict) -> dict | None:
    payload = entry.get("jsonPayload", {})
    metadata = payload.get("metadata_snapshot", {})
    sha256 = payload.get("sha256") or metadata.get("sha256")
    if not sha256:
        return None

    return {
        "sha256": sha256,
        "uploaded": metadata.get("uploaded") or payload.get("timestamp"),
        "owner": metadata.get("owner"),
        "size": metadata.get("size"),
        "dim": metadata.get("dim"),
        "thumbnail": metadata.get("thumbnail")
        or f"https://media.divine.video/{sha256}.jpg",
    }


def main() -> None:
    args = parse_args()
    log_filter = build_filter(args.service_name, args.since, args.until)

    output = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    seen: set[str] = set()
    count = 0

    try:
        for entry in list_entries(args.project, log_filter):
            record = extract_record(entry)
            if record is None or record["sha256"] in seen:
                continue

            seen.add(record["sha256"])
            count += 1

            if args.format == "hashes":
                output.write(f"{record['sha256']}\n")
            else:
                output.write(json.dumps(record, sort_keys=True) + "\n")

            if count % 1000 == 0:
                print(f"exported={count}", file=sys.stderr)
    finally:
        if args.output:
            output.close()

    print(f"done exported={count}", file=sys.stderr)


if __name__ == "__main__":
    main()
