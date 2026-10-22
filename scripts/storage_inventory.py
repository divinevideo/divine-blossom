#!/usr/bin/env python3
"""Read-only B2/Bunny resource inventory. Outputs explicit non-secret fields only.

Credentials come from B2_APPLICATION_KEY_ID / B2_APPLICATION_KEY and BUNNY_API_KEY
in the operator's approved credential wrapper. No credentials are accepted as
arguments, and no storage, CDN or access settings are changed.
"""
import argparse
import base64
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request


class InventoryError(RuntimeError):
    pass


def request_json(url, headers, body=None):
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, headers=headers, data=payload)
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    try:
        # These account APIs do not require redirects. Do not forward credentials
        # to a destination supplied by an HTTP redirect.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise InventoryError(f"provider inventory HTTP {error.code}") from None
    except (OSError, ValueError):
        raise InventoryError("provider inventory response unavailable or invalid") from None


def validate_b2_api_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.port is not None or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment
            or not re.fullmatch(r"api[0-9]*\.backblazeb2\.com", parsed.hostname or "")):
        raise InventoryError("invalid B2 account API endpoint")
    return url.rstrip("/")


def inventory_b2(key_id, application_key):
    basic = base64.b64encode(f"{key_id}:{application_key}".encode()).decode()
    auth = request_json("https://api.backblazeb2.com/b2api/v3/b2_authorize_account", {"Authorization": f"Basic {basic}"})
    storage = auth.get("apiInfo", {}).get("storageApi", auth)
    api_url = validate_b2_api_url(storage.get("apiUrl", ""))
    data = request_json(f"{api_url}/b2api/v3/b2_list_buckets", {"Authorization": auth["authorizationToken"]}, {"accountId": auth["accountId"]})
    return {
        "status": "ok",
        "s3_endpoint": safe_origin(storage.get("s3ApiUrl", "")),
        "buckets": [{
            "name": bucket.get("bucketName"), "id": bucket.get("bucketId"),
            "type": bucket.get("bucketType"),
            "file_lock": bucket.get("fileLockConfiguration", {}).get("value"),
            "lifecycle_rules": bucket.get("lifecycleRules", []),
        } for bucket in data.get("buckets", [])],
    }


def safe_origin(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        return ""
    host = parsed.hostname
    if parsed.port:
        host += f":{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def summarize_bunny_zone(zone):
    return {
        "id": zone.get("Id"), "name": zone.get("Name"),
        "origin": safe_origin(zone.get("OriginUrl", "")),
        "network_type": zone.get("Type"),
        "hostnames": [hostname.get("Value") for hostname in zone.get("Hostnames", [])],
        "aws_signing_enabled": zone.get("AWSSigningEnabled", False),
        "aws_signing_region": zone.get("AWSSigningRegionName"),
    }


def collect_inventory():
    result = {"b2": {"status": "not_configured"}, "bunny": {"status": "not_configured"}}
    key_id, key = os.environ.get("B2_APPLICATION_KEY_ID"), os.environ.get("B2_APPLICATION_KEY")
    if key_id and key:
        try:
            result["b2"] = inventory_b2(key_id, key)
        except (InventoryError, KeyError, TypeError):
            result["b2"] = {"status": "unavailable"}
    if os.environ.get("BUNNY_API_KEY"):
        try:
            zones = request_json("https://api.bunny.net/pullzone", {"AccessKey": os.environ["BUNNY_API_KEY"]})
            result["bunny"] = {"status": "ok", "zones": [summarize_bunny_zone(zone) for zone in zones]}
        except (InventoryError, ValueError, KeyError, TypeError):
            result["bunny"] = {"status": "unavailable"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gcs-bucket", action="append", default=[], help="Optional bucket metadata, using existing gcloud authentication")
    args = parser.parse_args()
    result = collect_inventory()
    result["gcs"] = []
    for bucket in args.gcs_bucket:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", bucket):
            parser.error("invalid GCS bucket name")
        try:
            completed = subprocess.run([
                "gcloud", "storage", "buckets", "describe", f"gs://{bucket}",
                "--format=json(name,location,public_access_prevention,retention_policy,lifecycle_config,soft_delete_policy,versioning_enabled)", "--quiet"
            ], capture_output=True, text=True, timeout=30)
            if completed.returncode:
                raise InventoryError("GCS metadata unavailable")
            result["gcs"].append(json.loads(completed.stdout))
        except (InventoryError, OSError, ValueError, subprocess.TimeoutExpired):
            result["gcs"].append({"name": bucket, "status": "unavailable"})
    print(json.dumps(result, indent=2, sort_keys=True))
    complete = all(result[provider]["status"] == "ok" for provider in ("b2", "bunny"))
    complete = complete and all(bucket.get("status") != "unavailable" for bucket in result["gcs"])
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
