#!/usr/bin/env python3
"""Read-only audit of legacy stretched renditions; emit force-request candidates."""

import argparse
from fractions import Fraction
import json
from pathlib import Path
import re
import subprocess
import sys


RENDITIONS = ("720p.mp4", "480p.mp4", "hls/stream_720p.m3u8", "hls/stream_480p.m3u8")
LEGACY_SIZES = {(1280, 720), (854, 480)}


def geometry(document):
    """Return coded size and rotation/SAR-corrected display aspect ratio."""
    stream = document["streams"][0]
    width, height = int(stream["width"]), int(stream["height"])
    if width <= 0 or height <= 0:
        raise ValueError("invalid video dimensions")
    sar_text = stream.get("sample_aspect_ratio", "1:1")
    sar = Fraction(sar_text.replace(":", "/")) if sar_text not in ("N/A", "0:1") else Fraction(1)
    if sar <= 0:
        raise ValueError("invalid sample aspect ratio")
    rotation = float(stream.get("tags", {}).get("rotate", 0))
    for side in stream.get("side_data_list", []):
        if side.get("side_data_type") == "Display Matrix":
            rotation = float(side["rotation"])
    # Refuse ambiguous transforms rather than selecting a destructive repair.
    if rotation % 90 != 0:
        raise ValueError("non-right-angle rotation")
    ratio = Fraction(width, height) * sar
    if rotation % 180 != 0:
        ratio = 1 / ratio
    return (width, height), ratio


def is_stretched(source, rendition):
    """Select legacy landscape dimensions with a materially different display ratio."""
    size, ratio = rendition
    source_ratio = source[1]
    # 854x480 rounds 16:9 to an even pixel width; allow this rounding, not squares.
    return (
        size in LEGACY_SIZES
        and abs(ratio / Fraction(16, 9) - 1) < Fraction(1, 100)
        and abs(source_ratio / ratio - 1) > Fraction(1, 100)
    )


def probe(url):
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-protocol_whitelist", "file,crypto,data",
         "-select_streams", "v:0", "-show_streams",
         "-of", "json", url],
        capture_output=True, text=True, check=True, timeout=60,
    )
    return geometry(json.loads(result.stdout))


def audit_hash(hash_value, media_root, probe_fn=probe):
    source = probe_fn(f"{media_root}/originals/{hash_value}")
    affected, errors = [], []
    for rendition in RENDITIONS:
        try:
            object_path = {"720p.mp4": "hls/stream_720p.mp4", "480p.mp4": "hls/stream_480p.mp4"}.get(rendition, rendition)
            if is_stretched(source, probe_fn(f"{media_root}/derivatives/{hash_value}/{object_path}")):
                affected.append(rendition)
        except (ValueError, KeyError, IndexError, TypeError, ZeroDivisionError,
                subprocess.SubprocessError, OSError):
            errors.append(rendition)
    record = {"hash": hash_value, "affected": affected, "probe_errors": errors}
    if affected:
        record["request"] = {"hash": hash_value, "force": True}
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hash-file", required=True, type=Path, help="one SHA256 per line")
    parser.add_argument("--media-root", required=True, type=Path, help="local read-only object export")
    args = parser.parse_args()
    base = args.media_root.resolve()
    if not base.is_dir():
        parser.error("media root must be a local directory")
    hashes = list(dict.fromkeys(args.hash_file.read_text().split()))
    if not hashes or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes):
        parser.error("hash file must contain only lowercase 64-character SHA256 values")
    failed = False
    for hash_value in hashes:
        try:
            record = audit_hash(hash_value, base)
        except (ValueError, KeyError, IndexError, TypeError, ZeroDivisionError,
                subprocess.SubprocessError, OSError):
            record = {"hash": hash_value, "affected": [], "probe_errors": ["original"]}
        failed |= bool(record["probe_errors"])
        print(json.dumps(record), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
