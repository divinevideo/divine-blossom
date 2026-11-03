# ABOUTME: Decodes uploaded audio with ffmpeg into mono float32 PCM for the tagger.
# ABOUTME: Only the first MAX_SECONDS are analyzed; sounds are usually ~6 s long.

from __future__ import annotations

import subprocess
import tempfile

import numpy as np

SAMPLE_RATE = 32000  # PANNs CNN14 is trained on 32 kHz audio.
MAX_SECONDS = 30.0
# Below this RMS level a clip is treated as silent and is not classified. Real
# quiet field recordings (crickets at night) measured -60 dBFS; silent uploads
# are digital zero.
SILENCE_DBFS = -70.0


class DecodeError(Exception):
    """ffmpeg could not decode the body as audio."""


def decode(audio: bytes, timeout_s: float = 60.0) -> np.ndarray:
    """Decode any ffmpeg-readable audio (or video) bytes to mono float32 at SAMPLE_RATE.

    Raises:
        DecodeError: if ffmpeg fails or produces no samples.
    """
    # A temp file rather than stdin: MP4/M4A uploads usually carry their moov atom
    # at the end, which ffmpeg cannot reach on a non-seekable pipe.
    with tempfile.NamedTemporaryFile(suffix=".bin") as src:
        src.write(audio)
        src.flush()
        cmd = [
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
            "-i", src.name,
            "-t", str(MAX_SECONDS),
            "-vn", "-ac", "1", "-ar", str(SAMPLE_RATE),
            "-f", "f32le", "pipe:1",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise DecodeError("ffmpeg timed out") from exc
    if proc.returncode != 0:
        raise DecodeError(proc.stderr.decode("utf-8", "replace").strip()[:500] or "ffmpeg failed")
    samples = np.frombuffer(proc.stdout, dtype=np.float32)
    if samples.size == 0:
        raise DecodeError("no audio samples")
    return samples


def rms_dbfs(samples: np.ndarray) -> float:
    rms = float(np.sqrt(np.mean(np.square(samples, dtype=np.float64))))
    return 20.0 * float(np.log10(rms)) if rms > 0 else float("-inf")


def is_silent(samples: np.ndarray) -> bool:
    return bool(rms_dbfs(samples) < SILENCE_DBFS)
