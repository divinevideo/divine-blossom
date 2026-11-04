# ABOUTME: Decodes uploaded audio with ffmpeg into mono float32 PCM for the tagger,
# ABOUTME: and measures its loudness to decide whether the sound plays anything.

from __future__ import annotations

import math
import subprocess
import tempfile
from dataclasses import dataclass

import numpy as np

SAMPLE_RATE = 32000  # PANNs CNN14 is trained on 32 kHz audio.
MAX_SECONDS = 30.0

# A sound is silent when almost none of it is audible. Audible means a 10 ms
# window whose sample peak reaches AUDIBLE_FLOOR_DBFS. Silent means less audible
# time than MIN_AUDIBLE_SECONDS, or than MIN_AUDIBLE_SHARE of the clip if that is
# shorter, so a deliberately short effect stays audible. Measured on 3,064
# production sounds; see "Silence" in the README for why these values.
AUDIBLE_FLOOR_DBFS = -50.0
AUDIBLE_WINDOW_SECONDS = 0.01
MIN_AUDIBLE_SECONDS = 0.25
MIN_AUDIBLE_SHARE = 0.10


def analysis_windows(samples: np.ndarray, window_seconds: int = 10) -> list:
    """Split into `window_seconds` windows and zero-pad any window under a second.

    CNN14 halves the time axis five times, so a window shorter than ~0.35 s
    leaves a pooling layer with no frames and the model raises.
    """
    n = window_seconds * SAMPLE_RATE
    windows = [samples[i:i + n] for i in range(0, len(samples), n)]
    # Drop a trailing scrap shorter than a second unless it is the whole clip.
    windows = [w for w in windows if len(w) >= SAMPLE_RATE] or windows[:1]
    return [np.pad(w, (0, max(0, SAMPLE_RATE - len(w)))) for w in windows]


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


def _dbfs(level: float) -> float | None:
    """Level in dBFS rounded to 0.1 dB; None for digital silence, which JSON cannot hold as -inf."""
    return round(20.0 * math.log10(level), 1) if level > 0 else None


@dataclass(frozen=True)
class Loudness:
    peak_dbfs: float | None
    rms_dbfs: float | None
    audible_seconds: float
    silent: bool

    def to_dict(self) -> dict:
        return {
            "peak_dbfs": self.peak_dbfs,
            "rms_dbfs": self.rms_dbfs,
            "audible_seconds": self.audible_seconds,
            "audible_floor_dbfs": AUDIBLE_FLOOR_DBFS,
        }


def measure_loudness(samples: np.ndarray) -> Loudness:
    """Peak, RMS and audible time of decoded samples, and whether they count as silent.

    A clip that fills MAX_SECONDS was cut by `decode`, so the rest of it was never
    heard. It is never called silent: a long track may start with a silent intro.
    """
    x = samples.astype(np.float64)
    window = int(AUDIBLE_WINDOW_SECONDS * SAMPLE_RATE)
    # The trailing partial window counts as a whole one; at 10 ms that is noise.
    padded = np.pad(np.abs(x), (0, -len(x) % window))
    window_peaks = padded.reshape(-1, window).max(axis=1)
    audible = int(np.count_nonzero(window_peaks >= 10 ** (AUDIBLE_FLOOR_DBFS / 20)))
    audible_seconds = round(audible * AUDIBLE_WINDOW_SECONDS, 2)

    seconds = len(x) / SAMPLE_RATE
    truncated = len(x) >= int(MAX_SECONDS * SAMPLE_RATE)
    needed = min(MIN_AUDIBLE_SECONDS, MIN_AUDIBLE_SHARE * seconds)
    return Loudness(
        peak_dbfs=_dbfs(float(np.max(np.abs(x)))),
        rms_dbfs=_dbfs(float(np.sqrt(np.mean(x * x)))),
        audible_seconds=audible_seconds,
        silent=not truncated and audible_seconds < needed,
    )
