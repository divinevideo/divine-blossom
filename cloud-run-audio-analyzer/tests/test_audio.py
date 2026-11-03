# ABOUTME: Tests ffmpeg decoding and the silence check on generated audio.
# ABOUTME: Needs ffmpeg and numpy, no model.

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import wave

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import audio  # noqa: E402


def _wav(samples: np.ndarray, rate: int = 48000, channels: int = 1) -> bytes:
    pcm = (np.clip(samples, -1, 1) * 32767).astype("<i2")
    if channels == 2:
        pcm = np.repeat(pcm[:, None], 2, axis=1)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())
    return buf.getvalue()


def _tone(seconds: float, rate: int = 48000, amplitude: float = 0.5) -> np.ndarray:
    t = np.arange(int(seconds * rate)) / rate
    return amplitude * np.sin(2 * np.pi * 440 * t)


@unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg is not installed")
class TestDecode(unittest.TestCase):
    def test_resamples_stereo_to_mono_32k(self):
        samples = audio.decode(_wav(_tone(2.0), channels=2))
        self.assertEqual(samples.dtype, np.float32)
        self.assertAlmostEqual(len(samples) / audio.SAMPLE_RATE, 2.0, places=2)

    def test_caps_long_audio_at_max_seconds(self):
        samples = audio.decode(_wav(_tone(audio.MAX_SECONDS + 5, rate=8000), rate=8000))
        self.assertAlmostEqual(len(samples) / audio.SAMPLE_RATE, audio.MAX_SECONDS, places=1)

    def test_decodes_m4a_with_the_moov_atom_at_the_end(self):
        # ffmpeg writes moov last unless asked for +faststart, like most phone recordings.
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = os.path.join(tmp, "in.wav"), os.path.join(tmp, "out.m4a")
            with open(src, "wb") as f:
                f.write(_wav(_tone(2.0)))
            subprocess.run(["ffmpeg", "-nostdin", "-loglevel", "error", "-i", src, "-c:a", "aac", dst],
                           check=True)
            with open(dst, "rb") as f:
                samples = audio.decode(f.read())
        self.assertAlmostEqual(len(samples) / audio.SAMPLE_RATE, 2.0, delta=0.1)

    def test_rejects_bytes_that_are_not_audio(self):
        with self.assertRaises(audio.DecodeError):
            audio.decode(b"definitely not audio")


class TestSilence(unittest.TestCase):
    def test_digital_silence_is_silent(self):
        self.assertTrue(audio.is_silent(np.zeros(32000, dtype=np.float32)))

    def test_quiet_hiss_below_the_floor_is_silent(self):
        noise = np.random.default_rng(1).normal(0, 1e-4, 32000).astype(np.float32)
        self.assertTrue(audio.is_silent(noise))

    def test_a_tone_is_not_silent(self):
        self.assertFalse(audio.is_silent(_tone(1.0).astype(np.float32)))


if __name__ == "__main__":
    unittest.main()
