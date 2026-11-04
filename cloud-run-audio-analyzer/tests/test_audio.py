# ABOUTME: Tests ffmpeg decoding and the loudness and silence check on generated audio.
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


class TestWindows(unittest.TestCase):
    def test_short_clips_are_padded_to_a_second(self):
        (w,) = audio.analysis_windows(np.ones(3200, dtype=np.float32))
        self.assertEqual(len(w), audio.SAMPLE_RATE)
        self.assertEqual(float(w[:3200].sum()), 3200.0)
        self.assertEqual(float(w[3200:].sum()), 0.0)

    def test_long_clips_split_into_ten_second_windows(self):
        ws = audio.analysis_windows(np.zeros(25 * audio.SAMPLE_RATE, dtype=np.float32))
        self.assertEqual([len(w) // audio.SAMPLE_RATE for w in ws], [10, 10, 5])

    def test_a_trailing_scrap_under_a_second_is_dropped(self):
        ws = audio.analysis_windows(np.zeros(10 * audio.SAMPLE_RATE + 100, dtype=np.float32))
        self.assertEqual(len(ws), 1)


def _silence(seconds: float) -> np.ndarray:
    return np.zeros(int(seconds * audio.SAMPLE_RATE), dtype=np.float32)


def _at(samples: np.ndarray, start_s: float, burst: np.ndarray) -> np.ndarray:
    out = samples.copy()
    i = int(start_s * audio.SAMPLE_RATE)
    out[i:i + len(burst)] = burst
    return out


def _burst(seconds: float, amplitude: float = 0.5) -> np.ndarray:
    return _tone(seconds, rate=audio.SAMPLE_RATE, amplitude=amplitude).astype(np.float32)


class TestSilence(unittest.TestCase):
    def test_digital_silence_is_silent_and_has_no_level(self):
        loudness = audio.measure_loudness(_silence(6.0))
        self.assertTrue(loudness.silent)
        self.assertIsNone(loudness.peak_dbfs)
        self.assertIsNone(loudness.rms_dbfs)
        self.assertEqual(loudness.audible_seconds, 0.0)

    def test_hiss_below_the_audible_floor_is_silent(self):
        # Peaks around -60 dBFS: the level of the inaudible "Original sound" uploads.
        noise = np.random.default_rng(1).normal(0, 2.5e-4, 6 * audio.SAMPLE_RATE)
        loudness = audio.measure_loudness(noise.astype(np.float32))
        self.assertLess(loudness.peak_dbfs, audio.AUDIBLE_FLOOR_DBFS)
        self.assertTrue(loudness.silent)

    def test_a_single_click_in_silence_is_silent(self):
        click = _at(_silence(6.0), 1.0, _burst(0.02, amplitude=0.9))
        loudness = audio.measure_loudness(click)
        self.assertGreater(loudness.peak_dbfs, -3.0)
        self.assertLess(loudness.audible_seconds, audio.MIN_AUDIBLE_SECONDS)
        self.assertTrue(loudness.silent)

    def test_a_short_word_in_silence_is_audible(self):
        word = _at(_silence(6.0), 2.0, _burst(0.4))
        self.assertFalse(audio.measure_loudness(word).silent)

    def test_quiet_audio_above_the_floor_is_audible(self):
        # About -40 dBFS peak: quiet, but it plays.
        quiet = _burst(6.0, amplitude=0.01)
        self.assertFalse(audio.measure_loudness(quiet).silent)

    def test_a_short_effect_that_is_mostly_sound_is_audible(self):
        # 0.15 s of a 0.2 s clip is audible: under MIN_AUDIBLE_SECONDS, but most of the clip.
        effect = _at(_silence(0.2), 0.0, _burst(0.15))
        loudness = audio.measure_loudness(effect)
        self.assertLess(loudness.audible_seconds, audio.MIN_AUDIBLE_SECONDS)
        self.assertFalse(loudness.silent)

    def test_a_clip_cut_at_the_analysis_limit_is_never_silent(self):
        # Only the first MAX_SECONDS are decoded; a long track may start quietly.
        self.assertFalse(audio.measure_loudness(_silence(audio.MAX_SECONDS)).silent)

    def test_levels_are_reported_in_dbfs(self):
        loudness = audio.measure_loudness(_burst(1.0, amplitude=0.5))
        self.assertAlmostEqual(loudness.peak_dbfs, -6.0, delta=0.1)
        self.assertAlmostEqual(loudness.rms_dbfs, -9.0, delta=0.1)
        self.assertAlmostEqual(loudness.audible_seconds, 1.0, delta=0.01)
        self.assertEqual(loudness.to_dict()["audible_floor_dbfs"], audio.AUDIBLE_FLOOR_DBFS)


if __name__ == "__main__":
    unittest.main()
