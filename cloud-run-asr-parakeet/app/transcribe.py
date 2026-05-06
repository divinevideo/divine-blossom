# ABOUTME: Wrapper around NVIDIA NeMo Parakeet TDT 0.6B v3 for word-timed ASR.
# ABOUTME: Loaded once at process start; expose a single `transcribe(audio_bytes)` call.

from __future__ import annotations

import io
import logging
import os
import tempfile
from dataclasses import asdict, dataclass
from typing import List, Optional

import torch

logger = logging.getLogger(__name__)


DEFAULT_MODEL_NAME = os.environ.get(
    "PARAKEET_MODEL_NAME", "nvidia/parakeet-tdt-0.6b-v3"
)


@dataclass
class Word:
    word: str
    start: float
    end: float


@dataclass
class Segment:
    start: float
    end: float
    text: str
    words: List[Word]


@dataclass
class TranscriptionResult:
    language: Optional[str]
    segments: List[Segment]

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "segments": [
                {
                    "start": s.start,
                    "end": s.end,
                    "text": s.text,
                    "words": [asdict(w) for w in s.words],
                }
                for s in self.segments
            ],
        }


class ParakeetTranscriber:
    """Holds the loaded NeMo model. One instance per process."""

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME):
        # Imported lazily so `import transcribe` works in tests without GPU.
        from nemo.collections.asr.models import ASRModel

        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info("Loading Parakeet model %s on %s", model_name, device)
        self._model = ASRModel.from_pretrained(model_name=model_name)
        self._model = self._model.to(device).eval()
        self._device = device
        self._model_name = model_name
        logger.info("Parakeet model ready")

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def device(self) -> str:
        return self._device

    def transcribe(self, audio_bytes: bytes, language: Optional[str] = None) -> TranscriptionResult:
        """Run Parakeet on a single WAV blob and return word-timed segments."""
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=True) as f:
            f.write(audio_bytes)
            f.flush()
            hyps = self._model.transcribe([f.name], timestamps=True)

        if not hyps:
            return TranscriptionResult(language=language, segments=[])

        hyp = hyps[0]
        return _hypothesis_to_result(hyp, language=language)


def _hypothesis_to_result(hyp, language: Optional[str]) -> TranscriptionResult:
    """Map a NeMo Hypothesis (with timestamps=True) to our wire format.

    NeMo's Parakeet hypothesis carries `timestamp = {"word": [...], "segment": [...]}`
    where each entry has `word`/`segment`, `start`, `end` in seconds.
    """
    raw_text: str = getattr(hyp, "text", "") or ""
    timestamps = getattr(hyp, "timestamp", None) or {}

    word_entries = timestamps.get("word") or []
    segment_entries = timestamps.get("segment") or []

    words = [
        Word(
            word=str(w.get("word", "")).strip(),
            start=float(w.get("start", 0.0)),
            end=float(w.get("end", 0.0)),
        )
        for w in word_entries
        if str(w.get("word", "")).strip()
    ]

    segments: List[Segment] = []
    if segment_entries:
        for s in segment_entries:
            seg_start = float(s.get("start", 0.0))
            seg_end = float(s.get("end", seg_start))
            seg_text = str(s.get("segment", s.get("text", ""))).strip()
            seg_words = [w for w in words if seg_start <= w.start <= seg_end]
            if not seg_text and seg_words:
                seg_text = " ".join(w.word for w in seg_words)
            segments.append(
                Segment(start=seg_start, end=seg_end, text=seg_text, words=seg_words)
            )
    elif words:
        # Some Parakeet checkpoints emit only word timestamps; fold them into a
        # single segment so downstream VTT generation has something to chunk.
        segments = [
            Segment(
                start=words[0].start,
                end=words[-1].end,
                text=raw_text or " ".join(w.word for w in words),
                words=words,
            )
        ]
    elif raw_text:
        # No timestamps at all (degenerate path). Emit one untimed segment so
        # the caller can still surface the text.
        segments = [Segment(start=0.0, end=0.0, text=raw_text, words=[])]

    return TranscriptionResult(language=language, segments=segments)
