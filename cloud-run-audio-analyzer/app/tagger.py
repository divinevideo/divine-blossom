# ABOUTME: Wrapper around the PANNs CNN14 AudioSet tagger (527 classes, CPU).
# ABOUTME: Loaded once at process start; scores a clip as the max over 10 s windows.

from __future__ import annotations

import logging
import os
from typing import Dict

import numpy as np
import torch

from .audio import SAMPLE_RATE
from .rules import GENRES, INSTRUMENTS, MOODS, MUSIC_CLASSES, NOT_EFFECT_CLASSES, SPEECH_CLASSES

logger = logging.getLogger(__name__)

MODEL_NAME = "panns-cnn14-mAP0.431"
# panns_inference reads its label list from ~/panns_data at import time; the
# image bakes the labels and checkpoint there (see Dockerfile).
DEFAULT_CHECKPOINT = os.path.expanduser("~/panns_data/Cnn14_mAP=0.431.pth")
WINDOW_SECONDS = 10


class PannsTagger:
    def __init__(self, checkpoint_path: str | None = None, threads: int | None = None) -> None:
        from panns_inference import AudioTagging
        from panns_inference.config import labels

        torch.set_num_threads(threads or int(os.environ.get("ANALYZER_TORCH_THREADS", "1")))
        path = checkpoint_path or os.environ.get("ANALYZER_CHECKPOINT", DEFAULT_CHECKPOINT)
        self._model = AudioTagging(checkpoint_path=path, device="cpu").model.eval()
        self.labels = list(labels)
        self.model_name = MODEL_NAME
        known = set(self.labels)
        configured = set(SPEECH_CLASSES | MUSIC_CLASSES | NOT_EFFECT_CLASSES)
        for group in (GENRES, INSTRUMENTS, MOODS):
            for classes in group.values():
                configured.update(classes)
        missing = sorted(configured - known)
        if missing:
            raise RuntimeError(f"rule classes missing from the model's labels: {missing}")

    def scores(self, samples: np.ndarray) -> Dict[str, float]:
        """Clip-level score per AudioSet class: the max over 10 s windows."""
        n = WINDOW_SECONDS * SAMPLE_RATE
        windows = [samples[i:i + n] for i in range(0, len(samples), n)]
        # Drop a trailing scrap shorter than a second unless it is the whole clip.
        windows = [w for w in windows if len(w) >= SAMPLE_RATE] or windows[:1]
        with torch.no_grad():
            out = [
                self._model(torch.from_numpy(np.ascontiguousarray(w)[None, :]))["clipwise_output"][0].numpy()
                for w in windows
            ]
        clip = np.max(np.stack(out), axis=0)
        return {label: float(v) for label, v in zip(self.labels, clip)}
