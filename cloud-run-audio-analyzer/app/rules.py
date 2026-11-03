# ABOUTME: Turns PANNs AudioSet clip scores into a sound's kind, scores and tags.
# ABOUTME: Pure Python, no torch: the product rules live here so they are testable.

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional

_GROUPS = json.loads((Path(__file__).parent / "audioset_groups.json").read_text())
SPEECH_CLASSES = frozenset(_GROUPS["speech"])
MUSIC_CLASSES = frozenset(_GROUPS["music"])
NOT_EFFECT_CLASSES = frozenset(_GROUPS["not_effect"])

# Coarse labels exposed to search. Each is the max over its AudioSet classes.
GENRES: Dict[str, List[str]] = {
    "classical": ["Classical music", "Opera"],
    "rock": ["Rock music", "Heavy metal", "Punk rock", "Grunge", "Progressive rock",
             "Rock and roll", "Psychedelic rock"],
    "hiphop": ["Hip hop music", "Beatboxing"],
    "electronic": ["Electronic music", "House music", "Techno", "Dubstep", "Drum and bass",
                   "Electronica", "Electronic dance music", "Ambient music", "Trance music"],
    "pop": ["Pop music", "Disco", "Rhythm and blues", "Soul music"],
    "jazz": ["Jazz", "Swing music", "Blues", "Music of Latin America"],
    "folk": ["Folk music", "Country", "Bluegrass", "Traditional music"],
}
INSTRUMENTS: Dict[str, List[str]] = {
    "piano": ["Piano", "Electric piano", "Keyboard (musical)"],
    "guitar": ["Guitar", "Electric guitar", "Acoustic guitar", "Bass guitar",
               "Steel guitar, slide guitar", "Strum"],
    "drums": ["Drum kit", "Drum", "Snare drum", "Bass drum", "Percussion", "Drum machine",
              "Tabla"],
    "violin": ["Violin, fiddle", "Bowed string instrument", "String section", "Cello",
               "Pizzicato"],
    "synthesizer": ["Synthesizer", "Sampler"],
    "vocals": ["Singing", "Male singing", "Female singing", "Choir", "Rapping",
               "A capella", "Vocal music"],
}
MOODS: Dict[str, List[str]] = {
    "calm": ["Tender music"],
    "happy": ["Happy music", "Funny music"],
    "sad": ["Sad music"],
    "energetic": ["Exciting music", "Angry music"],
    "scary": ["Scary music"],
}


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass(frozen=True)
class Thresholds:
    """Defaults come from the labelled-sample evaluation on divine-blossom#319."""

    # `music` needs music to be the top kind and score at least this.
    music_min: float = field(default_factory=lambda: _env_float("ANALYZER_MUSIC_MIN", 0.5))
    # Speech clips shorter than this are meme sound bites and count as `sfx`.
    short_speech_max_s: float = field(
        default_factory=lambda: _env_float("ANALYZER_SHORT_SPEECH_MAX_S", 2.5)
    )
    instrument_min: float = field(
        default_factory=lambda: _env_float("ANALYZER_INSTRUMENT_MIN", 0.2)
    )
    audioset_tag_min: float = field(
        default_factory=lambda: _env_float("ANALYZER_AUDIOSET_TAG_MIN", 0.1)
    )
    audioset_tag_count: int = 10


@dataclass
class Label:
    label: str
    score: float


@dataclass
class Analysis:
    # "music", "sfx" or None. None means the sound shows only under "All".
    kind: Optional[str]
    # Top acoustic kind before the product rules: "music", "speech" or "effect".
    detected: str
    scores: Dict[str, Dict[str, float]]
    tags: List[str]
    audioset: List[Label]

    def to_dict(self) -> dict:
        return asdict(self)


def _group_max(scores: Mapping[str, float], classes) -> float:
    return max((scores.get(c, 0.0) for c in classes), default=0.0)


def _rounded(values: Mapping[str, float]) -> Dict[str, float]:
    return {k: round(v, 4) for k, v in values.items()}


def analyze_scores(
    scores: Mapping[str, float],
    analyzed_seconds: float,
    thresholds: Optional[Thresholds] = None,
) -> Analysis:
    """Apply the product rules to clip-level AudioSet scores.

    - Pure speech gets no kind; it is listed only under "All".
    - Speech shorter than `short_speech_max_s` is a sound bite and counts as `sfx`.
    - Genre is only reported for music; mood is returned as scores but never
      becomes a tag, because AudioSet mood scores are too low on 6-second clips
      to threshold reliably.
    """
    t = thresholds or Thresholds()
    kinds = {
        "music": _group_max(scores, MUSIC_CLASSES),
        "speech": _group_max(scores, SPEECH_CLASSES),
        "effect": max(
            (v for c, v in scores.items()
             if c not in SPEECH_CLASSES and c not in MUSIC_CLASSES and c not in NOT_EFFECT_CLASSES),
            default=0.0,
        ),
    }
    detected = max(kinds, key=kinds.get)

    kind: Optional[str] = None
    if detected == "music" and kinds["music"] >= t.music_min:
        kind = "music"
    elif detected == "effect":
        kind = "sfx"
    elif detected == "speech" and analyzed_seconds < t.short_speech_max_s:
        kind = "sfx"

    genres = {g: _group_max(scores, cs) for g, cs in GENRES.items()}
    instruments = {i: _group_max(scores, cs) for i, cs in INSTRUMENTS.items()}
    moods = {m: _group_max(scores, cs) for m, cs in MOODS.items()}

    tags: List[str] = [kind] if kind else []
    if kind == "music":
        tags.append(max(genres, key=genres.get))
        tags += [i for i, v in sorted(instruments.items(), key=lambda kv: -kv[1])
                 if v >= t.instrument_min]

    top = sorted(scores.items(), key=lambda kv: -kv[1])
    audioset = [Label(name, round(v, 4)) for name, v in top[: t.audioset_tag_count]
                if v >= t.audioset_tag_min]

    return Analysis(
        kind=kind,
        detected=detected,
        scores={
            "kind": _rounded(kinds),
            "genre": _rounded(genres),
            "instrument": _rounded(instruments),
            "mood": _rounded(moods),
        },
        tags=tags,
        audioset=audioset,
    )
