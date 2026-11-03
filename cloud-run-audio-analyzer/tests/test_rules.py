# ABOUTME: Unit tests for the kind and tag rules applied to AudioSet scores.
# ABOUTME: Pure Python; does not load torch or the PANNs checkpoint.

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.rules import (  # noqa: E402
    GENRES, INSTRUMENTS, MOODS, MUSIC_CLASSES, NOT_EFFECT_CLASSES, SPEECH_CLASSES,
    Thresholds, analyze_scores,
)

T = Thresholds(music_min=0.5, short_speech_max_s=2.5, instrument_min=0.2,
               audioset_tag_min=0.1, audioset_tag_count=10)


class TestKind(unittest.TestCase):
    def test_confident_music_is_music(self):
        a = analyze_scores({"Music": 0.9, "Speech": 0.1, "Dog": 0.05}, 6.3, T)
        self.assertEqual(a.detected, "music")
        self.assertEqual(a.kind, "music")
        self.assertEqual(a.tags[0], "music")

    def test_weak_music_gets_no_kind(self):
        a = analyze_scores({"Music": 0.4, "Speech": 0.1}, 6.3, T)
        self.assertEqual(a.detected, "music")
        self.assertIsNone(a.kind)
        self.assertEqual(a.tags, [])

    def test_effect_is_sfx_without_a_threshold(self):
        a = analyze_scores({"Dog": 0.2, "Music": 0.05, "Speech": 0.1}, 6.3, T)
        self.assertEqual(a.detected, "effect")
        self.assertEqual(a.kind, "sfx")
        self.assertEqual(a.tags, ["sfx"])

    def test_speech_shows_only_under_all(self):
        a = analyze_scores({"Speech": 0.9, "Music": 0.2}, 6.3, T)
        self.assertEqual(a.detected, "speech")
        self.assertIsNone(a.kind)
        self.assertEqual(a.tags, [])

    def test_short_speech_is_a_sound_bite(self):
        a = analyze_scores({"Speech": 0.9, "Music": 0.2}, 0.8, T)
        self.assertEqual(a.detected, "speech")
        self.assertEqual(a.kind, "sfx")

    def test_speech_at_the_limit_is_not_a_sound_bite(self):
        a = analyze_scores({"Speech": 0.9}, 2.5, T)
        self.assertIsNone(a.kind)

    def test_background_classes_do_not_count_as_effects(self):
        a = analyze_scores({"Speech": 0.3, "Inside, small room": 0.9, "Silence": 0.8}, 6.3, T)
        self.assertEqual(a.detected, "speech")
        self.assertEqual(a.scores["kind"]["effect"], 0.0)

    def test_singing_counts_as_music(self):
        a = analyze_scores({"Singing": 0.8, "Speech": 0.5}, 6.3, T)
        self.assertEqual(a.kind, "music")


class TestTags(unittest.TestCase):
    def test_music_gets_top_genre_and_confident_instruments(self):
        a = analyze_scores({"Music": 0.95, "Classical music": 0.3, "Jazz": 0.1,
                            "Piano": 0.7, "Violin, fiddle": 0.25, "Guitar": 0.1}, 6.3, T)
        self.assertEqual(a.tags, ["music", "classical", "piano", "violin"])

    def test_effects_never_get_genre_or_instrument_tags(self):
        a = analyze_scores({"Explosion": 0.6, "Piano": 0.3, "Rock music": 0.2}, 3.0, T)
        self.assertEqual(a.tags, ["sfx"])

    def test_mood_is_scored_but_never_tagged(self):
        a = analyze_scores({"Music": 0.9, "Sad music": 0.9}, 6.3, T)
        self.assertEqual(a.scores["mood"]["sad"], 0.9)
        self.assertNotIn("sad", a.tags)

    def test_audioset_labels_are_top_classes_above_the_floor(self):
        a = analyze_scores({"Music": 0.9, "Piano": 0.5, "Speech": 0.05}, 6.3, T)
        self.assertEqual([x.label for x in a.audioset], ["Music", "Piano"])

    def test_to_dict_is_json_ready(self):
        d = analyze_scores({"Music": 0.9, "Piano": 0.5}, 6.3, T).to_dict()
        self.assertEqual(d["kind"], "music")
        self.assertEqual(d["audioset"][0], {"label": "Music", "score": 0.9})
        self.assertEqual(set(d["scores"]), {"kind", "genre", "instrument", "mood"})


class TestGroups(unittest.TestCase):
    def test_groups_do_not_overlap(self):
        self.assertFalse(SPEECH_CLASSES & MUSIC_CLASSES)
        self.assertFalse(NOT_EFFECT_CLASSES & (SPEECH_CLASSES | MUSIC_CLASSES))

    def test_coarse_labels_point_into_the_music_group(self):
        for group in (GENRES, INSTRUMENTS, MOODS):
            for name, classes in group.items():
                for c in classes:
                    self.assertIn(c, MUSIC_CLASSES, f"{name}: {c}")


if __name__ == "__main__":
    unittest.main()
