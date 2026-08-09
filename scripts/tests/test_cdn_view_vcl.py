# ABOUTME: Tests the CDN view-logging regexes exactly as they appear in vcl/log_cdn_views.vcl.
# ABOUTME: Guards the VCL escaping rule and keeps the runbook copies from drifting.

"""Tests for the CDN view-counting VCL regexes.

There is no local Fastly compiler, so the risk this file covers is that the
patterns *look* right and behave differently once VCL string semantics are
applied. VCL string literals do not process backslash escapes -- Fastly uses
percent escapes (``%22``) and hands a backslash straight to the regex engine.
Writing ``\\\\?`` therefore produces "optional literal backslash", which matches
the empty string; the path allow-list silently degenerates into "anything
starting with /{sha}" and the query-strip regsub eats the whole URL.

So these tests read the literal bytes between the quotes in
``vcl/log_cdn_views.vcl`` and feed them to a real regex engine unchanged, which
is the same thing Fastly does. A test that retyped the patterns here would pass
while production stayed broken.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VCL_PATH = os.path.join(REPO_ROOT, "vcl", "log_cdn_views.vcl")
RUNBOOK_PATH = os.path.join(REPO_ROOT, "docs", "runbooks", "cdn-view-counting.md")

SHA = "a" * 64
UPPER_SHA = "A" * 63 + "b"


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def extract_url_condition(vcl_source):
    """Return the req.url regex literal, verbatim, from the snippet's condition."""
    match = re.search(r'req\.url\s*~\s*"([^"]*)"', vcl_source)
    assert match, "no `req.url ~ \"...\"` condition found in the VCL snippet"
    return match.group(1)


def extract_regsubs(source):
    """Return [(pattern, replacement), ...] for every regsub(req.url, ...) call."""
    return re.findall(
        r'regsub\(\s*req\.url\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)',
        source,
    )


VCL_SOURCE = read(VCL_PATH)
URL_CONDITION = extract_url_condition(VCL_SOURCE)
REGSUBS = extract_regsubs(VCL_SOURCE)


class TestNoOverEscaping(unittest.TestCase):
    """The specific mistake that motivated this file."""

    def test_condition_uses_single_backslash_escapes(self):
        self.assertNotIn(
            "\\\\",
            URL_CONDITION,
            "doubled backslash in a VCL string literal reaches the regex engine as a "
            "literal backslash, not as a regex escape",
        )

    def test_regsub_patterns_use_single_backslash_escapes(self):
        for pattern, _ in REGSUBS:
            self.assertNotIn("\\\\", pattern, pattern)


class TestPathAllowList(unittest.TestCase):
    def setUp(self):
        self.pattern = re.compile(URL_CONDITION)

    def assert_matches(self, url):
        self.assertIsNotNone(self.pattern.search(url), "should log: %s" % url)

    def assert_rejects(self, url):
        self.assertIsNone(self.pattern.search(url), "should not log: %s" % url)

    def test_canonical_and_derivative_video_paths_match(self):
        for url in [
            "/%s" % SHA,
            "/%s?dl=1" % SHA,
            "/%s.mp4" % SHA,
            "/%s.mp4?dl=1" % SHA,
            "/%s/720p" % SHA,
            "/%s/480p" % SHA,
            "/%s/720p.mp4" % SHA,
            "/%s/480p.mp4?t=3" % SHA,
            "/%s/hls/stream_720p.ts" % SHA,
            "/%s/hls/stream_480p.mp4" % SHA,
        ]:
            self.assert_matches(url)

    def test_uppercase_hash_matches_because_routing_accepts_it(self):
        # blossom-core parse_hash_from_path validates with is_ascii_hexdigit and
        # then lowercases, so an uppercase request is served normally.
        self.assert_matches("/%s" % UPPER_SHA)

    def test_non_view_paths_are_rejected(self):
        # These are the paths the design excludes. Several also fail the
        # Content-Type guard, but the allow-list must not be the thing that
        # stopped working -- an over-escaped pattern accepts every one of them.
        for url in [
            "/%s.jpg" % SHA,  # thumbnail
            "/%s.audio.m4a" % SHA,  # audio extraction
            "/%s/provenance" % SHA,
            "/%s/hls/master.m3u8" % SHA,
            "/%s/hls/stream_720p.m3u8" % SHA,
            "/%s/vtt/main.vtt" % SHA,
            "/%s/1080p" % SHA,
            "/%s/hls/stream_720p.key" % SHA,
            "/upload",
            "/list/%s" % SHA,
            "/%s" % ("a" * 63),  # too short to be a sha256
        ]:
            self.assert_rejects(url)

    def test_hash_prefix_alone_does_not_authorise_the_rest_of_the_path(self):
        # The regression guard: with `\\?` in the alternation this matched.
        self.assert_rejects("/%s/anything/else" % SHA)


class TestFieldExtraction(unittest.TestCase):
    """regsub replaces the first match only, and returns the input unchanged on no match."""

    def setUp(self):
        by_replacement = {replacement: pattern for pattern, replacement in REGSUBS}
        self.sha_pattern = by_replacement["\\1"]
        self.strip_pattern = by_replacement[""]

    def regsub(self, pattern, replacement, value):
        return re.sub(pattern, replacement, value, count=1)

    def test_sha256_is_extracted_from_derivative_paths(self):
        for url in [
            "/%s" % SHA,
            "/%s.mp4" % SHA,
            "/%s/720p.mp4?t=3" % SHA,
            "/%s/hls/stream_480p.ts" % SHA,
        ]:
            self.assertEqual(self.regsub(self.sha_pattern, "\\1", url), SHA)

    def test_query_strip_keeps_the_path(self):
        # The bug this replaces: an over-escaped pattern matched at offset 0 and
        # replaced the entire URL with the empty string, so every row lost the
        # path that media_path_type classification reads.
        self.assertEqual(
            self.regsub(self.strip_pattern, "", "/%s/720p.mp4?t=3" % SHA),
            "/%s/720p.mp4" % SHA,
        )
        self.assertEqual(
            self.regsub(self.strip_pattern, "", "/%s" % SHA),
            "/%s" % SHA,
        )

    def test_stripped_path_is_json_safe(self):
        # The log line interpolates `path` into JSON without escaping, so the
        # allow-list is what keeps quotes and backslashes out of the payload.
        allowed = re.compile(r"^[0-9A-Za-z/._]+$")
        for url in ["/%s" % SHA, "/%s/hls/stream_720p.ts?x=%%22" % SHA]:
            stripped = self.regsub(self.strip_pattern, "", url)
            self.assertRegex(stripped, allowed)


class TestNormalisation(unittest.TestCase):
    def test_logged_sha256_and_path_are_lowercased(self):
        # Downstream joins are against lowercase hashes; the service lowercases
        # server-side, so the log row has to as well.
        for field in ('"sha256"', '"path"'):
            line = next(
                line for line in VCL_SOURCE.splitlines() if field in line and "regsub" in line
            )
            self.assertIn("std.tolower(", line, line.strip())


class TestRunbookHasNotDrifted(unittest.TestCase):
    """One authoritative copy of each regex, enforced rather than requested."""

    def setUp(self):
        self.runbook = read(RUNBOOK_PATH)

    def test_response_condition_matches_the_vcl_file(self):
        self.assertEqual(extract_url_condition(self.runbook), URL_CONDITION)

    def test_log_format_regsubs_match_the_vcl_file(self):
        self.assertEqual(extract_regsubs(self.runbook), REGSUBS)


if __name__ == "__main__":
    unittest.main()
