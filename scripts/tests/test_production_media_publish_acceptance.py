import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock
import urllib.error

from scripts.production_media_publish_acceptance import (
    AcceptanceError,
    FEED_EXCLUSION_ENV,
    NakClient,
    anonymous_head_status,
    build_parser,
    build_video_tags,
    main,
    poll_until,
    require_feed_exclusion,
    run_acceptance,
    validate_signed_event,
    validate_upload_descriptor,
)


HASH = "ab" * 32
PUBKEY = "cd" * 32
EVENT_ID = "ef" * 32
SIGNATURE = "01" * 64


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class ProductionMediaPublishAcceptanceTests(unittest.TestCase):
    def test_video_tags_are_relay_valid_format_one_imeta(self) -> None:
        tags = build_video_tags(
            d_tag="stable-coordinate",
            media_url=f"https://media.example/{HASH}",
            thumbnail_url=f"https://media.example/{HASH}.jpg",
            media_hash=HASH,
            media_size=123,
            mime_type="video/mp4",
            dimensions="64x64",
            title="Synthetic acceptance",
            run_nonce="run-1",
        )

        self.assertEqual(tags[0], ["d", "stable-coordinate"])
        self.assertEqual(tags[1], ["title", "Synthetic acceptance"])
        self.assertEqual(tags[2], ["client", "divine-production-acceptance"])
        self.assertEqual(tags[3], ["nonce", "run-1"])
        self.assertEqual(
            tags[4],
            [
                "imeta",
                f"url https://media.example/{HASH}",
                "m video/mp4",
                f"x {HASH}",
                "size 123",
                "dim 64x64",
                f"image https://media.example/{HASH}.jpg",
            ],
        )
        self.assertTrue(all(" " in entry for entry in tags[4][1:]))

    def test_feed_exclusion_is_a_hard_publish_gate(self) -> None:
        with self.assertRaisesRegex(AcceptanceError, "refusing to publish"):
            require_feed_exclusion({})
        require_feed_exclusion({FEED_EXCLUSION_ENV: "1"})

    def test_upload_descriptor_must_match_local_fixture(self) -> None:
        descriptor = {
            "sha256": HASH,
            "size": 123,
            "type": "video/mp4",
            "url": f"https://media.example/{HASH}",
            "thumbnail": f"https://media.example/{HASH}.jpg",
            "dim": "64x64",
        }
        self.assertEqual(
            validate_upload_descriptor(
                descriptor, media_hash=HASH, size=123, mime_type="video/mp4"
            ),
            (f"https://media.example/{HASH}.jpg", "64x64"),
        )
        descriptor["size"] = 124
        with self.assertRaisesRegex(AcceptanceError, "size"):
            validate_upload_descriptor(
                descriptor, media_hash=HASH, size=123, mime_type="video/mp4"
            )

    def test_signed_event_preserves_exact_coordinate_and_hash(self) -> None:
        event = {
            "id": EVENT_ID,
            "pubkey": PUBKEY,
            "sig": SIGNATURE,
            "kind": 34236,
            "tags": [["d", "stable"], ["imeta", f"x {HASH}"]],
        }
        validate_signed_event(event, d_tag="stable", media_hash=HASH)
        event["id"] = "short"
        with self.assertRaisesRegex(AcceptanceError, "invalid id"):
            validate_signed_event(event, d_tag="stable", media_hash=HASH)

    def test_nak_receives_secret_only_through_environment(self) -> None:
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout="nostr army knife", stderr="")

        client = NakClient("nak-nostr", "nsec-secret", 10, runner=runner)
        client.validate_binary()

        command, kwargs = calls[0]
        self.assertNotIn("nsec-secret", command)
        self.assertNotIn("nsec-secret", kwargs.get("input") or "")
        self.assertEqual(kwargs["env"]["NOSTR_SECRET_KEY"], "nsec-secret")

    def test_nak_sign_event_preserves_multivalue_tags(self) -> None:
        tags = [["d", "stable"], ["imeta", "url https://media.example/video", "m video/mp4"]]

        def runner(command, **kwargs):
            partial_event = json.loads(kwargs["input"])
            self.assertEqual(command, ["nak-nostr", "event"])
            self.assertEqual(partial_event["tags"], tags)
            event = {
                **partial_event,
                "id": EVENT_ID,
                "pubkey": PUBKEY,
                "sig": SIGNATURE,
            }
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(event), stderr="")

        client = NakClient("nak-nostr", "nsec-secret", 10, runner=runner)

        event = client.sign_event(34236, "Synthetic acceptance", tags)

        self.assertEqual(event["tags"], tags)

    def test_acceptance_suppresses_upload_harness_trace(self) -> None:
        args = build_parser().parse_args([])
        environment = {
            FEED_EXCLUSION_ENV: "1",
            "DIVINE_ACCEPTANCE_NSEC": "nsec-secret",
        }
        with mock.patch(
            "scripts.production_media_publish_acceptance.anonymous_head_status",
            return_value=200,
        ), mock.patch(
            "scripts.production_media_publish_acceptance.NakClient"
        ) as nak_class, mock.patch(
            "scripts.production_media_publish_acceptance.UploadHttpClient"
        ) as upload_client_class, mock.patch(
            "scripts.production_media_publish_acceptance.run_legacy_upload",
            side_effect=AcceptanceError("stop after client construction"),
        ):
            nak_class.return_value.blossom_upload_auth.return_value = ("Nostr auth", PUBKEY)

            with self.assertRaisesRegex(AcceptanceError, "stop after client construction"):
                run_acceptance(args, environment)

        output_stream = upload_client_class.call_args.kwargs["output_stream"]
        self.assertIsInstance(output_stream, io.StringIO)

    def test_nak_failure_does_not_echo_secret_or_stderr(self) -> None:
        def runner(command, **_kwargs):
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="failure nsec-secret"
            )

        client = NakClient("nak-nostr", "nsec-secret", 10, runner=runner)
        with self.assertRaises(AcceptanceError) as raised:
            client.validate_binary()
        self.assertNotIn("nsec-secret", str(raised.exception))

    def test_coordinate_query_requires_exact_event_id(self) -> None:
        outputs = [
            json.dumps({"id": "00" * 32}),
            "\n".join((json.dumps({"id": "00" * 32}), json.dumps({"id": EVENT_ID}))),
        ]

        def runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, stdout=outputs.pop(0), stderr="")

        client = NakClient("nak-nostr", "secret", 10, runner=runner)
        first = client.query_coordinate("wss://relay.example", PUBKEY, "stable")
        second = client.query_coordinate("wss://relay.example", PUBKEY, "stable")
        self.assertNotIn(EVENT_ID, [event["id"] for event in first])
        self.assertIn(EVENT_ID, [event["id"] for event in second])

    def test_poll_uses_bounded_deadline(self) -> None:
        clock = FakeClock()
        with self.assertRaisesRegex(AcceptanceError, "relay read-back bounded poll expired"):
            poll_until(
                lambda: False,
                stage="relay read-back",
                deadline_seconds=5,
                interval_seconds=2,
                clock=clock,
                sleep=clock.sleep,
            )
        self.assertEqual(clock.now, 5)

    def test_anonymous_media_network_failure_names_stage(self) -> None:
        with mock.patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("offline")
        ):
            with self.assertRaisesRegex(AcceptanceError, "pre-upload media check failed"):
                anonymous_head_status("https://media.example/hash", 10, "pre-upload media check")
            with self.assertRaisesRegex(AcceptanceError, "uploaded media check failed"):
                anonymous_head_status("https://media.example/hash", 10, "uploaded media check")

    def test_cli_failure_does_not_print_secret(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(
            "os.environ",
            {FEED_EXCLUSION_ENV: "1", "DIVINE_ACCEPTANCE_NSEC": "nsec-secret"},
            clear=True,
        ), mock.patch(
            "scripts.production_media_publish_acceptance.NakClient.validate_binary",
            side_effect=AcceptanceError("Nostr command failed"),
        ), mock.patch("sys.stdout", output):
            exit_code = main(["--json"])
        self.assertEqual(exit_code, 1)
        self.assertNotIn("nsec-secret", output.getvalue())

    def test_cli_rejects_missing_fixture_without_traceback(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(
            "os.environ",
            {FEED_EXCLUSION_ENV: "1", "DIVINE_ACCEPTANCE_NSEC": "nsec-secret"},
            clear=True,
        ), mock.patch("sys.stdout", output):
            exit_code = main(["--json", "--fixture", "/missing/fixture.mp4"])
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"verdict": "fail", "reason": "fixture is not a readable file"},
        )

    def test_default_fixture_is_committed_supported_media(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "readiness_ok.mp4"
        self.assertTrue(fixture.exists())
        self.assertIn(b"moov", fixture.read_bytes())


if __name__ == "__main__":
    unittest.main()
