"""Safety contracts for the production transcoder deploy script."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


TRANSCODER_DIR = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = TRANSCODER_DIR / "deploy.sh"


class TranscoderDeployGuardTest(unittest.TestCase):
    def run_deploy(
        self, *, project_id: str, service_name: str, gcs_bucket: str,
        dispatch_secret_name: str = "synthetic-transcode-dispatch",
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            calls_path = temp_path / "gcloud-calls"
            gcloud_path = temp_path / "gcloud"
            gcloud_path.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$GCLOUD_CALLS"\nexit 0\n',
                encoding="utf-8",
            )
            gcloud_path.chmod(gcloud_path.stat().st_mode | stat.S_IXUSR)

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{temp_path}:{env['PATH']}",
                    "GCLOUD_CALLS": str(calls_path),
                    "PROJECT_ID": project_id,
                    "GCP_PROJECT_ID": project_id,
                    "SERVICE_NAME": service_name,
                    "SERVICE_ACCOUNT": "runtime@example.invalid",
                    "IMAGE_TAG": "test",
                    "GCS_BUCKET": gcs_bucket,
                    "TRANSCODE_QUEUE": "projects/synthetic/locations/us-central1/queues/transcode",
                    "TRANSCODE_WORKER_URL": "https://transcoder.example.invalid",
                    "TRANSCODE_DISPATCH_SECRET_NAME": dispatch_secret_name,
                    "TRANSCODE_DISPATCH_SECRET_VERSION": "1",
                    "TRANSCODE_WRITES_PAUSED": "true",
                }
            )

            result = subprocess.run(
                ["bash", str(DEPLOY_SCRIPT)],
                cwd=TRANSCODER_DIR,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            calls = calls_path.read_text(encoding="utf-8") if calls_path.exists() else ""
            return result, calls

    def test_production_deploy_rejects_nonproduction_bucket_before_build(self) -> None:
        # Reproduces the deploy that redirected the production transcoder to a
        # non-production bucket and broke transcoding for four and a half hours.
        # This is the staging bucket value exported during the incident, so the
        # test reproduces an input the guard must reject instead of using an
        # arbitrary value.
        result, calls = self.run_deploy(
            project_id="rich-compiler-479518-d2",
            service_name="divine-transcoder",
            gcs_bucket="divine-blossom-media-staging",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing production deploy", result.stderr)
        self.assertNotIn("builds submit", calls)

    def test_nonproduction_service_can_use_nonproduction_bucket(self) -> None:
        result, calls = self.run_deploy(
            project_id="example-staging-project",
            service_name="divine-transcoder-staging",
            gcs_bucket="divine-blossom-media-staging",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("builds submit", calls)
        self.assertIn("run deploy divine-transcoder-staging", calls)
        self.assertIn("--no-traffic", calls)
        self.assertIn("TRANSCODE_WRITES_PAUSED=true", calls)
        self.assertIn("TRANSCODE_DISPATCH_SECRET=synthetic-transcode-dispatch:1", calls)

    def test_dispatch_credential_is_independent_of_webhook_rotation(self) -> None:
        result, calls = self.run_deploy(
            project_id="example-staging-project",
            service_name="divine-transcoder-staging",
            gcs_bucket="synthetic-staging",
            dispatch_secret_name="webhook_secret",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("builds submit", calls)


if __name__ == "__main__":
    unittest.main()
