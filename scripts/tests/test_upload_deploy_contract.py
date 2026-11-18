"""Safety contracts for the upload-service Cloud Run deployment."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SCRIPT = ROOT / "cloud-run-upload/deploy.sh"


class UploadDeployContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    def test_deploy_owns_the_cleanup_bucket_configuration(self) -> None:
        self.assertIn('GCS_BUCKET="${GCS_BUCKET:-divine-blossom-media}"', self.script)
        self.assertIn("GCS_BUCKET=${GCS_BUCKET}", self.script)
        self.assertIn("--update-env-vars", self.script)
        self.assertNotIn("--set-env-vars", self.script)

    def test_production_deploy_rejects_a_different_bucket(self) -> None:
        self.assertIn('PRODUCTION_PROJECT_ID="rich-compiler-479518-d2"', self.script)
        self.assertIn('PRODUCTION_SERVICE_NAME="blossom-upload-rust"', self.script)
        self.assertIn('PRODUCTION_GCS_BUCKET="divine-blossom-media"', self.script)
        self.assertIn("Refusing production deploy: GCS_BUCKET must be", self.script)

    def test_deploy_preserves_unmanaged_secrets(self) -> None:
        self.assertIn("--update-secrets", self.script)
        self.assertNotIn("--set-secrets", self.script)

    def test_production_deploy_inherits_omitted_derivative_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gcloud = Path(directory) / "gcloud"
            gcloud.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n', encoding="utf-8")
            gcloud.chmod(0o755)
            env = dict(os.environ)
            for binding in ("TRANSCODER_URL", "TRANSCRIBER_URL", "TRANSCODE_QUEUE",
                            "TRANSCODE_QUEUE_INVOKER_SA"):
                env.pop(binding, None)
            env.update(
                PATH=f"{directory}:{env['PATH']}",
                PROJECT_ID="rich-compiler-479518-d2",
                SERVICE_NAME="blossom-upload-rust",
                GCS_BUCKET="divine-blossom-media",
                TRANSCODE_QUEUE="",
            )
            result = subprocess.run(
                ["bash", str(DEPLOY_SCRIPT)], text=True, capture_output=True, env=env, check=True,
            )
            env_update = result.stdout.split("--update-env-vars\n", 1)[1].splitlines()[0]
            self.assertIn(",TRANSCODE_QUEUE=", env_update)
            self.assertNotIn("TRANSCODER_URL=", env_update)
            self.assertNotIn("TRANSCRIBER_URL=", env_update)
            self.assertNotIn("TRANSCODE_QUEUE_INVOKER_SA=", env_update)


if __name__ == "__main__":
    unittest.main()
