"""Safety contracts for the upload-service Cloud Run deployment."""

from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
