"""Safety contracts for the process-blob Cloud Run deployment."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class ProcessBlobDeployContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r"^  deploy-process-blob:\n(?P<body>.*)\Z", workflow, re.DOTALL | re.MULTILINE)
        if match is None:
            raise AssertionError("deploy-process-blob job is missing")
        cls.job = match.group("body")

    def test_deploy_preserves_unmanaged_environment_variables(self) -> None:
        self.assertIn("--update-env-vars=", self.job)
        self.assertNotIn("--set-env-vars=", self.job)

    def test_deploy_uses_an_explicit_runtime_identity(self) -> None:
        self.assertIn(
            '--service-account="${{ secrets.GCP_RUNTIME_SERVICE_ACCOUNT }}"',
            self.job,
        )


if __name__ == "__main__":
    unittest.main()
