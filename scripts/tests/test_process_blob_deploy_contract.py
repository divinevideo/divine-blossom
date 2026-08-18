"""Safety contracts for the process-blob Cloud Run deployment."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def extract_job(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  \S|\Z)",
        workflow,
        re.DOTALL | re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"{job_name} job is missing")
    return match.group("body")


class ProcessBlobDeployContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.job = extract_job(workflow, "deploy-process-blob")

    def test_deploy_preserves_unmanaged_environment_variables(self) -> None:
        self.assertIn("--update-env-vars=", self.job)
        self.assertNotIn("--set-env-vars=", self.job)
        self.assertNotIn("--set-secrets=", self.job)

    def test_deploy_uses_an_explicit_runtime_identity(self) -> None:
        self.assertIn(
            "GCP_RUNTIME_SERVICE_ACCOUNT: ${{ secrets.GCP_RUNTIME_SERVICE_ACCOUNT }}",
            self.job,
        )
        self.assertIn('if [ -z "$GCP_RUNTIME_SERVICE_ACCOUNT" ]; then', self.job)
        self.assertIn('--service-account="$GCP_RUNTIME_SERVICE_ACCOUNT"', self.job)

    def test_job_extraction_stops_at_the_next_job(self) -> None:
        workflow = """jobs:
  deploy-process-blob:
    steps:
      - run: expected
  unrelated:
    steps:
      - run: --set-env-vars=unexpected
"""

        self.assertEqual(
            "    steps:\n      - run: expected\n",
            extract_job(workflow, "deploy-process-blob"),
        )


if __name__ == "__main__":
    unittest.main()
