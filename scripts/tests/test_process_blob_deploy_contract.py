"""Safety contracts for the process-blob Cloud Run deployment."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
PROCESS_BLOB_DOCKERFILE = ROOT / "cloud-functions/process-blob/Dockerfile"


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
        # No trailing "=" in the rejected flags: gcloud accepts both
        # "--set-env-vars=..." and "--set-secrets X=y:latest" spellings, and the
        # space-separated form is what this repo's deploy scripts use.
        self.assertNotIn("--set-env-vars", self.job)
        self.assertNotIn("--set-secrets", self.job)

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

    def test_c2patool_download_uses_the_official_release_and_verifies_it(self) -> None:
        dockerfile = PROCESS_BLOB_DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn("github.com/contentauth/c2pa-rs/releases/download/", dockerfile)
        self.assertIn("curl --retry 3 --retry-all-errors -fsSL", dockerfile)
        self.assertIn("sha256sum -c -", dockerfile)
        self.assertIn("--strip-components=1 c2patool/c2patool", dockerfile)
        self.assertIn("c2patool --version", dockerfile)
        self.assertNotIn("github.com/contentauth/c2patool/releases/", dockerfile)


if __name__ == "__main__":
    unittest.main()
