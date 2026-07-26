"""Contract tests for compiler artifact release and infrastructure promotion."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/compiler-release.yml"


class CompilerReleaseWorkflowTest(unittest.TestCase):
    def test_imperative_cloud_run_deploy_is_removed(self) -> None:
        self.assertFalse((ROOT / "cloud-run-compiler/deploy.sh").exists())

    def test_release_is_explicit_and_runs_all_compiler_checks(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("inputs.promote_image && inputs.deploy_worker", workflow)
        self.assertIn(
            "cargo test --manifest-path cloud-run-compiler/Cargo.toml --locked",
            workflow,
        )
        self.assertIn(
            "cargo clippy --manifest-path cloud-run-compiler/Cargo.toml",
            workflow,
        )
        self.assertIn("npm test", workflow)
        self.assertIn("npm run build", workflow)

    def test_image_is_pushed_and_promoted_by_digest(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("containers-production/divine-compiler", workflow)
        self.assertIn("docker/build-push-action", workflow)
        self.assertIn("steps.compiler-image.outputs.digest", workflow)
        self.assertIn("event_type: 'image-deploy'", workflow)
        self.assertIn("application: 'divine-compiler'", workflow)
        self.assertIn("environments: ['production']", workflow)

    def test_worker_deploy_uses_managed_variables_and_secrets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("wrangler deploy", workflow)
        self.assertIn("COMPILER_SERVICE_URL", workflow)
        self.assertIn("GOOGLE_SERVICE_ACCOUNT_EMAIL", workflow)
        self.assertIn("GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY", workflow)
        self.assertIn("CLOUDFLARE_API_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main()
