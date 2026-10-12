"""Verify the transcoder's isolated build context includes its shared dependency."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class TranscoderBuildContextTest(unittest.TestCase):
    def test_context_contains_only_service_and_core_build_inputs(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            subprocess.run(["bash", str(repo / "cloud-run-transcoder/prepare-build-context.sh"), str(context)], check=True)
            self.assertEqual({path.name for path in context.iterdir()},
                             {"Cargo.toml", "Cargo.lock", "Dockerfile", ".dockerignore", "src", "blossom-core"})
            self.assertTrue((context / "blossom-core/src/subtitle_lang.rs").is_file())
            self.assertEqual((context / "Cargo.lock").read_bytes(), (repo / "cloud-run-transcoder/Cargo.lock").read_bytes())
            self.assertIn('path = "../blossom-core"', (context / "Cargo.toml").read_text())
            self.assertIn("COPY blossom-core /blossom-core", (context / "Dockerfile").read_text())
            self.assertFalse(any(path.name in {"target", ".git", ".env"} for path in context.rglob("*")))
