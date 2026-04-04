import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


def load_process_blob_module():
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")
    storage = types.ModuleType("google.cloud.storage")
    vision = types.ModuleType("google.cloud.vision")
    vision_v1 = types.ModuleType("google.cloud.vision_v1")
    storage.Client = object
    vision.ImageAnnotatorClient = object
    vision.Likelihood = object
    vision_v1.types = types.SimpleNamespace(Image=object, ImageSource=object)

    sys.modules.setdefault("google", google)
    sys.modules["google.cloud"] = cloud
    sys.modules["google.cloud.storage"] = storage
    sys.modules["google.cloud.vision"] = vision
    sys.modules["google.cloud.vision_v1"] = vision_v1

    path = Path(__file__).with_name("main.py")
    spec = importlib.util.spec_from_file_location("process_blob_main", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProcessBlobTests(unittest.TestCase):
    def test_flagged_content_updates_metadata_without_deleting_blob(self):
        module = load_process_blob_module()
        blob = Mock()
        thumb_blob = Mock()
        bucket = Mock()
        bucket.blob.side_effect = [blob, thumb_blob]
        client = Mock()
        client.bucket.return_value = bucket

        with patch.object(module.storage, "Client", return_value=client):
            with patch.object(module, "update_metadata") as update_metadata:
                module.handle_moderation_result(
                    "bucket",
                    "hash",
                    {"is_flagged": True, "reason": "flagged", "scores": {"adult": "LIKELY"}},
                    "thumbnails/hash",
                )

        blob.delete.assert_not_called()
        thumb_blob.delete.assert_not_called()
        update_metadata.assert_called_once()


if __name__ == "__main__":
    unittest.main()
