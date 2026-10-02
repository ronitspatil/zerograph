"""Cleanup refusal tests: ownership of both resources precedes all deletion."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "oidc-cleanup.py"
spec = importlib.util.spec_from_file_location("oidc_cleanup", MODULE)
cleanup_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup_module)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(
            tempfile.mkdtemp(prefix="zerograph-oidc-qualification.", dir="/tmp")
        ).resolve()
        self.env_dir = tempfile.TemporaryDirectory(prefix="oidc-env-")
        self.env = Path(self.env_dir.name) / ".env"
        self.nonce = "c" * 64
        marker = {
            "kind": "zerograph-oidc-qualification",
            "directory": str(self.directory),
            "env_file": str(self.env.resolve()),
            "uid": os.getuid(),
            "nonce": self.nonce,
        }
        self.marker = self.directory / ".owner.json"
        self.marker.write_text(json.dumps(marker))
        self.marker.chmod(0o600)
        self.env.write_text(
            f"ZG_OIDC_FIXTURE_DIR={self.directory}\nZG_OIDC_FIXTURE_OWNER={self.nonce}\n"
        )
        self.env.chmod(0o600)
        (self.directory / "sensitive").write_text("disposable-secret")

    def tearDown(self):
        # Tests own their allocated paths; preserve no external symlink targets.
        import shutil

        if self.directory.exists():
            shutil.rmtree(self.directory)
        self.env_dir.cleanup()

    def refused(self):
        with self.assertRaises((ValueError, OSError)):
            cleanup_module.cleanup(self.directory, self.env)
        self.assertTrue(self.directory.exists())
        self.assertTrue((self.directory / "sensitive").exists())
        self.assertTrue(self.env.exists())

    def test_valid_cleanup(self):
        cleanup_module.cleanup(self.directory, self.env)
        self.assertFalse(self.directory.exists())
        self.assertFalse(self.env.exists())

    def test_environment_mismatch_preserves_both_resources(self):
        self.env.write_text("unrelated-environment-secret")
        self.refused()

    def test_missing_marker_preserves_resources(self):
        self.marker.unlink()
        self.refused()

    def test_nonmatching_owner_marker_preserves_resources(self):
        marker = json.loads(self.marker.read_text())
        marker["uid"] = os.getuid() + 1
        self.marker.write_text(json.dumps(marker))
        self.refused()

    def test_world_readable_environment_refused(self):
        self.env.chmod(0o644)
        self.refused()

    def test_public_fixture_directory_refused(self):
        self.directory.chmod(0o755)
        self.refused()

    def test_symlink_descendant_refused(self):
        (self.directory / "linked-secret").symlink_to(self.env)
        self.refused()

    def test_symlink_environment_refused_before_directory_deletion(self):
        target = self.env.parent / "external-env"
        self.env.rename(target)
        self.env.symlink_to(target)
        self.refused()
        self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
