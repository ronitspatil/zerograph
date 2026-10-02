"""Safety regressions: no cluster access or Docker required."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.kubernetes import Drill, DrillError, check_config, private_file, run


def config():
    return {
        "current-context": "kind-owned",
        "clusters": [{"name": "kind-owned", "cluster": {"server": "https://127.0.0.1:1234"}}],
        "contexts": [{"name": "kind-owned", "context": {"cluster": "kind-owned"}}],
    }


class SafetyTests(unittest.TestCase):
    def test_context_and_endpoint_are_pinned(self):
        current = config()
        self.assertEqual(check_config(current, "kind-owned"), "https://127.0.0.1:1234")
        for mutate in (
            lambda c: c.update({"current-context": "live"}),
            lambda c: c["clusters"][0]["cluster"].update(server="https://customer.example.com"),
            lambda c: c["clusters"][0]["cluster"].update(server="http://127.0.0.1:1234"),
            lambda c: c["contexts"].append(c["contexts"][0]),
            lambda c: c["contexts"][0]["context"].update(cluster="live"),
        ):
            current = config()
            mutate(current)
            with self.assertRaises(DrillError):
                check_config(current, "kind-owned")
        with self.assertRaises(DrillError):
            check_config(config(), "kind-owned", "https://127.0.0.1:4567")

    def test_sensitive_file_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private"
            private_file(path, "sensitive")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                private_file(path, "replacement")
            self.assertEqual(path.read_text(), "sensitive")

    def test_commands_refuse_before_cluster_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            with patch.object(drill, "command") as command:
                for operation in (
                    lambda: drill.kubectl("delete", "namespace", "customer"),
                    lambda: drill.helm("uninstall", "customer"),
                ):
                    with self.assertRaises(DrillError):
                        operation()
                command.assert_not_called()

    def test_node_label_mismatch_refuses_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            with patch.object(
                drill, "command", return_value='[{"Config":{"Labels":{"io.x-k8s.kind.cluster":"customer"}}}]'
            ):
                with self.assertRaises(DrillError):
                    drill.owned_node()

    def test_subprocess_errors_do_not_expose_sensitive_inputs(self):
        with patch("deploy.kubernetes.subprocess.run") as command:
            command.return_value.returncode = 1
            command.return_value.stdout = "secret output"
            command.return_value.stderr = "secret error"
            with self.assertRaisesRegex(DrillError, "safe operation: exit 1") as error:
                run(
                    ["tool", "secret argument"],
                    env={"SECRET": "secret value"},
                    data="secret manifest",
                    label="safe operation",
                )
            self.assertNotIn("secret", str(error.exception))

    def test_symlink_and_public_kubeconfig_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            drill.created = True
            private_file(drill.kubeconfig, "unused")
            os.chmod(drill.kubeconfig, 0o644)
            with self.assertRaises(DrillError):
                drill.guard()
            drill.kubeconfig.unlink()
            target = Path(folder) / "target"
            private_file(target, "unused")
            drill.kubeconfig.symlink_to(target)
            with self.assertRaises(DrillError):
                drill.guard()


if __name__ == "__main__":
    unittest.main()
