"""Safety regressions: no cluster access or Docker required."""

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.kubernetes import Drill, DrillError, check_config, private_file, run


def config():
    embedded = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----").decode()
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "users": [
            {"name": "kind-owned", "user": {"client-certificate-data": embedded, "client-key-data": embedded}}
        ],
        "current-context": "kind-owned",
        "clusters": [
            {
                "name": "kind-owned",
                "cluster": {"server": "https://127.0.0.1:1234", "certificate-authority-data": embedded},
            }
        ],
        "contexts": [{"name": "kind-owned", "context": {"cluster": "kind-owned", "user": "kind-owned"}}],
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

    def test_tls_plugins_and_external_credentials_refused(self):
        mutations = [
            lambda c: c["clusters"][0]["cluster"].update({"insecure-skip-tls-verify": True}),
            lambda c: c["clusters"][0]["cluster"].update({"tls-server-name": "customer"}),
            lambda c: c["clusters"][0]["cluster"].update({"certificate-authority": "/customer/ca"}),
            lambda c: c["users"][0]["user"].update({"exec": {"command": "credential-plugin"}}),
            lambda c: c["users"][0]["user"].update({"auth-provider": {"name": "plugin"}}),
            lambda c: c["users"][0]["user"].update({"client-key": "/customer/key"}),
            lambda c: c["users"].append(c["users"][0]),
            lambda c: c["contexts"][0]["context"].update(user="customer"),
            lambda c: c["users"][0]["user"].update({"client-key-data": "malformed"}),
        ]
        for mutate in mutations:
            current = config()
            mutate(current)
            with self.assertRaises(DrillError):
                check_config(current, "kind-owned")

    def test_replacement_control_plane_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            node = {"Id": "original", "Config": {"Labels": {"io.x-k8s.kind.cluster": drill.cluster}}}
            with patch.object(drill, "command", return_value=json.dumps([node])):
                drill.owned_node()
            node["Id"] = "replacement"
            with patch.object(drill, "command", return_value=json.dumps([node])):
                with self.assertRaises(DrillError):
                    drill.owned_node()

    def test_sensitive_file_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private"
            private_file(path, "sensitive")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                private_file(path, "replacement")
            self.assertEqual(path.read_text(), "sensitive")

    def test_environment_cannot_override_helm_cluster_or_storage(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict(
                os.environ,
                {
                    "HELM_KUBEAPISERVER": "https://customer.example.com",
                    "HELM_KUBETOKEN": "customer-token",
                    "HELM_KUBEINSECURE_SKIP_TLS_VERIFY": "true",
                    "HELM_DRIVER": "sql",
                    "KUBECONFIG": "/customer/config",
                    "KUBERNETES_MASTER": "https://customer.example.com",
                    "HELM_DATA_HOME": "/customer/helm",
                },
            ),
        ):
            drill = Drill(Path(folder))
            self.assertFalse(any(key.startswith("HELM_KUBE") for key in drill.env))
            self.assertNotIn("KUBERNETES_MASTER", drill.env)
            self.assertEqual(drill.env["HELM_DRIVER"], "secret")
            self.assertEqual(drill.env["KUBECONFIG"], str(Path(folder) / "kubeconfig"))
            self.assertEqual(drill.env["HELM_DATA_HOME"], str(Path(folder) / "helm-data"))

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
