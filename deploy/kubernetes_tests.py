"""Safety regressions: no cluster access or Docker required."""

import ast
import base64
import copy
import json
import os
import shutil
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from deploy.kubernetes import Drill, DrillError, check_config, classify_fixture_log, main, private_file, run


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

    def test_docker_bootstrap_cannot_use_remote_context_or_credentials(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict(
                os.environ,
                {
                    "DOCKER_HOST": "tcp://customer.example.com:2376",
                    "DOCKER_CONTEXT": "customer",
                    "DOCKER_CONFIG": "/customer/docker",
                    "DOCKER_CERT_PATH": "/customer/certs",
                    "DOCKER_TLS_VERIFY": "1",
                },
            ),
        ):
            drill = Drill(Path(folder))
            self.assertEqual(drill.env["DOCKER_HOST"], "unix:///var/run/docker.sock")
            self.assertEqual(drill.env["DOCKER_CONFIG"], str(Path(folder) / "docker-config"))
            self.assertFalse(
                any(key in drill.env for key in ("DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"))
            )
            config_file = Path(drill.env["DOCKER_CONFIG"]) / "config.json"
            self.assertEqual(config_file.read_text(), "{}")
            self.assertEqual(config_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config_file.parent.stat().st_mode & 0o777, 0o700)

    def test_memgraph_fixture_uses_vendor_nonroot_volume_group(self):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            with (
                patch.object(drill, "apply") as apply,
                patch.object(drill, "kubectl"),
                patch.object(drill, "get", return_value={"items": []}),
            ):
                drill.fixtures()
            resources = apply.call_args.args[0]
            graph = next(
                r for r in resources if r["kind"] == "StatefulSet" and r["metadata"]["name"] == "memgraph"
            )
            self.assertEqual(
                graph["spec"]["template"]["spec"]["securityContext"],
                {"runAsUser": 101, "runAsGroup": 103, "fsGroup": 103, "runAsNonRoot": True},
            )
            self.assertEqual(
                graph["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]["mountPath"],
                "/var/lib/memgraph",
            )
            init = graph["spec"]["template"]["spec"]["initContainers"][0]
            self.assertEqual(init["image"], "memgraph/memgraph:3.2.0")
            self.assertEqual(init["volumeMounts"], [{"name": "data", "mountPath": "/var/lib/memgraph"}])
            self.assertEqual(init["securityContext"]["capabilities"], {"drop": ["ALL"], "add": ["CHOWN"]})
            self.assertFalse(init["securityContext"]["allowPrivilegeEscalation"])
            self.assertTrue(init["securityContext"]["readOnlyRootFilesystem"])
            self.assertNotIn("-R", init["command"][-1])
            self.assertEqual(init["command"][-1].count("chown"), 1)
            self.assertIn("chown 101:103 /var/lib/memgraph", init["command"][-1])
            container = graph["spec"]["template"]["spec"]["containers"][0]
            self.assertNotIn("command", container)
            self.assertIn("--log-file=", container["args"])
            self.assertIn("--also-log-to-stderr=true", container["args"])
            self.assertFalse(any(arg.startswith("--log-file=/") for arg in container["args"]))
            self.assertEqual(len(container["volumeMounts"]), 1)

    def test_fixture_logs_export_only_bounded_boolean_categories(self):
        categories = classify_fixture_log(
            "sensitive-value Permission denied ERROR unknown command line flag Out of memory No space left on device"
        )
        self.assertEqual(
            categories, {"permission_denied": True, "invalid_flag": True, "oom": True, "no_space": True}
        )
        self.assertNotIn("sensitive-value", str(categories))
        self.assertTrue(
            classify_fixture_log(
                "The process is running as user synthetic, but the data directory is owned by user root. Please start the process as user root!"
            )["permission_denied"]
        )
        self.assertFalse(any(classify_fixture_log("x" * 10000 + " Permission denied").values()))
        self.assertFalse(
            any(classify_fixture_log("Unclassified segmentation fault sensitive-value").values())
        )

    def test_interrupted_drill_cannot_publish_passed_artifact(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            with (
                patch.dict(os.environ, {"CI": "true"}),
                patch("sys.argv", ["kubernetes.py", "--ci-disposable", "--output", str(output)]),
                patch.object(Drill, "execute", side_effect=KeyboardInterrupt),
                patch.object(Drill, "diagnostics"),
                patch.object(Drill, "cleanup"),
            ):
                with self.assertRaises(SystemExit):
                    main()
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("KeyboardInterrupt", evidence["failure"])

    @unittest.skipUnless(shutil.which("helm"), "helm required for actual render regression")
    def test_rendered_deployment_labels_are_pod_only(self):
        from deploy.tests.test_chart import render

        deployments = [item for item in render() if item["kind"] == "Deployment"]
        self.assertEqual(len(deployments), 4)
        for item in deployments:
            self.assertNotIn("app", item["metadata"].get("labels", {}))
            self.assertEqual(item["spec"]["template"]["metadata"]["labels"]["app"], "release-test")
            self.assertEqual(item["spec"]["selector"]["matchLabels"]["app"], "release-test")

    def test_runtime_uses_exact_unlabelled_deployment_metadata(self):
        components = ("backend", "frontend", "worker", "scheduler")
        deployments = {}
        pods = []
        for component in components:
            security = {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            }
            container = {"name": component, "image": "qualification:commit", "securityContext": security}
            if component in ("backend", "frontend"):
                container.update(
                    {
                        key: {"httpGet": {"path": "/health", "port": 8000}}
                        for key in ("startupProbe", "readinessProbe", "livenessProbe")
                    }
                )
            deployments[component] = {
                "metadata": {"name": "zerograph-" + component},
                "spec": {
                    "replicas": 1,
                    "strategy": {"type": "Recreate" if component == "scheduler" else "RollingUpdate"},
                    "template": {
                        "metadata": {"labels": {"app": "zerograph", "component": component}},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
                            "containers": [container],
                        },
                    },
                },
                "status": {"availableReplicas": 1},
            }
            pods.append(
                {
                    "metadata": {"labels": {"app": "zerograph", "component": component}},
                    "spec": {"containers": [container]},
                    "status": {"containerStatuses": [{"ready": True, "imageID": "sha256:proof"}]},
                }
            )

        def get(kind, *args):
            if kind == "deployment":
                self.assertEqual(len(args), 1)
                self.assertNotIn("-l", args)
                return deployments[args[0].removeprefix("zerograph-")]
            if kind == "pods":
                return {"items": pods}
            if kind == "endpoints":
                return {"subsets": [{"addresses": [{"ip": "10.0.0.1"}]}]}
            self.fail("Unexpected resource query")

        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            with (
                patch.object(drill, "get", side_effect=get),
                patch.object(drill, "kubectl"),
                patch.object(drill, "check"),
            ):
                drill.runtime()
                self.assertEqual(set(drill.results["application_images"]), set(components))
                original = copy.deepcopy(deployments["backend"])
                for key, value in (
                    ("allowPrivilegeEscalation", True),
                    ("readOnlyRootFilesystem", False),
                    ("capabilities", {"drop": []}),
                ):
                    deployments["backend"] = copy.deepcopy(original)
                    deployments["backend"]["spec"]["template"]["spec"]["containers"][0]["securityContext"][
                        key
                    ] = value
                    with self.assertRaisesRegex(DrillError, "runtime container security controls"):
                        drill.runtime()

    def test_http_contract_and_sanitized_failures(self):
        # Read the actual Counter declaration; no backend dependency install needed in kind CI.
        source = Path(__file__).resolve().parents[1] / "backend/app/core/telemetry.py"
        tree = ast.parse(source.read_text())
        names = [
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Counter"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ]
        self.assertIn("zg_http_requests_total", names)
        self.http_fixture(b"# HELP " + names[0].encode() + b" requests")
        with self.assertRaisesRegex(DrillError, "HTTP content: metrics_authorized"):
            self.http_fixture(b"zerograph_wrong_metric secret-body")
        with self.assertRaisesRegex(DrillError, "HTTP status: graph_denied"):
            self.http_fixture(b"zg_http_requests_total", denied=200)

    def http_fixture(self, metrics, denied=401):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            statuses = [
                (200, b""),
                (200, b""),
                (denied, b"private"),
                (401, b""),
                (401, b""),
                (200, metrics),
                (200, b""),
                (403, b"Demo disabled"),
            ]
            responses = []
            for status, body in statuses:
                response = Mock(status=status)
                response.read.return_value = body
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                responses.append(response)
            with (
                patch.object(drill, "forward", side_effect=lambda *a: nullcontext("http://127.0.0.1:1234")),
                patch("deploy.kubernetes.build_opener") as opener,
            ):
                opener.return_value.open.side_effect = responses
                try:
                    drill.http_checks()
                finally:
                    self.assertTrue(all(isinstance(v, int) for v in drill.results["http_statuses"].values()))
                    self.assertNotIn("private", json.dumps(drill.results))

    def test_actual_telemetry_render_contract(self):
        try:
            from app.core.telemetry import Telemetry
        except ImportError:
            self.skipTest("Backend dependencies/PYTHONPATH absent; AST contract runs independently")
        with patch("app.core.telemetry.IngestionCollector._refresh"):
            telemetry = Telemetry({"health"})
            telemetry.observe_http("health", "GET", 200, 0.01)
            self.http_fixture(telemetry.render())

    def test_restart_exact_names_and_nonvacuous_uid_proof(self):
        components = ("backend", "frontend", "worker", "scheduler")

        def pods(suffix):
            return {
                "items": [{"metadata": {"labels": {"component": c}, "uid": c + suffix}} for c in components]
            }

        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            old, new = pods("old"), pods("new")
            # A terminating previous generation must never overwrite the active baseline.
            terminating = copy.deepcopy(old["items"][0])
            terminating["metadata"]["deletionTimestamp"] = "fixture"
            terminating["metadata"]["uid"] = "obsolete"
            old["items"].append(terminating)
            with (
                patch.object(drill, "get", side_effect=[old, new]),
                patch.object(drill, "kubectl") as kubectl,
                patch.object(drill, "rollouts"),
            ):
                drill.restart_applications()
                kubectl.assert_called_once_with(
                    "rollout", "restart", *["deployment/zerograph-" + c for c in components]
                )
                self.assertEqual(set(drill.results["application_restart_components"]), set(components))
            with (
                patch.object(drill, "get", side_effect=[old, old]),
                patch.object(drill, "kubectl"),
                patch.object(drill, "rollouts"),
            ):
                with self.assertRaisesRegex(DrillError, "application restart pod UID proof"):
                    drill.restart_applications()
            for invalid in (
                {"items": []},
                {"items": new["items"][:-1]},
                {"items": new["items"] + [new["items"][0]]},
            ):
                with patch.object(drill, "get", return_value=invalid):
                    with self.assertRaisesRegex(DrillError, "application active pod inventory"):
                        drill.active_pod_ids()

    def test_uninstall_absence_is_scoped_and_strict(self):
        with tempfile.TemporaryDirectory() as folder:
            drill = Drill(Path(folder))
            expected = (
                "get",
                "deployment",
                "zerograph-backend",
                "zerograph-frontend",
                "zerograph-worker",
                "zerograph-scheduler",
                "--ignore-not-found=true",
                "-o",
                "json",
            )
            for output in ("", " \n", '{"items":[]}'):
                with patch.object(drill, "kubectl", return_value=output) as kubectl:
                    drill.verify_release_absent()
                    kubectl.assert_called_once_with(*expected)
            with patch.object(
                drill, "kubectl", return_value='{"items":[{"metadata":{"name":"zerograph-backend"}}]}'
            ):
                with self.assertRaisesRegex(DrillError, "release deployment uninstall incomplete"):
                    drill.verify_release_absent()
            for invalid in ("not JSON private-data", "{}", "[]", '{"items":null}'):
                with patch.object(drill, "kubectl", return_value=invalid):
                    with self.assertRaisesRegex(
                        DrillError, "release deployment uninstall response invalid"
                    ) as error:
                        drill.verify_release_absent()
                    self.assertNotIn("private-data", str(error.exception))
            with patch.object(drill, "kubectl", side_effect=DrillError("fixed command failure")):
                with self.assertRaisesRegex(DrillError, "fixed command failure"):
                    drill.verify_release_absent()
            with patch.object(drill, "kubectl", return_value=""):
                with self.assertRaises(json.JSONDecodeError):
                    drill.get("deployment", "zerograph-backend")

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
