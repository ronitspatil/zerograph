"""Render the real chart and verify deployment contracts without a cluster."""

import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parents[1] / "helm" / "zerograph"


def render(*options):
    helm = shutil.which("helm")
    if not helm:
        raise RuntimeError("helm is required for deployment validation")
    result = subprocess.run(
        [helm, "template", "release-test", str(CHART), *options],
        check=True,
        capture_output=True,
        text=True,
    )
    return [resource for resource in yaml.safe_load_all(result.stdout) if resource]


class ChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = render()
        cls.deployments = {
            resource["metadata"]["name"]: resource
            for resource in cls.resources
            if resource["kind"] == "Deployment"
        }

    def test_migration_precedes_workloads_with_hardened_container(self):
        job = next(resource for resource in self.resources if resource["kind"] == "Job")
        config = next(resource for resource in self.resources if resource["kind"] == "ConfigMap")
        annotations = job["metadata"]["annotations"]
        self.assertEqual(annotations["helm.sh/hook"], "pre-install,pre-upgrade")
        self.assertLess(
            int(config["metadata"]["annotations"]["helm.sh/hook-weight"]),
            int(annotations["helm.sh/hook-weight"]),
        )
        spec = job["spec"]["template"]["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertTrue(spec["securityContext"]["runAsNonRoot"])
        container = spec["containers"][0]
        self.assertEqual(container["command"], ["python", "-m", "app.db.migrate"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertIn("limits", container["resources"])
        self.assertEqual(container["volumeMounts"][0]["mountPath"], "/tmp")

    def test_configuration_change_rolls_all_workloads(self):
        changed = render("--set", "config.ZG_OIDC_AUDIENCE=another-api")
        updated = {
            resource["metadata"]["name"]: resource
            for resource in changed
            if resource["kind"] == "Deployment"
        }
        self.assertEqual(len(self.deployments), 4)
        for name, deployment in self.deployments.items():
            before = deployment["spec"]["template"]["metadata"]["annotations"]["checksum/config"]
            after = updated[name]["spec"]["template"]["metadata"]["annotations"]["checksum/config"]
            self.assertNotEqual(before, after)

    def test_web_probes_and_scheduler_singleton(self):
        for component in ("backend", "frontend"):
            container = self.deployments[f"release-test-{component}"]["spec"]["template"]["spec"]["containers"][0]
            self.assertIn("startupProbe", container)
            self.assertIn("readinessProbe", container)
            self.assertIn("livenessProbe", container)
        scheduler = self.deployments["release-test-scheduler"]["spec"]
        self.assertEqual(scheduler["replicas"], 1)
        self.assertEqual(scheduler["strategy"]["type"], "Recreate")

    def test_external_secrets_override_config_without_rendering_values(self):
        for deployment in self.deployments.values():
            container = deployment["spec"]["template"]["spec"]["containers"][0]
            self.assertEqual(container["envFrom"][0]["configMapRef"]["name"], "release-test-config")
            self.assertEqual(container["envFrom"][1]["secretRef"]["name"], "zerograph-secrets")
        disabled = render("--set", "ingress.enabled=false")
        self.assertFalse(any(resource["kind"] == "Ingress" for resource in disabled))


if __name__ == "__main__":
    unittest.main()
