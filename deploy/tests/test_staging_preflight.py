"""Actual local Helm configuration contracts; no cluster, credentials or network."""

import copy
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

from deploy.staging_preflight import CHART, PreflightError, main, preflight, render, validate

SENTINEL = "private-sentinel-do-not-disclose"


def values():
    return {
        "backend": {"image": "registry.corp.test/team/backend@sha256:" + "a" * 64},
        "frontend": {"image": "registry.corp.test/team/frontend@sha256:" + "b" * 64},
        "secretName": "existing-app-secret",
        "publicUrl": "https://security.corp.test",
        "config": {
            "ZG_OIDC_ISSUER": "https://login.corp.test/tenant/v2.0",
            "ZG_OIDC_JWKS_URL": "https://keys.other.test/tenant/discovery/keys",
        },
        "ingress": {"host": "security.corp.test", "tlsSecret": "existing-tls-secret"},
    }


@unittest.skipUnless(shutil.which("helm"), "Local Helm required for actual rendering")
class PreflightTests(unittest.TestCase):
    def run_values(self, inputs):
        with tempfile.TemporaryDirectory(prefix="zerograph-staging-test-") as folder:
            path = Path(folder) / "values.yaml"
            path.write_text(yaml.safe_dump(inputs))
            return preflight(path)

    def test_actual_chart_valid_and_private_target(self):
        report = self.run_values(values())
        self.assertEqual(report["status"], "configuration_valid")
        self.assertIn("hardened_application_and_migration_pods", report["checks"])
        self.assertIn("secret_existence_contents_and_configuration_overrides", report["unchecked"])
        self.assertEqual(
            report["required_secret_keys"], ["ZG_SESSION_SECRET", "ZG_DATABASE_URL", "ZG_METRICS_TOKEN"]
        )
        serialized = json.dumps(report)
        for sensitive in ("corp.test", "existing-app-secret", "existing-tls-secret", "registry."):
            self.assertNotIn(sensitive, serialized)
        private = values()
        private["ingress"] = {"enabled": False}
        report = self.run_values(private)
        self.assertEqual(report["status"], "configuration_valid")
        self.assertIn("private_target_without_chart_ingress", report["checks"])

    def test_nondefault_https_ports_internal_dns_and_ipv6(self):
        inputs = values()
        inputs["publicUrl"] = "https://security.corp.test:8443"
        inputs["config"].update(
            {
                "ZG_OIDC_ISSUER": "https://identity:8443/tenant",
                "ZG_OIDC_JWKS_URL": "https://[fd00::1]:9443/keys",
            }
        )
        self.assertEqual(self.run_values(inputs)["status"], "configuration_valid")
        inputs["publicUrl"] = "https://[fd00::2]:8443"
        inputs["ingress"] = {"enabled": False}
        self.assertEqual(self.run_values(inputs)["status"], "configuration_valid")

    def test_auth_and_credential_configuration_fail_closed(self):
        cases = [
            ({"ZG_ENVIRONMENT": "development"}, "production_policy"),
            ({"ZG_DEMO_MODE": "true"}, "production_policy"),
            ({"ZG_COOKIE_SECURE": "false"}, "production_policy"),
            ({"ZG_GRAPH_VENDOR": "memory"}, "production_policy"),
            ({"ZG_OIDC_AUDIENCE": ""}, "oidc_configuration"),
            ({"ZG_OIDC_CLIENT_ID": ""}, "oidc_configuration"),
            ({"ZG_SESSION_SECRET": SENTINEL}, "configuration_credentials"),
            (
                {"ZG_DATABASE_URL": "postgresql+psycopg://user:" + SENTINEL + "@db/app"},
                "configuration_credentials",
            ),
            ({"ZG_REDIS_URL": "redis://cache/0?password=" + SENTINEL}, "configuration_credentials"),
        ]
        for override, failure in cases:
            with self.subTest(failure=failure, keys=list(override)):
                inputs = values()
                inputs["config"].update(override)
                report = self.run_values(inputs)
                self.assertEqual(report["failure"], failure)
                self.assertNotIn(SENTINEL, json.dumps(report))

    def test_credential_free_tls_and_jwks_query_configuration(self):
        inputs = values()
        inputs["config"]["ZG_DATABASE_URL"] = "postgresql+psycopg://app@db/app?sslmode=verify-full"
        inputs["config"]["ZG_OIDC_JWKS_URL"] += "?version=2"
        self.assertEqual(self.run_values(inputs)["status"], "configuration_valid")
        for key in ("password", "token", "api_key", "access_key", "X-Amz-Credential"):
            inputs["config"]["ZG_OIDC_JWKS_URL"] = "https://keys.other.test/keys?" + key + "=" + SENTINEL
            report = self.run_values(inputs)
            self.assertEqual(report["failure"], "configuration_credentials")
            self.assertNotIn(SENTINEL, json.dumps(report))

    def test_https_and_public_origin_contract(self):
        bad_urls = (
            "http://security.corp.test",
            "HTTPS://security.corp.test",
            "https://user:private@security.corp.test",
            "https://security.example.com",
            "https://qualification.invalid",
            "https://localhost",
            "https://security.corp.test?x=private",
            "https://security.corp.test#private",
        )
        for url in bad_urls:
            inputs = values()
            inputs["publicUrl"] = url
            self.assertEqual(self.run_values(inputs)["status"], "configuration_invalid")
        for path in ("/prefix", "/"):
            inputs = values()
            inputs["publicUrl"] += path
            self.assertEqual(self.run_values(inputs)["failure"], "public_url_path")
        for key in ("ZG_OIDC_ISSUER", "ZG_OIDC_JWKS_URL"):
            inputs = values()
            inputs["config"][key] = "http://identity.corp.test"
            self.assertEqual(self.run_values(inputs)["failure"], "https_endpoints")

    def test_ingress_images_and_secret_references(self):
        cases = [
            ("ingress", "host", "different.corp.test", "ingress_public_host"),
            ("ingress", "tlsSecret", "", "ingress_tls_reference"),
            ("backend", "image", "registry.corp.test/backend:latest", "immutable_images"),
            ("frontend", "image", "registry.corp.test/frontend@sha256:short", "immutable_images"),
        ]
        for section, key, value, failure in cases:
            inputs = values()
            inputs[section][key] = value
            self.assertEqual(self.run_values(inputs)["failure"], failure)
        inputs = values()
        inputs["secretName"] = "INVALID reference"
        self.assertEqual(self.run_values(inputs)["failure"], "secret_reference")

    def test_real_render_security_and_hook_refusals(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "values.yaml"
            path.write_text(yaml.safe_dump(values()))
            resources = render(path)
        for kind in ("Deployment", "Job"):
            for field, weakened in (
                ("readOnlyRootFilesystem", False),
                ("allowPrivilegeEscalation", True),
                ("capabilities", {"drop": []}),
                ("capabilities", {"drop": ["ALL"], "add": ["SYS_ADMIN"]}),
                ("runAsUser", 0),
                ("runAsNonRoot", False),
            ):
                changed = copy.deepcopy(resources)
                target = next(r for r in changed if r["kind"] == kind)
                target["spec"]["template"]["spec"]["containers"][0]["securityContext"][field] = weakened
                with self.assertRaisesRegex(PreflightError, "container_security"):
                    validate(changed)
            changed = copy.deepcopy(resources)
            target = next(r for r in changed if r["kind"] == kind)
            target["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
            with self.assertRaisesRegex(PreflightError, "pod_security"):
                validate(changed)
        changed = copy.deepcopy(resources)
        job = next(r for r in changed if r["kind"] == "Job")
        job["spec"]["template"]["spec"]["containers"][0]["envFrom"][1]["secretRef"]["name"] = (
            "different-secret"
        )
        with self.assertRaisesRegex(PreflightError, "existing_secret_reference"):
            validate(changed)


class InputAndRendererTests(unittest.TestCase):
    def test_malformed_oversized_and_private_cli(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "values.yaml"
            for data in (
                "[",
                "config: {key: one, key: two}",
                "config: &a {key: x}\nbackend: *a",
                "- not-a-mapping",
            ):
                path.write_text(data)
                self.assertEqual(preflight(path)["status"], "configuration_invalid")
            path.write_text("x" * 1_000_001)
            self.assertEqual(preflight(path)["failure"], "values_size")
            path.write_text("config: {ZG_SESSION_SECRET: " + SENTINEL + "}")
            stream = io.StringIO()
            with (
                redirect_stdout(stream),
                patch("deploy.staging_preflight.render", side_effect=PreflightError("helm_render")),
            ):
                self.assertEqual(main(["--values", str(path)]), 1)
            self.assertNotIn(SENTINEL, stream.getvalue())
            self.assertNotIn(str(path), stream.getvalue())
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(main(["--unknown", SENTINEL]), 1)
            self.assertNotIn(SENTINEL, stream.getvalue())

    def fake_helm(self, root, script):
        path = root / "fake-helm"
        path.write_text("#!/bin/sh\n" + script)
        path.chmod(0o700)
        return str(path)

    def test_render_failure_timeout_and_size_never_echo(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "values.yaml"
            path.write_text("{}")
            helm = self.fake_helm(root, "echo '" + SENTINEL + "' >&2\nexit 1\n")
            self.assertEqual(preflight(path, helm)["failure"], "helm_render")
            helm = self.fake_helm(root, "sleep 2\n")
            with patch("deploy.staging_preflight.RENDER_SECONDS", 0.01):
                self.assertEqual(preflight(path, helm)["failure"], "helm_timeout")
            helm = self.fake_helm(root, "printf '" + SENTINEL + "'\n")
            with patch("deploy.staging_preflight.MAX_RENDER", 5):
                report = preflight(path, helm)
                self.assertEqual(report["failure"], "helm_output_size")
                self.assertNotIn(SENTINEL, json.dumps(report))
            self.assertEqual(preflight(path, str(root / "missing"))["failure"], "helm_execution")

    def test_render_uses_private_files_and_no_ambient_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "values.yaml"
            path.write_text("{}")
            helm = self.fake_helm(root, "printf 'kind: Service\\nmetadata: {name: fixture}\\n'\n")
            real_popen = __import__("subprocess").Popen

            def guarded(command, **kwargs):
                self.assertNotIn("--debug", command)
                self.assertEqual(command[1:3], ["template", "staging-preflight"])
                self.assertEqual(command[3], str(CHART))
                self.assertEqual(
                    set(kwargs["env"]),
                    {
                        "PATH",
                        "HOME",
                        "HELM_CACHE_HOME",
                        "HELM_CONFIG_HOME",
                        "HELM_DATA_HOME",
                        "HELM_PLUGINS",
                        "KUBECONFIG",
                    },
                )
                values_path = Path(command[-1])
                self.assertEqual(values_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(values_path.parent.stat().st_mode & 0o777, 0o700)
                return real_popen(command, **kwargs)

            with (
                patch.dict(os.environ, {"HELM_DEBUG": SENTINEL, "AWS_SECRET_ACCESS_KEY": SENTINEL}),
                patch("deploy.staging_preflight.subprocess.Popen", side_effect=guarded),
            ):
                self.assertEqual(render(path, helm)[0]["kind"], "Service")


if __name__ == "__main__":
    unittest.main()
