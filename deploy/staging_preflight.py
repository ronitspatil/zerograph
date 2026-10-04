"""Offline configuration checks; never connects to Kubernetes or external providers."""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml

CHART = Path(__file__).resolve().parent / "helm" / "zerograph"
MAX_INPUT = 1_000_000
MAX_RENDER = 4_000_000
RENDER_SECONDS = 30
IMAGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}$")
SECRET_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
SECRET_KEYS = {
    "ZG_SESSION_SECRET",
    "ZG_METRICS_TOKEN",
    "ZG_DEMO_TOKEN",
    "ZG_GRAPH_PASSWORD",
    "ZG_GIT_TOKEN",
    "ZG_AWS_EXTERNAL_ID",
    "ZG_OIDC_CLIENT_SECRET",
}
UNCHECKED = [
    "secret_existence_contents_and_configuration_overrides",
    "registry_digest_availability",
    "dns_routing_tls_certificates_and_ingress_controller",
    "oidc_discovery_signatures_and_claims",
    "database_graph_redis_authentication_and_connectivity",
    "target_cluster_storage_and_capacity",
    "release_install_upgrade_backup_restore_and_load",
]


class PreflightError(Exception):
    """Only fixed labels may be emitted; untrusted inputs are never included."""


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    keys = [loader.construct_object(key) for key, _ in node.value]
    if any(not isinstance(key, str) for key in keys) or len(keys) != len(set(keys)):
        raise PreflightError("yaml_mapping")
    return loader.construct_mapping(node)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def parse_yaml(text, *, documents=False):
    # Bound aliases and syntax depth before construction to avoid adversarial object graphs.
    try:
        depth = 0
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
                raise PreflightError("yaml_aliases")
            if isinstance(
                token,
                (
                    yaml.tokens.BlockMappingStartToken,
                    yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowMappingStartToken,
                    yaml.tokens.FlowSequenceStartToken,
                ),
            ):
                depth += 1
                if depth > 32:
                    raise PreflightError("yaml_depth")
            if isinstance(
                token,
                (
                    yaml.tokens.BlockEndToken,
                    yaml.tokens.FlowMappingEndToken,
                    yaml.tokens.FlowSequenceEndToken,
                ),
            ):
                depth -= 1
        return (
            list(yaml.load_all(text, Loader=UniqueLoader))
            if documents
            else yaml.load(text, Loader=UniqueLoader)
        )
    except PreflightError:
        raise
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise PreflightError("yaml_parse") from None


def render(values_file, helm=None):
    try:
        with Path(values_file).open("rb") as source:
            data = source.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise PreflightError("values_size")
        values = parse_yaml(data.decode("utf-8"))
        if not isinstance(values, dict):
            raise PreflightError("values_mapping")
    except PreflightError:
        raise
    except (OSError, UnicodeError):
        raise PreflightError("values_read") from None
    executable = helm or shutil.which("helm")
    if not executable:
        raise PreflightError("helm_missing")
    with tempfile.TemporaryDirectory(prefix="zerograph-staging-preflight-") as folder:
        root = Path(folder)
        os.chmod(root, 0o700)
        private_values = root / "values.yaml"
        private_values.touch(mode=0o600)
        private_values.write_text(yaml.safe_dump(values))
        env = {
            "PATH": os.defpath,
            "HOME": folder,
            "HELM_CACHE_HOME": str(root / "cache"),
            "HELM_CONFIG_HOME": str(root / "config"),
            "HELM_DATA_HOME": str(root / "data"),
            "HELM_PLUGINS": str(root / "plugins"),
            "KUBECONFIG": str(root / "no-kubeconfig"),
        }
        paths = [root / "stdout", root / "stderr"]
        for path in paths:
            path.touch(mode=0o600)
        try:
            with paths[0].open("wb") as output, paths[1].open("wb") as errors:
                process = subprocess.Popen(
                    [
                        str(executable),
                        "template",
                        "staging-preflight",
                        str(CHART),
                        "--values",
                        str(private_values),
                    ],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=errors,
                )
                try:
                    deadline = time.monotonic() + RENDER_SECONDS
                    while True:
                        if any(path.stat().st_size > MAX_RENDER for path in paths):
                            raise PreflightError("helm_output_size")
                        if process.poll() is not None:
                            break
                        if time.monotonic() >= deadline:
                            raise PreflightError("helm_timeout")
                        time.sleep(0.02)
                    if process.returncode:
                        raise PreflightError("helm_render")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
            if any(path.stat().st_size > MAX_RENDER for path in paths):
                raise PreflightError("helm_output_size")
            resources = parse_yaml(paths[0].read_text(), documents=True)
            if not resources or any(not isinstance(item, dict) for item in resources):
                raise PreflightError("rendered_resources")
            return resources
        except PreflightError:
            raise
        except (OSError, UnicodeError, subprocess.SubprocessError):
            raise PreflightError("helm_execution") from None


def require(condition, label):
    if not condition:
        raise PreflightError(label)


def credential_query(query):
    for key, _ in parse_qsl(query, keep_blank_values=True):
        normalized = key.lower().replace("-", "_")
        if any(
            word in normalized for word in ("password", "secret", "token", "credential", "signature")
        ) or normalized in {"pwd", "pass", "api_key", "apikey", "access_key", "accesskey"}:
            return True
    return False


def https_url(value, *, allow_query=False):
    require(
        isinstance(value, str) and value.startswith("https://") and not any(c.isspace() for c in value),
        "https_endpoints",
    )
    try:
        url = urlsplit(value)
        host = url.hostname
        require(
            url.scheme == "https"
            and host
            and not url.username
            and not url.password
            and not url.fragment
            and (not url.query or (allow_query and not credential_query(url.query)))
            and (url.port is None or 1 <= url.port <= 65535),
            "https_endpoints",
        )
        require(
            host != "localhost"
            and not host.endswith((".invalid", ".example.com", ".example.org", ".example.net"))
            and host not in {"example.com", "example.org", "example.net"},
            "endpoint_placeholders",
        )
        return url
    except ValueError:
        raise PreflightError("https_endpoints") from None


def validate(resources):
    try:
        return _validate(resources)
    except PreflightError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        raise PreflightError("rendered_contract") from None


def _validate(resources):
    checks = []
    configs = [r for r in resources if r.get("kind") == "ConfigMap"]
    require(len(configs) == 1, "configuration_inventory")
    config = configs[0]["data"]
    require(
        config.get("ZG_ENVIRONMENT") == "production"
        and config.get("ZG_DEMO_MODE") == "false"
        and config.get("ZG_COOKIE_SECURE") == "true"
        and config.get("ZG_GRAPH_VENDOR") in {"memgraph", "neo4j"},
        "production_policy",
    )
    require(all(isinstance(k, str) and isinstance(v, str) for k, v in config.items()), "configuration_types")
    require(
        not any(
            k in SECRET_KEYS
            or any(word in k.upper() for word in ("PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY"))
            for k in config
        ),
        "configuration_credentials",
    )
    for value in config.values():
        if "://" in value:
            try:
                url = urlsplit(value)
                require(
                    not url.password and not credential_query(url.query) and not url.fragment,
                    "configuration_credentials",
                )
            except ValueError:
                raise PreflightError("configuration_credentials") from None
    checks.append("production_policy_and_configmap_credentials")
    public = https_url(config["ZG_PUBLIC_URL"])
    require(public.path == "", "public_url_path")
    https_url(config["ZG_OIDC_ISSUER"])
    https_url(config["ZG_OIDC_JWKS_URL"], allow_query=True)
    require(
        all(
            config.get(key, "").strip()
            for key in ("ZG_OIDC_CLIENT_ID", "ZG_OIDC_AUDIENCE", "ZG_TENANT_CLAIM", "ZG_ROLE_CLAIM")
        ),
        "oidc_configuration",
    )
    checks.append("https_public_and_oidc_configuration")
    ingress = [r for r in resources if r.get("kind") == "Ingress"]
    require(len(ingress) <= 1, "ingress_inventory")
    if ingress:
        spec = ingress[0]["spec"]
        require(
            spec.get("ingressClassName")
            and len(spec["rules"]) == 1
            and spec["rules"][0]["host"] == public.hostname,
            "ingress_public_host",
        )
        require(
            len(spec["tls"]) == 1
            and spec["tls"][0]["hosts"] == [public.hostname]
            and isinstance(spec["tls"][0].get("secretName"), str)
            and len(spec["tls"][0]["secretName"]) <= 253
            and SECRET_NAME.fullmatch(spec["tls"][0]["secretName"]),
            "ingress_tls_reference",
        )
        checks.append("ingress_host_and_tls_reference")
    else:
        checks.append("private_target_without_chart_ingress")
    deployments = [r for r in resources if r.get("kind") == "Deployment"]
    jobs = [r for r in resources if r.get("kind") == "Job"]
    require(len(deployments) == 4 and len(jobs) == 1, "workload_inventory")
    require(
        {r["metadata"]["name"] for r in deployments}
        == {"staging-preflight-" + c for c in ("backend", "frontend", "worker", "scheduler")},
        "workload_inventory",
    )
    secret_names = set()
    images = {}
    for resource in deployments + jobs:
        pod = resource["spec"]["template"]["spec"]
        require(
            pod.get("automountServiceAccountToken") is False
            and pod["securityContext"].get("runAsNonRoot") is True
            and isinstance(pod["securityContext"].get("runAsUser"), int)
            and pod["securityContext"]["runAsUser"] > 0,
            "pod_security",
        )
        require(len(pod["containers"]) == 1 and not pod.get("initContainers"), "container_inventory")
        container = pod["containers"][0]
        security = container["securityContext"]
        require(
            security.get("allowPrivilegeEscalation") is False
            and security.get("readOnlyRootFilesystem") is True
            and security.get("capabilities", {}).get("drop") == ["ALL"]
            and not security.get("capabilities", {}).get("add")
            and security.get("runAsNonRoot", pod["securityContext"]["runAsNonRoot"]) is True
            and type(security.get("runAsUser", pod["securityContext"]["runAsUser"])) is int
            and security.get("runAsUser", pod["securityContext"]["runAsUser"]) > 0
            and not security.get("privileged", False),
            "container_security",
        )
        require(IMAGE.fullmatch(container["image"]), "immutable_images")
        images[container["name"]] = container["image"]
        require(
            container.get("envFrom") and len(container["envFrom"]) == 2 and not container.get("env"),
            "secret_environment",
        )
        require(
            container["envFrom"][0] == {"configMapRef": {"name": configs[0]["metadata"]["name"]}},
            "configmap_reference",
        )
        reference = container["envFrom"][1]
        require(
            set(reference) == {"secretRef"} and set(reference["secretRef"]) == {"name"}, "secret_reference"
        )
        name = reference["secretRef"]["name"]
        require(
            isinstance(name, str) and len(name) <= 253 and SECRET_NAME.fullmatch(name), "secret_reference"
        )
        secret_names.add(name)
    require(
        len(secret_names) == 1 and not any(r.get("kind") == "Secret" for r in resources),
        "existing_secret_reference",
    )
    require(
        images["backend"] == images["worker"] == images["scheduler"] == images["migrate"],
        "backend_image_coherence",
    )
    checks.extend(
        [
            "immutable_application_and_migration_images",
            "hardened_application_and_migration_pods",
            "existing_secret_references",
        ]
    )
    return {
        "status": "configuration_valid",
        "checks": checks,
        "required_secret_keys": ["ZG_SESSION_SECRET", "ZG_DATABASE_URL", "ZG_METRICS_TOKEN"],
        "conditional_secret_keys": {
            "graph_authentication": ["ZG_GRAPH_PASSWORD"],
            "redis_authentication": ["ZG_REDIS_URL"],
            "confidential_oidc_client": ["ZG_OIDC_CLIENT_SECRET"],
            "gitops_enabled": ["ZG_GIT_TOKEN"],
            "aws_external_id_required": ["ZG_AWS_EXTERNAL_ID"],
        },
        "unchecked": UNCHECKED,
    }


def preflight(values_file, helm=None):
    try:
        return validate(render(values_file, helm))
    except PreflightError as error:
        return {"status": "configuration_invalid", "failure": str(error), "unchecked": UNCHECKED}


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise PreflightError("arguments")


def main(argv=None):
    parser = PrivateParser(description=__doc__)
    parser.add_argument("--values", required=True)
    try:
        args = parser.parse_args(argv)
        report = preflight(args.values)
    except PreflightError:
        report = {"status": "configuration_invalid", "failure": "arguments", "unchecked": UNCHECKED}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "configuration_valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
