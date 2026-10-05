"""Qualify the real Helm chart on an exclusively owned disposable CI kind cluster."""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import json
import os
import secrets
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

import yaml

ROOT = Path(__file__).resolve().parents[1]
NODE_IMAGE = "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"


class DrillError(RuntimeError):
    pass


def run(args, *, env, label, data=None, timeout=600):
    try:
        result = subprocess.run(args, env=env, input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise DrillError(f"{label}: command unavailable or timed out") from None
    if result.returncode:
        # Arguments, captured outputs and environment can contain credentials.
        raise DrillError(f"{label}: exit {result.returncode}")
    return result.stdout


def private_file(path, content):
    with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
        file.write(content)


def check_config(config, context, server=None):
    if not isinstance(config, dict) or set(config) - {
        "apiVersion",
        "kind",
        "preferences",
        "clusters",
        "contexts",
        "current-context",
        "users",
    }:
        raise DrillError("Refusing unexpected kubeconfig fields")
    if (
        config.get("apiVersion") != "v1"
        or config.get("kind") != "Config"
        or config.get("preferences") not in (None, {})
    ):
        raise DrillError("Refusing unexpected kubeconfig format")
    if config.get("current-context") != context or len(config.get("contexts", [])) != 1:
        raise DrillError("Refusing unexpected kubeconfig context")
    entries = config.get("clusters", [])
    if len(entries) != 1 or set(entries[0]) != {"name", "cluster"} or entries[0]["name"] != context:
        raise DrillError("Refusing unexpected kubeconfig cluster")
    cluster = entries[0]["cluster"]
    if set(cluster) != {"server", "certificate-authority-data"}:
        raise DrillError("Refusing TLS overrides or external CA references")
    target = cluster["server"]
    parsed = urlparse(target)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise DrillError("Refusing non-loopback Kubernetes endpoint")
    if server is not None and server != target:
        raise DrillError("Refusing changed Kubernetes endpoint")
    entry = config["contexts"][0]
    if (
        set(entry) != {"name", "context"}
        or entry["name"] != context
        or entry["context"] != {"cluster": context, "user": context}
    ):
        raise DrillError("Refusing context/cluster/user mismatch")
    users = config.get("users", [])
    if len(users) != 1 or set(users[0]) != {"name", "user"} or users[0]["name"] != context:
        raise DrillError("Refusing ambiguous Kubernetes user")
    user = users[0]["user"]
    if set(user) != {"client-certificate-data", "client-key-data"}:
        raise DrillError("Refusing plugins or external credential references")
    for value in (
        cluster["certificate-authority-data"],
        user["client-certificate-data"],
        user["client-key-data"],
    ):
        if not isinstance(value, str) or not value or len(value) > 65536:
            raise DrillError("Refusing unbounded embedded credentials")
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError:
            raise DrillError("Refusing malformed embedded credentials") from None
        if not decoded.startswith(b"-----BEGIN ") or b"-----END " not in decoded:
            raise DrillError("Refusing malformed embedded credentials")
    return target


def classify_fixture_log(output):
    """Return fixed categories only; never retain or emit raw fixture log text."""
    bounded = output[:10000].lower()
    return {
        "permission_denied": "permission denied" in bounded
        or all(
            term in bounded for term in ("process is running as user", "data directory is", "owned by user")
        ),
        "invalid_flag": any(
            term in bounded
            for term in (
                "unknown command line flag",
                "unrecognized option",
                "unknown option",
                "invalid value for flag",
            )
        ),
        "oom": any(term in bounded for term in ("out of memory", "bad_alloc", "cannot allocate memory")),
        "no_space": "no space left on device" in bounded,
    }


class Drill:
    def __init__(self, folder):
        self.folder = folder
        self.cluster = "zerograph-kubernetes-qualification-" + uuid.uuid4().hex[:12]
        self.context = "kind-" + self.cluster
        self.namespace = "qualification"
        self.kubeconfig = folder / "kubeconfig"
        self.server = None
        self.node_id = None
        self.config_digest = None
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("HELM_KUBE", "DOCKER_")) and key != "KUBERNETES_MASTER"
        }
        docker_config = folder / "docker-config"
        docker_config.mkdir(mode=0o700)
        private_file(docker_config / "config.json", "{}")
        self.env.update(
            {
                "KUBECONFIG": str(self.kubeconfig),
                "KIND_EXPERIMENTAL_PROVIDER": "docker",
                "HELM_DRIVER": "secret",
                "DOCKER_HOST": "unix:///var/run/docker.sock",
                "DOCKER_CONFIG": str(docker_config),
                "HELM_CONFIG_HOME": str(folder / "helm-config"),
                "HELM_CACHE_HOME": str(folder / "helm-cache"),
                "HELM_DATA_HOME": str(folder / "helm-data"),
            }
        )
        self.results = {"checks": [], "cluster": self.cluster, "node_image": NODE_IMAGE}
        self.metrics_token = secrets.token_hex(32)
        self.password = secrets.token_hex(24)
        self.created = False
        self.stage = "initialization"

    def command(self, args, label, **kwargs):
        return run(args, env=self.env, label=label, **kwargs)

    def owned_node(self):
        result = json.loads(
            self.command(
                ["docker", "inspect", self.cluster + "-control-plane"], "verify node ownership", timeout=30
            )
        )
        if len(result) != 1 or result[0]["Config"]["Labels"].get("io.x-k8s.kind.cluster") != self.cluster:
            raise DrillError("Refusing node ownership mismatch")
        node_id = result[0]["Id"]
        if self.node_id is not None and node_id != self.node_id:
            raise DrillError("Refusing replaced control-plane container")
        self.node_id = node_id

    def guard(self):
        if (
            not self.created
            or self.kubeconfig.is_symlink()
            or stat.S_IMODE(self.kubeconfig.stat().st_mode) != 0o600
        ):
            raise DrillError("Refusing unowned or non-private kubeconfig")
        self.owned_node()
        config = yaml.safe_load(self.kubeconfig.read_text())
        self.server = check_config(config, self.context, self.server)
        digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        if self.config_digest is not None and digest != self.config_digest:
            raise DrillError("Refusing changed owned kubeconfig")
        self.config_digest = digest

    def kubectl(self, *args, **kwargs):
        self.guard()
        return self.command(
            [
                "kubectl",
                "--kubeconfig",
                str(self.kubeconfig),
                "--context",
                self.context,
                "--namespace",
                self.namespace,
                *args,
            ],
            "kubectl " + args[0],
            **kwargs,
        )

    def helm(self, *args, **kwargs):
        self.guard()
        return self.command(
            [
                "helm",
                *args,
                "--kubeconfig",
                str(self.kubeconfig),
                "--kube-context",
                self.context,
                "--namespace",
                self.namespace,
            ],
            "helm " + args[0],
            **kwargs,
        )

    def get(self, kind, *args):
        return json.loads(self.kubectl("get", kind, *args, "-o", "json"))

    def apply(self, resources):
        self.kubectl(
            "apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": resources})
        )

    def check(self, name):
        self.results["checks"].append(name)
        print(f"PASS {name}", flush=True)

    def fixtures(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "zerograph-secrets"},
            "stringData": {
                "ZG_DATABASE_URL": f"postgresql+psycopg://zerograph:{self.password}@postgres:5432/zerograph",
                "ZG_METRICS_TOKEN": self.metrics_token,
                "ZG_SESSION_SECRET": secrets.token_hex(32),
                "POSTGRES_PASSWORD": self.password,
            },
        }
        resources = [secret]
        definitions = [
            (
                "postgres",
                "postgres:16-alpine",
                5432,
                "/var/lib/postgresql/data",
                None,
                [
                    {"name": "POSTGRES_DB", "value": "zerograph"},
                    {"name": "POSTGRES_USER", "value": "zerograph"},
                    {
                        "name": "POSTGRES_PASSWORD",
                        "valueFrom": {
                            "secretKeyRef": {"name": "zerograph-secrets", "key": "POSTGRES_PASSWORD"}
                        },
                    },
                    {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
                ],
            ),
            (
                "redis",
                "redis:7.4-alpine",
                6379,
                "/data",
                ["redis-server", "--appendonly", "yes", "--appendfsync", "always"],
                [],
            ),
            (
                "memgraph",
                "memgraph/memgraph:3.2.0",
                7687,
                "/var/lib/memgraph",
                [
                    "--data-directory=/var/lib/memgraph",
                    # No log PVC: follow vendor chart and use stdout only.
                    "--log-file=",
                    "--also-log-to-stderr=true",
                    "--storage-snapshot-interval-sec=5",
                    "--storage-wal-enabled=true",
                    "--data-recovery-on-startup=true",
                ],
                [],
            ),
        ]
        for name, image, port, mount, command, env in definitions:
            resources.append(
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": name},
                    "spec": {"selector": {"fixture": name}, "ports": [{"port": port, "targetPort": port}]},
                }
            )
            container = {
                "name": name,
                "image": image,
                "env": env,
                "ports": [{"containerPort": port}],
                "readinessProbe": {"tcpSocket": {"port": port}, "periodSeconds": 3},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "1", "memory": "768Mi"},
                },
                "volumeMounts": [{"name": "data", "mountPath": mount}],
            }
            if command:
                container["args" if name == "memgraph" else "command"] = command
            resources.append(
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": name},
                    "spec": {
                        "serviceName": name,
                        "replicas": 1,
                        "selector": {"matchLabels": {"fixture": name}},
                        "template": {
                            "metadata": {"labels": {"fixture": name}},
                            "spec": {
                                "containers": [container],
                                **(
                                    {
                                        # Memgraph3.2 requires directory UID ownership, not only fsGroup access.
                                        "initContainers": [
                                            {
                                                "name": "prepare-owned-storage",
                                                "image": image,
                                                "command": [
                                                    "/bin/sh",
                                                    "-ec",
                                                    "chown 101:103 /var/lib/memgraph; test $(stat -c %u /var/lib/memgraph) = 101",
                                                ],
                                                "securityContext": {
                                                    "runAsUser": 0,
                                                    "runAsGroup": 0,
                                                    "runAsNonRoot": False,
                                                    "allowPrivilegeEscalation": False,
                                                    "readOnlyRootFilesystem": True,
                                                    "capabilities": {"drop": ["ALL"], "add": ["CHOWN"]},
                                                },
                                                "volumeMounts": [
                                                    {"name": "data", "mountPath": "/var/lib/memgraph"}
                                                ],
                                            }
                                        ],
                                        "securityContext": {
                                            "runAsUser": 101,
                                            "runAsGroup": 103,
                                            "fsGroup": 103,
                                            "runAsNonRoot": True,
                                        },
                                    }
                                    if name == "memgraph"
                                    else {}
                                ),
                            },
                        },
                        "volumeClaimTemplates": [
                            {
                                "metadata": {"name": "data"},
                                "spec": {
                                    "accessModes": ["ReadWriteOnce"],
                                    "resources": {"requests": {"storage": "1Gi"}},
                                },
                            }
                        ],
                    },
                }
            )
        self.apply(resources)
        for name, *_ in definitions:
            self.kubectl("rollout", "status", "statefulset/" + name, "--timeout=240s", timeout=270)
        assert all(pvc["status"]["phase"] == "Bound" for pvc in self.get("pvc")["items"])
        self.check("durable fixture PVCs bound")

    def rollouts(self):
        for component in ("backend", "frontend", "worker", "scheduler"):
            self.kubectl(
                "rollout", "status", "deployment/zerograph-" + component, "--timeout=240s", timeout=270
            )

    def release_proof(self, revision):
        record = self.get("secret", f"sh.helm.release.v1.zerograph.v{revision}")
        decoded = gzip.decompress(base64.b64decode(base64.b64decode(record["data"]["release"])))
        release = json.loads(decoded)
        hooks = [hook for hook in release["hooks"] if hook["name"] == "zerograph-migrate"]
        assert len(hooks) == 1 and hooks[0]["last_run"]["phase"] == "Succeeded"
        assert release["info"]["status"] == "deployed" and release["version"] == revision
        self.results[f"migration_hook_v{revision}"] = {
            "phase": "Succeeded",
            "started_at": hooks[0]["last_run"]["started_at"],
        }
        self.check(f"release {revision} migration hook succeeded")

    def runtime(self):
        def require(condition, label):
            if not condition:
                raise DrillError(label)

        components = ("backend", "frontend", "worker", "scheduler")
        # Labels exist on pod templates/selectors, not Deployment metadata.
        deployments = [self.get("deployment", "zerograph-" + component) for component in components]
        require(len(deployments) == 4, "runtime deployment inventory")
        for component, deployment in zip(components, deployments, strict=True):
            require(deployment["metadata"]["name"] == "zerograph-" + component, "runtime deployment identity")
            template = deployment["spec"]["template"]
            spec = template["spec"]
            require(spec["automountServiceAccountToken"] is False, "runtime service account token disabled")
            require(spec["securityContext"]["runAsNonRoot"] is True, "runtime nonroot required")
            require(spec["securityContext"]["runAsUser"] == 10001, "runtime user identity")
            container = spec["containers"][0]
            require(
                container["securityContext"]
                == {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "runtime container security controls",
            )
            if component in ("backend", "frontend"):
                require(
                    all(key in container for key in ("startupProbe", "readinessProbe", "livenessProbe")),
                    "runtime web probes",
                )
            require(deployment["status"].get("availableReplicas") == 1, "runtime deployment availability")
        scheduler = deployments[3]
        require(
            scheduler["spec"]["replicas"] == 1 and scheduler["spec"]["strategy"]["type"] == "Recreate",
            "runtime singleton scheduler strategy",
        )
        pods = self.get("pods", "-l", "app=zerograph")["items"]
        ready = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
        require(
            len(ready) == 4 and all(all(c["ready"] for c in p["status"]["containerStatuses"]) for p in ready),
            "runtime application pods ready",
        )
        require(
            {p["metadata"]["labels"]["component"] for p in ready} == set(components),
            "runtime application pod identity",
        )
        self.results["application_images"] = {
            p["metadata"]["labels"]["component"]: {
                "tag": p["spec"]["containers"][0]["image"],
                "image_id": p["status"]["containerStatuses"][0]["imageID"],
            }
            for p in ready
        }
        for component in ("backend", "frontend"):
            endpoint = self.get("endpoints", "zerograph-" + component)
            require(
                endpoint.get("subsets") and endpoint["subsets"][0].get("addresses"),
                "runtime service endpoints ready",
            )
        self.kubectl(
            "exec",
            "deployment/zerograph-frontend",
            "--",
            "node",
            "-e",
            "if(process.getuid()!==10001)process.exit(1);try{require('fs').writeFileSync('/app/qualification-proof','x');process.exit(1)}catch(e){if(!['EROFS','EACCES'].includes(e.code))process.exit(1)}",
        )
        self.check("ready services, hardened containers, probes and singleton scheduler")

    @contextlib.contextmanager
    def forward(self, service, remote):
        self.guard()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [
                "kubectl",
                "--kubeconfig",
                str(self.kubeconfig),
                "--context",
                self.context,
                "--namespace",
                self.namespace,
                "port-forward",
                "--address=127.0.0.1",
                "service/" + service,
                f"{port}:{remote}",
            ],
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise DrillError("Loopback port-forward exited")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise DrillError("Loopback port-forward timed out")
            yield f"http://127.0.0.1:{port}"
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def http_checks(self):
        def request(base, path, token=None, method="GET", extra_headers=None):
            headers = {"Authorization": "Bearer " + token} if token else {}
            headers.update(extra_headers or {})
            try:
                with build_opener(ProxyHandler({})).open(
                    Request(base + path, headers=headers, method=method), timeout=10
                ) as response:
                    return response.status, response.read(100_000)
            except HTTPError as error:
                return error.code, error.read(100_000)
            except URLError:
                raise DrillError("Loopback HTTP probe failed") from None

        def expect(label, expected, result, content=None):
            status, body = result
            # Only fixed keys and numeric HTTP outcomes reach the evidence artifact.
            self.results.setdefault("http_statuses", {})[label] = (
                status if isinstance(status, int) and 100 <= status <= 599 else 0
            )
            if status != expected:
                raise DrillError("HTTP status: " + label)
            if content is not None and content not in body:
                raise DrillError("HTTP content: " + label)

        with self.forward("zerograph-backend", 8000) as base:
            expect("live", 200, request(base, "/health/live"))
            expect("ready", 200, request(base, "/health/ready"))
            expect("graph_denied", 401, request(base, "/api/v1/graph"))
            expect("metrics_denied", 401, request(base, "/metrics"))
            expect("metrics_invalid", 401, request(base, "/metrics", "incorrect-fixture-token"))
            expect(
                "metrics_authorized",
                200,
                request(base, "/metrics", self.metrics_token),
                b"zg_http_requests_total",
            )
        with self.forward("zerograph-frontend", 3100) as base:
            expect("login", 200, request(base, "/login"))
            status, body = request(
                base,
                "/api/auth/demo",
                method="POST",
                extra_headers={"Origin": "https://qualification.invalid"},
            )
            expect("demo_disabled", 403, (status, body), b"Demo disabled")
        self.check("production API denial, protected metrics and web readiness")

    def active_pod_ids(self):
        ids = {}
        components = {"backend", "frontend", "worker", "scheduler"}
        for pod in self.get("pods", "-l", "app=zerograph")["items"]:
            metadata = pod["metadata"]
            if metadata.get("deletionTimestamp"):
                continue
            component = metadata.get("labels", {}).get("component")
            uid = metadata.get("uid")
            if component not in components or component in ids or not uid:
                raise DrillError("application active pod inventory")
            ids[component] = uid
        if set(ids) != components:
            raise DrillError("application active pod inventory")
        return ids

    def changed_pods(self, before, label):
        after = self.active_pod_ids()
        if set(before) != set(after) or any(before[c] == after[c] for c in before):
            raise DrillError(label)

    def restart_applications(self):
        before = self.active_pod_ids()
        self.kubectl(
            "rollout",
            "restart",
            *[
                "deployment/zerograph-" + component
                for component in ("backend", "frontend", "worker", "scheduler")
            ],
        )
        self.rollouts()
        self.changed_pods(before, "application restart pod UID proof")
        self.results["application_restart_components"] = sorted(before)

    def seed(self, mode):
        script = (ROOT / "deploy/kubernetes_seed.py").read_text()
        result = self.kubectl(
            "exec", "-i", "deployment/zerograph-backend", "--", "python", "-", mode, data=script
        )
        proof = json.loads(result)
        assert proof == {"migration_head": "0004", "revision": "kubernetes-proof-v1", "nodes": 2, "edges": 1}
        self.results["persistence_proof"] = proof

    def execute(self):
        self.stage = "create owned cluster"
        clusters = self.command(["kind", "get", "clusters"], "inventory owned name", timeout=30).splitlines()
        if self.cluster in clusters or self.kubeconfig.exists():
            raise DrillError("Refusing existing cluster or kubeconfig")
        private_file(self.kubeconfig, "")
        # Mark intent before create so partial node creation is checked/cleaned in finally.
        self.created = True
        self.command(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                self.cluster,
                "--kubeconfig",
                str(self.kubeconfig),
                "--image",
                NODE_IMAGE,
                "--wait",
                "120s",
            ],
            "create disposable kind",
            timeout=300,
        )
        self.guard()
        self.results["commit"] = self.command(
            ["git", "rev-parse", "HEAD"], "release commit", timeout=10
        ).strip()
        self.results["task_head"] = os.environ.get("ZG_KUBE_SOURCE_HEAD", self.results["commit"])
        self.results["kubernetes_version"] = json.loads(self.kubectl("get", "--raw=/version"))["gitVersion"]
        self.kubectl("create", "namespace", self.namespace)
        self.stage = "build application images"
        images = {}
        for component in ("backend", "frontend"):
            image = f"zerograph-qualification-{component}:{self.results['commit'][:12]}"
            self.command(
                ["docker", "build", "--tag", image, str(ROOT / component)], "build " + component, timeout=600
            )
            self.command(
                ["kind", "load", "docker-image", image, "--name", self.cluster],
                "load " + component,
                timeout=180,
            )
            images[component] = image
        self.stage = "provision stores and install"
        self.fixtures()
        values = {
            "backend": {"image": images["backend"], "replicas": 1},
            "frontend": {"image": images["frontend"], "replicas": 1},
            "worker": {"replicas": 1},
            "ingress": {"enabled": False},
            "publicUrl": "https://qualification.invalid",
            "config": {
                "ZG_OIDC_ISSUER": "https://unreachable-issuer.invalid",
                "ZG_OIDC_JWKS_URL": "https://unreachable-issuer.invalid/jwks",
                "ZG_QUERY_TIMEOUT_SECONDS": "15",
            },
            "resources": {
                "requests": {"cpu": "50m", "memory": "96Mi"},
                "limits": {"cpu": "1", "memory": "768Mi"},
            },
        }
        values_file = self.folder / "values.yaml"
        private_file(values_file, yaml.safe_dump(values))
        self.helm(
            "install",
            "zerograph",
            str(ROOT / "deploy/helm/zerograph"),
            "-f",
            str(values_file),
            "--wait",
            "--wait-for-jobs",
            "--timeout",
            "300s",
            timeout=360,
        )
        self.rollouts()
        self.release_proof(1)
        self.runtime()
        self.http_checks()
        self.seed("seed")
        self.check("fresh migration head and coherent synthetic SQL/graph seed")
        self.stage = "upgrade configuration"
        before = self.active_pod_ids()
        self.helm(
            "upgrade",
            "zerograph",
            str(ROOT / "deploy/helm/zerograph"),
            "-f",
            str(values_file),
            "--set",
            "config.ZG_QUERY_TIMEOUT_SECONDS=16",
            "--wait",
            "--wait-for-jobs",
            "--timeout",
            "300s",
            timeout=360,
        )
        self.rollouts()
        self.release_proof(2)
        assert (
            self.results["migration_hook_v1"]["started_at"] != self.results["migration_hook_v2"]["started_at"]
        )
        self.changed_pods(before, "configuration rollout pod UID proof")
        self.seed("verify")
        self.check("upgrade migration and ConfigMap rollout preserve revision")
        self.stage = "restart persistent fixture pods and application"
        self.kubectl(
            "delete",
            "pods",
            "postgres-0",
            "redis-0",
            "memgraph-0",
            "--wait=true",
            "--timeout=90s",
            timeout=120,
        )
        for name in ("postgres", "redis", "memgraph"):
            self.kubectl("rollout", "status", "statefulset/" + name, "--timeout=240s", timeout=270)
        self.restart_applications()
        self.seed("verify")
        self.runtime()
        self.http_checks()
        self.check("PVC-backed store and application pod restart retain SQL/graph coherence")
        self.stage = "uninstall release"
        self.helm("uninstall", "zerograph", "--wait", "--timeout", "120s", timeout=150)
        self.verify_release_absent()
        # Helm hooks are not ordinary release-managed resources; explicitly delete only owned hook ConfigMap.
        self.kubectl("delete", "configmap", "zerograph-config", "--ignore-not-found=true")
        self.kubectl("delete", "namespace", self.namespace, "--wait=true", "--timeout=120s", timeout=150)
        self.check("release uninstall and owned namespace removal")

    def verify_release_absent(self):
        # Successful kubectl returns no JSON when every explicitly requested name is absent.
        # This exception is restricted to uninstall; ordinary get() remains strict.
        output = self.kubectl(
            "get",
            "deployment",
            *["zerograph-" + component for component in ("backend", "frontend", "worker", "scheduler")],
            "--ignore-not-found=true",
            "-o",
            "json",
        )
        if not output.strip():
            return
        try:
            remaining = json.loads(output)
        except (ValueError, TypeError):
            raise DrillError("release deployment uninstall response invalid") from None
        if not isinstance(remaining, dict) or not isinstance(remaining.get("items"), list):
            raise DrillError("release deployment uninstall response invalid")
        if remaining["items"]:
            raise DrillError("release deployment uninstall incomplete")

    def diagnostics(self):
        try:
            output = self.kubectl(
                "logs", "memgraph-0", "--previous", "--tail=80", "--limit-bytes=10000", timeout=15
            )
            self.results["memgraph_failure_categories"] = classify_fixture_log(output)
            del output
        except Exception:
            self.results["memgraph_failure_categories"] = "unavailable"
        try:
            pods = self.get("pods")["items"]
            self.results["pod_status"] = [
                {
                    "name": pod["metadata"]["name"],
                    "phase": pod.get("status", {}).get("phase"),
                    "containers": [
                        {
                            "name": item["name"],
                            "ready": item["ready"],
                            "restarts": item["restartCount"],
                            "last_termination": {
                                key: value
                                for key, value in item.get("lastState", {}).get("terminated", {}).items()
                                if key in {"reason", "exitCode", "signal"}
                            },
                            "state": {
                                phase: {
                                    key: value
                                    for key, value in state.items()
                                    if key in {"reason", "exitCode"}
                                }
                                for phase, state in item["state"].items()
                            },
                        }
                        for item in pod.get("status", {}).get("containerStatuses", [])
                    ],
                }
                for pod in pods
            ]
        except Exception:
            self.results["pod_status"] = "unavailable"

    def cleanup(self):
        if self.created:
            # No ambient context or broad/name-prefix cleanup: node label must prove ownership.
            result = subprocess.run(
                ["docker", "inspect", self.cluster + "-control-plane"],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                self.guard()
                self.command(
                    [
                        "kind",
                        "delete",
                        "cluster",
                        "--name",
                        self.cluster,
                        "--kubeconfig",
                        str(self.kubeconfig),
                    ],
                    "delete owned cluster",
                    timeout=120,
                )
                assert (
                    self.cluster
                    not in self.command(
                        ["kind", "get", "clusters"], "verify cluster cleanup", timeout=30
                    ).splitlines()
                )
            else:
                assert (
                    self.cluster
                    not in self.command(
                        ["kind", "get", "clusters"], "verify absent cluster", timeout=30
                    ).splitlines()
                )
            self.check("owned kind cluster removed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-disposable", action="store_true", required=True)
    parser.add_argument("--output", type=Path, default=Path("kubernetes-qualification.json"))
    args = parser.parse_args()
    if os.environ.get("CI") != "true":
        parser.error("This runner is restricted to explicitly disposable CI; ambient clusters are prohibited")
    with tempfile.TemporaryDirectory(prefix="zerograph-kubernetes-qualification-") as temp:
        drill = Drill(Path(temp))
        failure = None
        try:
            drill.execute()
        except (Exception, KeyboardInterrupt) as error:
            failure = f"{drill.stage}: {type(error).__name__}"
            if isinstance(error, DrillError):
                failure += " (" + str(error) + ")"
        finally:
            if failure:
                drill.diagnostics()
            try:
                drill.cleanup()
            except Exception as error:
                failure = (failure + "; " if failure else "") + f"cleanup: {type(error).__name__}"
            drill.results.update(status="failed" if failure else "passed", failure=failure)
            args.output.write_text(json.dumps(drill.results, indent=2) + "\n")
        if failure:
            raise SystemExit(failure)


if __name__ == "__main__":
    main()
