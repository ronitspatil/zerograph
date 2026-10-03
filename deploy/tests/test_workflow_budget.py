"""Actions trigger and budget contracts, without dispatching any workflows."""

import re
import unittest
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


class WorkflowLoader(yaml.SafeLoader):
    """Use YAML 1.2 boolean spelling so Actions' `on` remains a key."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}

WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def load(name):
    return yaml.load((WORKFLOWS / name).read_text(), Loader=WorkflowLoader)


def runs(job):
    return "\n".join(step.get("run", "") for step in job["steps"])


class WorkflowBudgetTests(unittest.TestCase):
    def test_standard_ci_only_pr_and_main_push(self):
        workflow = load("ci.yml")
        self.assertEqual(set(workflow["on"]), {"push", "pull_request"})
        self.assertEqual(workflow["on"]["push"], {"branches": ["main"]})
        self.assertIsNone(workflow["on"]["pull_request"])
        self.assertEqual(set(workflow["jobs"]), {"backend", "frontend", "helm"})
        concurrency = workflow["concurrency"]
        self.assertIs(concurrency["cancel-in-progress"], True)
        self.assertIn("github.event.pull_request.number || github.ref", concurrency["group"])
        self.assertIn("github.workflow", concurrency["group"])

    def test_expensive_drills_manual_only_and_do_not_cancel_cleanup(self):
        for name in ("compose.yml", "graph.yml", "restore.yml", "oidc.yml"):
            with self.subTest(workflow=name):
                workflow = load(name)
                self.assertEqual(workflow["on"], {"workflow_dispatch": None})
                self.assertIs(workflow["concurrency"]["cancel-in-progress"], False)
                self.assertEqual(workflow["concurrency"]["group"], "${{ github.workflow }}")
                for job in workflow["jobs"].values():
                    self.assertTrue(any(step.get("if") == "always()" for step in job["steps"]))

    def test_all_owned_jobs_have_bounded_timeout_and_read_only_permissions(self):
        for name in ("ci.yml", "compose.yml", "graph.yml", "restore.yml", "oidc.yml"):
            with self.subTest(workflow=name):
                workflow = load(name)
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                for job in workflow["jobs"].values():
                    self.assertIs(type(job["timeout-minutes"]), int)
                    self.assertGreater(job["timeout-minutes"], 0)
                    self.assertLessEqual(job["timeout-minutes"], 25)

    def test_optional_browser_and_kubernetes_drills_stay_manual_and_bounded(self):
        names = ("browser.yml", "kubernetes.yml")
        if not any((WORKFLOWS / name).exists() for name in names):
            self.skipTest("browser/Kubernetes workflows are not in this base")
        for name in names:
            if not (WORKFLOWS / name).exists():
                continue  # Their implementation branches are not part of this base.
            with self.subTest(workflow=name):
                workflow = load(name)
                self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                self.assertIs(workflow["concurrency"]["cancel-in-progress"], False)
                for job in workflow["jobs"].values():
                    self.assertIs(type(job["timeout-minutes"]), int)
                    self.assertGreater(job["timeout-minutes"], 0)
                    self.assertLessEqual(job["timeout-minutes"], 25)

    def test_python_setup_consolidates_without_dropping_validation(self):
        jobs = load("ci.yml")["jobs"]
        backend = runs(jobs["backend"])
        self.assertEqual(backend.count("pip install -r backend/requirements-dev.lock -e backend"), 1)
        for command in (
            "ruff check backend",
            "ruff check --config backend/pyproject.toml deploy",
            "pytest --cov-fail-under=75",
            "scripts/qualify_analysis.py --output analysis-qualification.json",
            "pip-audit -r backend/requirements.lock --no-deps --disable-pip",
        ):
            self.assertIn(command, backend)
        self.assertIn("ZG_INGESTION_POSTGRES_URL", jobs["backend"]["env"])
        self.assertIn("postgres", jobs["backend"]["services"])
        frontend = runs(jobs["frontend"])
        self.assertIn("npm audit --audit-level=high", frontend)
        self.assertNotIn("--omit", frontend)
        for command in ("npm run typecheck", "npm test", "npm run build"):
            self.assertIn(command, frontend)
        self.assertIn("python -m unittest discover -s deploy/tests -v", runs(jobs["helm"]))

    def test_manual_drills_keep_real_qualification_and_cleanup(self):
        graph = load("graph.yml")["jobs"]["graph-integration"]
        self.assertEqual(graph["strategy"]["matrix"]["graph"], ["memgraph", "neo4j"])
        self.assertEqual(graph["strategy"]["max-parallel"], 1)
        self.assertIn("test_graph_integration.py", runs(graph))
        self.assertIn("docker rm -f graph", runs(graph))
        for name, required in {
            "compose.yml": ["test_stack_e2e.py", "survive_database_restart", "down --volumes --remove-orphans"],
            "restore.yml": ["backup_restore.py backup", "backup_restore.py restore", "test_restore_e2e.py", "rm -f /tmp/zerograph-restore.zip"],
            "oidc.yml": ["test_oidc_e2e.py", "deploy/oidc-cleanup.py", "down --volumes --remove-orphans"],
        }.items():
            with self.subTest(workflow=name):
                commands = runs(next(iter(load(name)["jobs"].values())))
                for command in required:
                    self.assertIn(command, commands)


if __name__ == "__main__":
    unittest.main()
