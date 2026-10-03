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


def runner_minutes(name, ancestors=()):
    """Expand local calls and finite matrices; reject hidden or recursive fanout."""
    if name in ancestors:
        raise ValueError("recursive workflow call")
    total = 0
    for job in load(name)["jobs"].values():
        copies = 1
        matrix = job.get("strategy", {}).get("matrix", {})
        if not isinstance(matrix, dict):
            raise ValueError("dynamic matrix is not budgetable")
        for key, values in matrix.items():
            if key in {"include", "exclude"} or not isinstance(values, list) or not values:
                raise ValueError("matrix must have nonempty finite dimensions")
            copies *= len(values)
        if "uses" in job:
            prefix = "./.github/workflows/"
            reference = job["uses"]
            if not reference.startswith(prefix):
                raise ValueError("only same-commit local calls are budgetable")
            child = reference[len(prefix):]
            if Path(child).name != child or not child.endswith(".yml"):
                raise ValueError("invalid local workflow reference")
            minutes = runner_minutes(child, (*ancestors, name))
        else:
            if job.get("runs-on") != "ubuntu-latest":
                raise ValueError("campaign must use ordinary Linux runners")
            minutes = job.get("timeout-minutes")
            if type(minutes) is not int or minutes <= 0:
                raise ValueError("positive fixed timeout required")
        total += copies * minutes
    return total


class WorkflowBudgetTests(unittest.TestCase):
    def test_standard_ci_only_pr_and_main_push(self):
        workflow = load("ci.yml")
        self.assertEqual(set(workflow["on"]), {"push", "pull_request"})
        self.assertEqual(workflow["on"]["push"], {"branches": ["main"]})
        self.assertIsNone(workflow["on"]["pull_request"])
        self.assertEqual(
            {name for name, job in workflow["jobs"].items() if "uses" not in job},
            {"backend", "frontend", "helm"},
        )
        concurrency = workflow["concurrency"]
        self.assertEqual(
            concurrency["cancel-in-progress"],
            "${{ github.event_name != 'pull_request' || "
            "github.head_ref != 'fm/zerograph-runtime-qualification' }}",
        )
        self.assertIn("github.event.pull_request.number || github.ref", concurrency["group"])
        self.assertIn("github.workflow", concurrency["group"])

    def test_expensive_drills_manual_only_and_do_not_cancel_cleanup(self):
        for name in ("compose.yml", "graph.yml", "restore.yml", "oidc.yml"):
            with self.subTest(workflow=name):
                workflow = load(name)
                self.assertEqual(workflow["on"], {"workflow_dispatch": None, "workflow_call": None})
                self.assertIs(workflow["concurrency"]["cancel-in-progress"], False)
                self.assertEqual(
                    workflow["concurrency"]["group"],
                    f"zerograph-{Path(name).stem}-qualification",
                )
                for job in workflow["jobs"].values():
                    self.assertTrue(any(step.get("if") == "always()" for step in job["steps"]))

    def test_all_owned_jobs_have_bounded_timeout_and_read_only_permissions(self):
        for name in ("ci.yml", "compose.yml", "graph.yml", "restore.yml", "oidc.yml"):
            with self.subTest(workflow=name):
                workflow = load(name)
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                for job in workflow["jobs"].values():
                    if "uses" in job:
                        continue
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
                self.assertEqual(set(workflow["on"]), {"workflow_dispatch", "workflow_call"})
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                self.assertIs(workflow["concurrency"]["cancel-in-progress"], False)
                for job in workflow["jobs"].values():
                    self.assertIs(type(job["timeout-minutes"]), int)
                    self.assertGreater(job["timeout-minutes"], 0)
                    self.assertLessEqual(job["timeout-minutes"], 25)

    def test_kubernetes_retry_only_calls_exact_guarded_same_commit_workflow(self):
        guard = (
            "github.event_name == 'pull_request' && "
            "github.head_ref == 'fm/zerograph-runtime-qualification' && "
            "github.event.pull_request.head.repo.full_name == github.repository && "
            "github.base_ref == 'main'"
        )
        jobs = load("ci.yml")["jobs"]
        names = ("compose", "graph", "restore", "oidc", "browser", "kubernetes")
        self.assertEqual(set(jobs), {"backend", "frontend", "helm", "qualify-kubernetes"})
        caller = jobs["qualify-kubernetes"]
        self.assertEqual(caller["if"], guard)
        self.assertEqual(caller["needs"], ["backend", "frontend", "helm"])
        self.assertEqual(caller["uses"], "./.github/workflows/kubernetes.yml")
        self.assertEqual(caller["permissions"], {"contents": "read"})
        self.assertNotIn("secrets", caller)
        self.assertNotIn("strategy", caller)
        groups = set()
        for name in names:
            child = load(f"{name}.yml")
            self.assertEqual(child["on"], {"workflow_dispatch": None, "workflow_call": None})
            group = child["concurrency"]["group"]
            self.assertNotIn("github.workflow", group)
            self.assertNotIn(group, groups)
            groups.add(group)
            for job in child["jobs"].values():
                self.assertEqual(job["if"], f"github.event_name == 'workflow_dispatch' || ({guard})")
                self.assertNotIn("uses", job)  # No nested fanout or reusable-call loops.

    def test_targeted_retry_budget_and_retained_historic_campaign_caps(self):
        self.assertEqual(runner_minutes("ci.yml"), 45)
        # Historic full campaign25+70; uncalled passing drills are not billed again.
        historic_children = ("compose", "graph", "restore", "oidc", "browser", "kubernetes")
        self.assertEqual(25 + sum(runner_minutes(f"{name}.yml") for name in historic_children), 95)
        self.assertEqual(runner_minutes("graph.yml"), 10)
        limits = {"compose": 10, "graph": 5, "restore": 10, "oidc": 10, "browser": 10, "kubernetes": 20}
        for name, limit in limits.items():
            for job in load(f"{name}.yml")["jobs"].values():
                self.assertEqual(job["timeout-minutes"], limit)
        for name, limit in {"backend": 10, "frontend": 10, "helm": 5}.items():
            self.assertEqual(load("ci.yml")["jobs"][name]["timeout-minutes"], limit)

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
