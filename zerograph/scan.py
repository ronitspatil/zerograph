"""Walk a directory, route each file to a parser, then link the pieces together.

Files are only read. Nothing found is imported, executed or sent anywhere.
"""

from __future__ import annotations

import fnmatch
import os

from .loader import load_documents
from .model import Graph
from .parsers import compose, kubernetes, langchain, mcp, registry

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages"}
COMPOSE_NAMES = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")
MAX_BYTES = 2_000_000


def scan(root: str) -> Graph:
    g = Graph()
    root = os.path.abspath(root)
    k8s = kubernetes.Objects()
    for path in _files(root):
        rel = os.path.relpath(path, os.path.dirname(root) if os.path.isfile(root) else root)
        rel = rel.replace(os.sep, "/")
        try:
            _scan_file(path, rel, g, k8s)
        except Exception as exc:  # one bad file must never stop the scan
            g.warn(f"{rel}: skipped after unexpected {exc.__class__.__name__}: {exc}")
    try:
        kubernetes.build(k8s, g)
    except Exception as exc:
        g.warn(f"Kubernetes resolution failed: {exc.__class__.__name__}: {exc}")
    _link(g)
    return g


def _files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith((".yml", ".yaml", ".json", ".py")):
                yield os.path.join(dirpath, name)


def _scan_file(path: str, rel: str, g: Graph, k8s: kubernetes.Objects) -> None:
    if os.path.getsize(path) > MAX_BYTES:
        g.warn(f"{rel}: larger than {MAX_BYTES} bytes, skipped")
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    name = os.path.basename(path)
    if name.endswith(".py"):
        if langchain.worth_scanning(text):
            langchain.parse(text, g, rel, path)
        return
    try:
        docs = load_documents(text, is_json=name.endswith(".json"))
    except ValueError as exc:
        g.warn(f"{rel}: {exc}, skipped")
        return
    if any(fnmatch.fnmatch(name, pattern) for pattern in COMPOSE_NAMES):
        if docs and isinstance(docs[0], dict):
            compose.parse(docs[0], g, rel, path)
        else:
            g.warn(f"{rel}: compose file is not a mapping, skipped")
        return
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if "apiVersion" in doc and "kind" in doc:
            k8s.add(doc, rel)
        elif mcp.servers_of(doc) is not None or (
                name == "mcp.json" and isinstance(doc.get("servers"), dict)):
            mcp.parse(doc, g, rel)
        elif registry.looks_like_registry(doc):
            registry.parse(doc, g, rel)


def _link(g: Graph) -> None:
    """Resolve cross-file references and promote agent-like workloads to agents."""
    aliases: dict[str, list[str]] = {}
    for node in g.nodes.values():
        for alias in node.attrs.get("_aliases", []):
            aliases.setdefault(alias, []).append(node.id)
    for src, ref, rel_name, file, line in g.refs:
        targets = [ref] if ref in g.nodes else aliases.get(ref, [])
        if not targets:
            g.warn(f"{file}:{line}: reference {ref!r} did not match anything")
        for target in targets:
            g.add_edge(src, target, rel_name, file, line)

    # Agent code inside a compose service's build context runs as that service.
    services = [n for n in g.nodes.values() if n.attrs.get("_build_context")]
    for agent in [n for n in g.nodes.values() if n.attrs.get("_path")]:
        for svc in services:
            ctx = svc.attrs["_build_context"]
            if agent.attrs["_path"].startswith(ctx.rstrip(os.sep) + os.sep):
                g.add_edge(agent.id, svc.id, "runs inside (build context)", agent.file, agent.line)

    # A workload holding an LLM key, or labelled as an agent, is an agent unless
    # agent code already runs as it.
    runs_as = {e.dst for e in g.edges if g.nodes.get(e.src) and g.nodes[e.src].kind == "agent"}
    for node in list(g.nodes.values()):
        if node.attrs.get("_agent_hint") and node.id not in runs_as:
            aid = f"agent:{node.id}"
            g.add_node(aid, "agent", node.label.replace(" (compose)", "") + " (agent)", 0,
                       node.file, node.line, source="workload holding an LLM key")
            g.add_edge(aid, node.id, "runs as", node.file, node.line)
