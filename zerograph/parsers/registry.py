"""Agent tool registries in JSON or YAML.

    agents:
      - name: triage-bot
        runs_as: k8s:ai/triage-bot      # optional: compose:<service> or k8s:<ns>/<sa or workload>
        tools: [shell, {name: tickets, type: http, credentials: [JIRA_TOKEN]}, {mcp: github}]
    tools:                              # optional shared definitions referenced by name
      - {name: shell, type: shell}

A file with only a top-level `tools:` list becomes one agent named after the file.
"""

from __future__ import annotations

import os

from ..loader import line_of
from ..model import Graph

TYPES = {
    "shell": "exec:shell", "bash": "exec:shell", "terminal": "exec:shell",
    "python": "exec:code", "code": "exec:code", "repl": "exec:code",
    "http": "net:http", "requests": "net:http", "web": "net:http", "browser": "net:http",
    "sql": "data:sql", "database": "data:sql",
    "kubernetes": "k8s:kubeconfig", "kubectl": "k8s:kubeconfig",
    "docker": "host:docker",
}
FS_TYPES = {"filesystem": True, "file": True, "files": True, "fs_read": False}


def looks_like_registry(doc) -> bool:
    if not isinstance(doc, dict):
        return False
    agents, tools = doc.get("agents"), doc.get("tools")
    return (isinstance(agents, list) and any(isinstance(a, dict) and "tools" in a for a in agents)) or (
        isinstance(tools, list) and bool(tools) and all(isinstance(t, (dict, str)) for t in tools)
        and "apiVersion" not in doc)


def parse(doc: dict, g: Graph, rel: str) -> None:
    shared = {}
    for t in doc.get("tools") or []:
        if isinstance(t, dict) and t.get("name"):
            shared[str(t["name"])] = t
    agents = doc.get("agents")
    if not isinstance(agents, list):
        stem = os.path.splitext(os.path.basename(rel))[0]
        agents = [{"name": stem, "tools": doc.get("tools") or []}]
    for spec in agents:
        if not isinstance(spec, dict) or not spec.get("name"):
            g.warn(f"{rel}: agent entry without a name, skipped")
            continue
        name = str(spec["name"])
        agent = f"agent:registry:{rel}:{name}"
        line = line_of(spec)
        g.add_node(agent, "agent", name, 0, rel, line, source="tool registry")
        if spec.get("runs_as"):
            g.add_ref(agent, str(spec["runs_as"]), "runs as", rel, line_of(spec, "runs_as"))
        for item in spec.get("tools") or []:
            _tool(g, agent, item, shared, rel, line_of(item) or line_of(spec, "tools"))


def _tool(g, agent, item, shared, rel, line) -> None:
    if isinstance(item, str):
        item = shared.get(item, {"name": item})
    if not isinstance(item, dict):
        return
    if item.get("mcp"):
        g.add_ref(agent, f"mcp:{item['mcp']}", "can call", rel, line)
        return
    name = str(item.get("name") or item.get("type") or "tool")
    item = {**shared.get(name, {}), **item}
    tool = f"tool:{rel}:{name}"
    kind = str(item.get("type") or name).lower()
    g.add_node(tool, "tool", name, 0, rel, line_of(item) or line, type=item.get("type"),
               _aliases=[f"tool:{name}"])
    g.add_edge(agent, tool, "can call", rel, line)
    if kind in TYPES:
        g.add_edge(tool, g.capability(TYPES[kind]), kind, rel, line)
    elif kind in FS_TYPES:
        g.add_edge(tool, g.fs_path(str(item.get("path") or "."), FS_TYPES[kind]), kind, rel, line)
    for cred in item.get("credentials") or item.get("env") or []:
        g.add_edge(tool, g.env_secret(str(cred), rel, line), "holds", rel, line)
