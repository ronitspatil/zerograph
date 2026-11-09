"""MCP client configs: each server is a tool provider the client agent can call."""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from ..loader import line_of
from ..model import Graph, is_credential_name

SHELLS = {"sh", "bash", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
SHELL_HINTS = ("server-shell", "mcp-shell", "shell-server", "server-commands", "desktop-commander",
               "terminal", "mcp-server-shell")
SQL_HINTS = ("postgres", "mysql", "sqlite", "mssql", "server-sql", "bigquery", "snowflake")
HTTP_HINTS = ("server-fetch", "mcp-server-fetch", "puppeteer", "playwright", "browser", "brave-search")
K8S_HINTS = ("kubernetes", "kubectl", "k8s")
CLIENTS = {"claude_desktop_config.json": "Claude Desktop", ".mcp.json": "Claude Code",
           "mcp.json": "MCP client"}


def servers_of(doc: dict) -> dict | None:
    servers = doc.get("mcpServers")
    if servers is None and isinstance(doc.get("mcp"), dict):
        servers = doc["mcp"].get("servers") or doc["mcp"].get("mcpServers")
    return servers if isinstance(servers, dict) else None


def parse(doc: dict, g: Graph, rel: str) -> None:
    servers = servers_of(doc) or {}
    if not servers and isinstance(doc.get("servers"), dict):  # VS Code .vscode/mcp.json
        servers = doc["servers"]
    base = os.path.basename(rel)
    client = CLIENTS.get(base, "MCP client")
    agent = f"agent:mcp:{rel}"
    g.add_node(agent, "agent", f"{client} ({rel})", 0, rel, line_of(doc), source="mcp config")
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            g.warn(f"{rel}: MCP server {name!r} is not a mapping, skipped")
            continue
        line = line_of(servers, name)
        tool = f"mcp:{rel}:{name}"
        command = str(cfg.get("command") or "")
        args = [str(a) for a in cfg.get("args") or []]
        g.add_node(tool, "tool", f"{name} (MCP server)", 0, rel, line, source="mcp server",
                   command=command or None, args=redact_args(args) or None,
                   url=redact(str(cfg["url"])) if cfg.get("url") else None,
                   _aliases=[f"mcp:{name}"])
        g.add_edge(agent, tool, "can call", rel, line)
        env = cfg.get("env") or {}
        for key in env if isinstance(env, dict) else []:
            if is_credential_name(str(key)) or key == "KUBECONFIG":
                g.add_edge(tool, g.env_secret(str(key), rel, line_of(env, key)), "holds", rel,
                           line_of(env, key))
        for target, why in classify(command, args, env if isinstance(env, dict) else {}, g):
            g.add_edge(tool, target, why, rel, line)
        if cfg.get("url"):
            host = urlsplit(str(cfg["url"])).hostname or "remote"
            remote = f"net:remote:{host}"
            g.add_node(remote, "resource", f"Remote MCP endpoint {host}", 2)
            g.add_edge(tool, remote, "connects to", rel, line, transitive=False)


def classify(command: str, args: list[str], env: dict, g: Graph) -> list[tuple[str, str]]:
    """Map a server launch command to (resource node id, reason) pairs."""
    text = " ".join([command, *args]).lower()
    out = []
    if os.path.basename(command).lower() in SHELLS or any(h in text for h in SHELL_HINTS):
        out.append((g.capability("exec:shell"), "runs shell commands"))
    if os.path.basename(command).lower().startswith(("python", "node")) and {"-c", "-e"} & set(args):
        out.append((g.capability("exec:code"), "runs inline code"))
    if "server-filesystem" in text:
        idx = next(i for i, a in enumerate(args) if "server-filesystem" in a)
        for root in args[idx + 1:] or ["."]:
            if not root.startswith("-"):
                out.append((g.fs_path(root, write=True), "filesystem root"))
    if any(h in text for h in SQL_HINTS):
        out.append((g.capability("data:sql"), "database access"))
    if any(h in text for h in HTTP_HINTS):
        out.append((g.capability("net:http"), "makes web requests"))
    if any(h in text for h in K8S_HINTS) or "KUBECONFIG" in env:
        out.append((g.capability("k8s:kubeconfig"), "uses kubeconfig"))
    if os.path.basename(command) == "docker":
        out += _docker_run(args, g)
    return out


def _docker_run(args: list[str], g: Graph) -> list[tuple[str, str]]:
    out = []
    for i, arg in enumerate(args):
        value = args[i + 1] if i + 1 < len(args) else ""
        if arg in ("-v", "--volume") or arg.startswith(("-v=", "--volume=")):
            spec = arg.split("=", 1)[1] if "=" in arg else value
            parts = spec.split(":")
            if len(parts) >= 2 and parts[0].startswith(("/", "~", ".", "$")):
                ro = len(parts) > 2 and "ro" in parts[2]
                out.append((g.host_path(parts[0], ro), "docker -v mount"))
        elif arg == "--privileged":
            out.append((g.capability("host:root"), "docker --privileged"))
        elif arg in ("--network", "--net") and value == "host" or arg in ("--network=host", "--net=host"):
            out.append((g.capability("host:network"), "docker --network host"))
        elif arg in ("--pid=host",) or arg == "--pid" and value == "host":
            out.append((g.capability("host:pid"), "docker --pid host"))
    return out


_KV = re.compile(r"^(--?[\w.-]*(?:key|token|secret|passw|pwd|auth)[\w.-]*[=:])(.+)$", re.I)
_URL_CREDS = re.compile(r"(\w+://)[^/@\s]+@")
_OPAQUE = re.compile(r"^[A-Za-z0-9_\-+/=.]{24,}$")


def redact(arg: str) -> str:
    """Strip anything that looks like a secret value from a command-line argument."""
    arg = _URL_CREDS.sub(r"\1***@", arg)
    match = _KV.match(arg)
    if match:
        return match.group(1) + "***"
    classes = sum(bool(re.search(p, arg)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
    if _OPAQUE.match(arg) and classes == 3 and not arg.startswith("/"):
        return "***"
    return arg


def redact_args(args: list[str]) -> list[str]:
    out = []
    for i, arg in enumerate(args):
        prev = args[i - 1] if i else ""
        flag = prev.startswith("-") and is_credential_name(prev.lstrip("-").replace("-", "_"))
        out.append("***" if flag else redact(arg))
    return out
