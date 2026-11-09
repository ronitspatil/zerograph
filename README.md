# ZeroGraph

ZeroGraph reads configuration files and maps the AI agents, non-human identities, tools and
secrets in them into one graph. For each agent it works out what an attacker could reach if
that agent were compromised (its blast radius) and ranks agents by it. It only reads files.
It never runs or imports scanned code, never uses the network, and never writes secret values.

## Install and run

```sh
pip install -e .
zerograph scan examples/ -o graph.html --json graph.json
```

This prints a ranked table, and `graph.html` is a single interactive page. Click an agent to
highlight its blast radius and see each reachable privilege with its `file:line` evidence.
The page loads Cytoscape.js from cdnjs when opened; offline, the ranked panel still works.

## What it reads

- **Docker Compose** (`docker-compose*.yml`, `compose*.yml`): services, privileged, `cap_add`,
  host network/PID, docker.sock and host mounts, secrets, credential env vars, shared networks.
- **Kubernetes** manifests: ServiceAccounts, Roles and bindings (with `*` and cluster-admin),
  Secrets, and workloads with their service account, token mount, privileged and hostPath settings.
- **MCP configs** (`claude_desktop_config.json`, `.mcp.json`, anything with `mcpServers`):
  each server's command, filesystem roots, docker flags and env credentials.
- **LangChain code** (via `ast`): ShellTool, PythonREPL, requests, SQL and file tools,
  `@tool` functions, and which agent they are bound to. Also simple JSON/YAML tool
  registries (see `zerograph/parsers/registry.py` and `examples/agents.yaml`).

A workload holding an LLM API key (or labelled `zerograph.agent` / `zerograph.io/agent`) is
treated as an agent. Agent code inside a compose service's build context runs as that service.

## Blast radius

Every privilege or secret has a severity from 0 to 10: host root or docker socket 10,
cluster-admin 9, host PID or kubeconfig 8, shell or code execution 7, secret read or SQL 6,
a credential 5, filesystem write 5 (8 for a home directory), outbound HTTP 3, network 2.
An agent's score is the sum over everything reachable from it; its rating comes from the
worst item (critical >= 9, high >= 7, medium >= 4). Reaching a service over a shared network
counts the network, but not that service's own privileges.
