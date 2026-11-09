import json

from conftest import targets

from zerograph.parsers.mcp import redact, redact_args

CONFIG = {
    "mcpServers": {
        "fs": {"command": "npx",
               "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me", "/tmp"]},
        "shell": {"command": "bash", "args": ["-c", "mcp-shell"]},
        "gh": {"command": "docker",
               "args": ["run", "-i", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                        "ghcr.io/github/server"],
               "env": {"GITHUB_TOKEN": "ghp_abcdefABCDEF1234567890abcdef"}},
        "db": {"command": "npx", "args": ["server-postgres", "postgresql://u:s3cret@host/db"]},
        "k8s": {"command": "npx", "args": ["mcp-server-kubernetes"], "env": {"KUBECONFIG": "/x"}},
        "remote": {"url": "https://user:pw@mcp.example.com/sse"},
    }
}


def test_servers_become_tools_of_the_client_agent(scan_files):
    text = json.dumps(CONFIG, indent=2)
    g = scan_files({"claude_desktop_config.json": text})
    agent = "agent:mcp:claude_desktop_config.json"
    assert g.nodes[agent].label.startswith("Claude Desktop")
    assert len(targets(g, agent)) == 6
    tool = lambda name: f"mcp:claude_desktop_config.json:{name}"  # noqa: E731
    assert {"fs:write:/Users/me", "fs:write:/tmp"} <= targets(g, tool("fs"))
    assert g.nodes["fs:write:/Users/me"].severity == 8  # a whole home directory
    assert "cap:exec:shell" in targets(g, tool("shell"))
    assert {"cap:host:docker", "secret:env:GITHUB_TOKEN"} <= targets(g, tool("gh"))
    assert "cap:data:sql" in targets(g, tool("db"))
    assert {"cap:k8s:kubeconfig", "secret:env:KUBECONFIG"} <= targets(g, tool("k8s"))
    assert "net:remote:mcp.example.com" in targets(g, tool("remote"))
    assert g.nodes[tool("gh")].line == text.splitlines().index('    "gh": {') + 1


def test_secret_values_never_reach_the_graph(scan_files):
    g = scan_files({".mcp.json": json.dumps(CONFIG)})
    dump = repr([n.to_dict() for n in g.nodes.values()])
    for value in ("ghp_abcdef", "s3cret", "user:pw"):
        assert value not in dump


def test_redaction():
    assert redact("postgresql://u:pw@h/db") == "postgresql://***@h/db"
    assert redact("--api-key=sk-123") == "--api-key=***"
    assert redact("sk-AbCdEf0123456789XyZ01234") == "***"
    assert redact("/Users/me/projects") == "/Users/me/projects"
    assert redact("@modelcontextprotocol/server-filesystem") == "@modelcontextprotocol/server-filesystem"
    assert redact_args(["--token", "abc", "--verbose"]) == ["--token", "***", "--verbose"]


def test_vscode_servers_key(scan_files):
    g = scan_files({".vscode/mcp.json": json.dumps({"servers": {"sh": {"command": "zsh"}}})})
    assert "cap:exec:shell" in targets(g, "mcp:.vscode/mcp.json:sh")
