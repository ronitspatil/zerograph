from conftest import targets

REGISTRY = """\
agents:
  - name: triage
    runs_as: compose:api
    tools:
      - shell
      - {name: tickets, type: http, credentials: [JIRA_TOKEN]}
      - {name: notes, type: filesystem, path: /srv/notes}
      - {mcp: github}
      - {name: nowhere, type: unknown}
tools:
  - {name: shell, type: shell}
"""


def test_registry_agents_tools_and_refs(scan_files):
    g = scan_files({
        "agents.yaml": REGISTRY,
        "docker-compose.yml": "services:\n  api:\n    image: api\n",
        ".mcp.json": '{"mcpServers": {"github": {"command": "npx", "args": ["server-github"]}}}',
    })
    agent = "agent:registry:agents.yaml:triage"
    out = targets(g, agent)
    api = next(n for n in g.nodes if n.startswith("compose:") and n.endswith("/api"))
    assert {"tool:agents.yaml:shell", "tool:agents.yaml:tickets", "tool:agents.yaml:notes",
            "mcp:.mcp.json:github", api} <= out
    assert targets(g, "tool:agents.yaml:shell") == {"cap:exec:shell"}
    assert targets(g, "tool:agents.yaml:tickets") == {"cap:net:http", "secret:env:JIRA_TOKEN"}
    assert targets(g, "tool:agents.yaml:notes") == {"fs:write:/srv/notes"}
    assert not targets(g, "tool:agents.yaml:nowhere")


def test_tools_only_file_is_one_agent(scan_files):
    g = scan_files({"tools.json": '{"tools": [{"name": "py", "type": "python"}]}'})
    assert g.nodes["agent:registry:tools.json:tools"].kind == "agent"


def test_unresolved_reference_warns(scan_files):
    g = scan_files({"agents.yml": "agents:\n  - {name: a, runs_as: k8s:nope/none, tools: []}\n"})
    assert any("did not match" in w for w in g.warnings)
