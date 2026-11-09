from conftest import targets

AGENT = '''\
import subprocess
from langchain.agents import initialize_agent, AgentExecutor, create_react_agent, load_tools
from langchain_community.tools import ShellTool, RequestsGetTool
from langchain_community.agent_toolkits import FileManagementToolkit, SQLDatabaseToolkit
from langchain_core.tools import tool

open("SIDE_EFFECT", "w").write("this file must never be executed")


@tool
def deploy(service: str) -> str:
    """Deploy a service."""
    return subprocess.check_output(["kubectl", "rollout", "restart", service])


@tool("pure")
def pure(x: int) -> int:
    """No side effects."""
    return x + 1


files = FileManagementToolkit(root_dir="/srv/data")
tools = [ShellTool(), deploy, pure]
tools += files.get_tools()

ops_agent = initialize_agent(tools, llm)

web = create_react_agent(llm, [RequestsGetTool(requests_wrapper=None)] + load_tools(["python_repl"]), prompt)
executor = AgentExecutor(agent=web, tools=[])

lonely = SQLDatabaseToolkit(db=None, llm=None)
'''


def test_agents_tools_and_capabilities(scan_files, tmp_path):
    g = scan_files({"bot/agent.py": AGENT})
    agents = {n.label: n for n in g.nodes.values() if n.kind == "agent"}
    assert set(agents) == {"ops_agent (initialize_agent)", "web (create_react_agent)"}

    ops = agents["ops_agent (initialize_agent)"].id
    tools = {g.nodes[t].label for t in targets(g, ops)}
    assert tools == {"ShellTool", "deploy (@tool)", "pure (@tool)", "FileManagementToolkit"}
    assert "cap:exec:shell" in targets(g, "tool:bot/agent.py:deploy")
    assert not targets(g, "tool:bot/agent.py:pure")
    fm = next(t for t in targets(g, ops) if "FileManagementToolkit" in t)
    assert targets(g, fm) == {"fs:write:/srv/data"}

    web = agents["web (create_react_agent)"].id
    caps = {c for t in targets(g, web) for c in targets(g, t)}
    assert caps == {"cap:net:http", "cap:exec:code"}
    # An unbound toolkit is still recorded as a tool.
    assert any(n.label == "SQLDatabaseToolkit" for n in g.nodes.values())


def test_scanned_code_is_never_executed(scan_files, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scan_files({"agent.py": AGENT})
    assert not (tmp_path / "SIDE_EFFECT").exists()


def test_agent_in_compose_build_context_runs_as_that_service(scan_files):
    g = scan_files({
        "docker-compose.yml": "services:\n  bot:\n    build: ./bot\n    privileged: true\n",
        "bot/agent.py": AGENT,
    })
    ops = next(n.id for n in g.nodes.values() if n.label.startswith("ops_agent"))
    service = next(n.id for n in g.nodes.values() if n.label == "bot (compose)")
    assert service in targets(g, ops)


def test_files_without_langchain_are_ignored(scan_files):
    g = scan_files({"util.py": "import os\nos.system('rm -rf /')\n"})
    assert not g.nodes


def test_syntax_error_warns(scan_files):
    g = scan_files({"broken.py": "from langchain import x\ndef (:\n"})
    assert any("not valid Python" in w for w in g.warnings)
