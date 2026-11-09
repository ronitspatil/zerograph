"""LangChain-style agent code, read with the ast module only. Nothing is imported or run."""

from __future__ import annotations

import ast
import os

from ..model import Graph

# Well-known dangerous tool classes -> (capability, filesystem mode or None).
TOOL_CLASSES = {
    "ShellTool": "exec:shell", "BashProcess": "exec:shell", "TerminalTool": "exec:shell",
    "PythonREPLTool": "exec:code", "PythonAstREPLTool": "exec:code", "PythonREPL": "exec:code",
    "RequestsGetTool": "net:http", "RequestsPostTool": "net:http", "RequestsPutTool": "net:http",
    "RequestsPatchTool": "net:http", "RequestsDeleteTool": "net:http", "RequestsToolkit": "net:http",
    "SQLDatabaseToolkit": "data:sql", "QuerySQLDataBaseTool": "data:sql",
    "QuerySQLDatabaseTool": "data:sql", "InfoSQLDatabaseTool": "data:sql",
    "FileManagementToolkit": "fs:write", "WriteFileTool": "fs:write", "DeleteFileTool": "fs:write",
    "MoveFileTool": "fs:write", "CopyFileTool": "fs:write",
    "ReadFileTool": "fs:read", "ListDirectoryTool": "fs:read", "FileSearchTool": "fs:read",
}
LOAD_TOOLS_NAMES = {"terminal": "exec:shell", "python_repl": "exec:code", "requests": "net:http",
                    "requests_all": "net:http", "requests_get": "net:http", "requests_post": "net:http"}
AGENT_FACTORIES = {
    "initialize_agent": None, "AgentExecutor": None, "create_react_agent": None,
    "create_openai_functions_agent": None, "create_openai_tools_agent": None,
    "create_tool_calling_agent": None, "create_structured_chat_agent": None,
    "create_sql_agent": "data:sql", "create_python_agent": "exec:code",
    "create_pandas_dataframe_agent": "exec:code", "create_csv_agent": "exec:code",
}
# Calls inside a @tool body that reveal what the tool really does.
BODY_CALLS = {
    "subprocess": "exec:shell", "os.system": "exec:shell", "os.popen": "exec:shell",
    "eval": "exec:code", "exec": "exec:code", "requests": "net:http", "httpx": "net:http",
    "urllib.request": "net:http",
}


def worth_scanning(text: str) -> bool:
    return "langchain" in text or "@tool" in text or "langgraph" in text


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _is_factory(node) -> bool:
    return isinstance(node, ast.Call) and _name(node).split(".")[-1] in AGENT_FACTORIES


class _Scan:
    def __init__(self, g: Graph, rel: str, abspath: str, tree: ast.Module) -> None:
        self.g, self.rel, self.abspath, self.tree = g, rel, abspath, tree
        self.stem = os.path.splitext(os.path.basename(rel))[0]
        self.env: dict[str, list[str]] = {}    # variable -> tool node ids
        self.agents: dict[str, str] = {}       # variable -> agent node id
        self.done: dict[int, str] = {}         # id(call node) -> agent node id

    def run(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and self._is_tool(node):
                self.env[node.name] = [self._decorated_tool(node)]
        for node in sorted(ast.walk(self.tree), key=lambda n: getattr(n, "lineno", 0)):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    if _is_factory(node.value):
                        self.agents[target.id] = self._agent(node.value, target.id)
                    else:
                        tools = self._resolve(node.value)
                        if tools:
                            self.env[target.id] = tools
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                self.env[node.target.id] = self.env.get(node.target.id, []) + self._resolve(node.value)
            elif _is_factory(node):
                self._agent(node, None)

    def _is_tool(self, fn) -> bool:
        return any(_name(d).split(".")[-1] == "tool" for d in fn.decorator_list)

    def _decorated_tool(self, fn) -> str:
        tid = f"tool:{self.rel}:{fn.name}"
        self.g.add_node(tid, "tool", f"{fn.name} (@tool)", 0, self.rel, fn.lineno, source="python @tool")
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            called = _name(call.func)
            for prefix, cap in BODY_CALLS.items():
                if called == prefix or called.startswith(prefix + "."):
                    self.g.add_edge(tid, self.g.capability(cap), f"calls {called}()", self.rel, call.lineno)
        return tid

    def _class_tool(self, call: ast.Call) -> list[str]:
        cls = _name(call.func).split(".")[-1]
        tid = f"tool:{self.rel}:{cls}@{call.lineno}"
        self.g.add_node(tid, "tool", cls, 0, self.rel, call.lineno, source="langchain tool")
        cap = TOOL_CLASSES[cls]
        if cap.startswith("fs:"):
            root = next((k.value.value for k in call.keywords if k.arg == "root_dir"
                         and isinstance(k.value, ast.Constant)), ".")
            target = self.g.fs_path(str(root), write=cap == "fs:write")
        else:
            target = self.g.capability(cap)
        self.g.add_edge(tid, target, cls, self.rel, call.lineno)
        return [tid]

    def _resolve(self, expr) -> list[str]:
        """Best-effort: which tool nodes does this expression evaluate to?"""
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return [t for e in expr.elts for t in self._resolve(e)]
        if isinstance(expr, ast.Starred):
            return self._resolve(expr.value)
        if isinstance(expr, ast.BinOp):
            return self._resolve(expr.left) + self._resolve(expr.right)
        if isinstance(expr, ast.Name):
            return self.env.get(expr.id, [])
        if isinstance(expr, ast.Call):
            called = _name(expr.func)
            last = called.split(".")[-1]
            if last in TOOL_CLASSES:
                return self._class_tool(expr)
            if last == "load_tools" and expr.args and isinstance(expr.args[0], ast.List):
                return self._load_tools(expr)
            if last == "get_tools" and isinstance(expr.func, ast.Attribute):
                return self._resolve(expr.func.value)
            if last in ("Tool", "StructuredTool", "from_function"):
                fn = next((k.value for k in expr.keywords if k.arg in ("func", "coroutine")), None)
                return self._resolve(fn) if fn is not None else []
        return []

    def _load_tools(self, call) -> list[str]:
        out = []
        for elt in call.args[0].elts:
            if isinstance(elt, ast.Constant) and elt.value in LOAD_TOOLS_NAMES:
                tid = f"tool:{self.rel}:{elt.value}@{call.lineno}"
                self.g.add_node(tid, "tool", f"{elt.value} (load_tools)", 0, self.rel, call.lineno)
                self.g.add_edge(tid, self.g.capability(LOAD_TOOLS_NAMES[elt.value]), "load_tools",
                                self.rel, call.lineno)
                out.append(tid)
        return out

    def _agent(self, call: ast.Call, var: str | None) -> str:
        if id(call) in self.done:
            return self.done[id(call)]
        factory = _name(call.func).split(".")[-1]
        inner = next((k.value for k in call.keywords if k.arg == "agent"), None)
        if isinstance(inner, ast.Name) and inner.id in self.agents:
            aid = self.agents[inner.id]          # AgentExecutor(agent=...) wraps an existing agent
        elif _is_factory(inner):
            aid = self._agent(inner, var)
        else:
            aid = f"agent:code:{self.rel}:{call.lineno}"
            label = var or f"{self.stem}:{call.lineno}"
            self.g.add_node(aid, "agent", f"{label} ({factory})", 0, self.rel, call.lineno,
                            source="python agent", _path=self.abspath)
        candidates = [k.value for k in call.keywords if k.arg in ("tools", "toolkit", "extra_tools")]
        candidates += [a for a in call.args if isinstance(a, (ast.List, ast.Name, ast.BinOp))]
        for expr in candidates:
            for tid in self._resolve(expr):
                self.g.add_edge(aid, tid, "can call", self.rel, call.lineno)
        self.done[id(call)] = aid
        if AGENT_FACTORIES[factory]:
            self.g.add_edge(aid, self.g.capability(AGENT_FACTORIES[factory]), factory, self.rel, call.lineno)
        return aid


def parse(text: str, g: Graph, rel: str, abspath: str) -> None:
    try:
        tree = ast.parse(text, filename=rel)
    except (SyntaxError, ValueError) as exc:
        g.warn(f"{rel}: not valid Python ({exc.__class__.__name__}), skipped")
        return
    _Scan(g, rel, abspath, tree).run()
