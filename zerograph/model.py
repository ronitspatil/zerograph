"""The graph model every parser writes into.

Node kinds: agent, identity, tool, secret, resource.
Edges point from the thing that is compromised to what it gives access to.
A non-transitive edge (for example "can reach over the network") marks its
target as reachable without granting that target's own privileges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

KINDS = ("agent", "identity", "tool", "secret", "resource")

# Built-in capabilities and their severity weight (0-10). See README for the scale.
CAPABILITIES = {
    "host:root": ("Host root (privileged container / escape)", 10),
    "host:docker": ("Docker daemon access (host root)", 10),
    "host:pid": ("Host PID namespace", 8),
    "host:network": ("Host network namespace", 6),
    "k8s:kubeconfig": ("Kubernetes API via kubeconfig", 8),
    "exec:shell": ("Shell command execution", 7),
    "exec:code": ("Arbitrary code execution", 7),
    "data:sql": ("SQL database access", 6),
    "net:http": ("Outbound HTTP requests", 3),
}

SECRET_SEVERITY = 5

_CRED_RE = re.compile(r"(key|token|secret|passw|pwd|credential|auth|private|dsn|conn)", re.I)
_NOT_CRED_RE = re.compile(r"(_FILE|_PATH|_URL_PATH|KEYBOARD|AUTHOR)$", re.I)
LLM_KEYS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY", "GOOGLE_API_KEY",
    "GEMINI_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY", "GROQ_API_KEY",
    "HUGGINGFACEHUB_API_TOKEN", "TOGETHER_API_KEY",
}


def is_credential_name(name: str) -> bool:
    return bool(_CRED_RE.search(name)) and not _NOT_CRED_RE.search(name)


@dataclass
class Node:
    id: str
    kind: str
    label: str
    severity: int = 0
    file: str | None = None
    line: int | None = None
    attrs: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        public = {k: v for k, v in self.attrs.items() if not k.startswith("_")}
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "severity": self.severity, "file": self.file, "line": self.line,
                "attrs": public}


@dataclass
class Edge:
    src: str
    dst: str
    rel: str
    file: str | None = None
    line: int | None = None
    transitive: bool = True

    def to_dict(self) -> dict:
        return {"source": self.src, "target": self.dst, "rel": self.rel,
                "file": self.file, "line": self.line, "transitive": self.transitive}


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.warnings: list[str] = []
        self.refs: list[tuple[str, str, str, str | None, int | None]] = []
        self._edge_keys: set[tuple[str, str, str]] = set()

    def add_node(self, id: str, kind: str, label: str, severity: int = 0,
                 file: str | None = None, line: int | None = None, **attrs) -> Node:
        assert kind in KINDS, kind
        node = self.nodes.get(id)
        if node is None:
            node = self.nodes[id] = Node(id, kind, label, severity, file, line)
        node.severity = max(node.severity, severity)
        if node.file is None:
            node.file, node.line = file, line
        for key, value in attrs.items():
            if isinstance(value, list) and isinstance(node.attrs.get(key), list):
                node.attrs[key] += [v for v in value if v not in node.attrs[key]]
            elif value is not None:
                node.attrs[key] = value
        return node

    def add_edge(self, src: str, dst: str, rel: str, file: str | None = None,
                 line: int | None = None, transitive: bool = True) -> None:
        key = (src, dst, rel)
        if key in self._edge_keys or src == dst:
            return
        self._edge_keys.add(key)
        self.edges.append(Edge(src, dst, rel, file, line, transitive))

    def add_ref(self, src: str, ref: str, rel: str, file: str | None, line: int | None) -> None:
        """An edge whose target is resolved by alias after every file is parsed."""
        self.refs.append((src, ref, rel, file, line))

    def capability(self, cap: str) -> str:
        label, severity = CAPABILITIES[cap]
        node_id = f"cap:{cap}"
        self.add_node(node_id, "resource", label, severity)
        return node_id

    def host_path(self, path: str, read_only: bool = False) -> str:
        """A host filesystem path mounted into a container."""
        if path.rstrip("/") in ("/var/run/docker.sock", "/run/docker.sock"):
            return self.capability("host:docker")
        if path in ("/", "/proc", "/sys", "/dev"):
            return self.capability("host:root")
        sensitive = re.match(r"^(/etc|/root|/home|/var/lib|/var/run|/run|~|\$HOME)", path)
        severity = (8 if sensitive else 4) - (2 if read_only else 0)
        mode = "ro" if read_only else "rw"
        node_id = f"hostpath:{mode}:{path}"
        self.add_node(node_id, "resource", f"Host path {path} ({mode})", severity)
        return node_id

    def fs_path(self, path: str, write: bool = True) -> str:
        """A filesystem root a tool can read or write."""
        broad = path in ("/", "~", "$HOME", ".") or re.match(r"^(/Users/[^/]+|/home/[^/]+|~)/?$", path)
        severity = (5 if write else 3) + (3 if broad else 0)
        mode = "write" if write else "read"
        node_id = f"fs:{mode}:{path}"
        self.add_node(node_id, "resource", f"Filesystem {mode}: {path}", severity)
        return node_id

    def env_secret(self, name: str, file: str | None, line: int | None, inline: bool = False) -> str:
        """A credential-looking environment variable, identified by name only."""
        node_id = f"secret:env:{name}"
        self.add_node(node_id, "secret", name, SECRET_SEVERITY, file, line, source="env var")
        if inline:
            self.nodes[node_id].attrs["inline_value_found"] = True
        return node_id

    def out_edges(self) -> dict[str, list[Edge]]:
        out: dict[str, list[Edge]] = {n: [] for n in self.nodes}
        for edge in self.edges:
            out.setdefault(edge.src, []).append(edge)
        return out

    def warn(self, message: str) -> None:
        self.warnings.append(message)
