"""JSON, HTML and terminal output."""

from __future__ import annotations

import json
from importlib import resources

from . import __version__
from .blast import all_radii, rank_agents
from .model import Graph


def to_dict(g: Graph, radii: dict | None = None) -> dict:
    radii = radii if radii is not None else all_radii(g)
    nodes = []
    for node in g.nodes.values():
        item = node.to_dict()
        item["blast_score"] = radii[node.id]["score"]
        nodes.append(item)
    return {
        "zerograph": __version__,
        "agents": rank_agents(g),
        "nodes": nodes,
        "edges": [e.to_dict() for e in g.edges],
        "warnings": g.warnings,
    }


def to_json(g: Graph) -> str:
    return json.dumps(to_dict(g), indent=2)


def to_html(g: Graph, title: str = "ZeroGraph") -> str:
    radii = all_radii(g)
    data = to_dict(g, radii)
    data["radii"] = {k: {key: v[key] for key in ("score", "rating", "reachable", "edges", "findings")}
                     for k, v in radii.items() if v["reachable"]}
    payload = json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = resources.files("zerograph").joinpath("report.html").read_text(encoding="utf-8")
    safe_title = title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return template.replace("__TITLE__", safe_title).replace("__DATA__", payload)


def summary(g: Graph) -> str:
    ranked = rank_agents(g)
    kinds = {}
    for node in g.nodes.values():
        kinds[node.kind] = kinds.get(node.kind, 0) + 1
    plural = {"agent": "agents", "identity": "identities", "tool": "tools", "secret": "secrets",
              "resource": "privileges"}
    counts = ", ".join(f"{kinds.get(k, 0)} {name}" for k, name in plural.items())
    lines = [f"{len(g.nodes)} nodes ({counts}), {len(g.edges)} edges", ""]
    if not ranked:
        lines.append("No agents found.")
        return "\n".join(lines)
    rows = [("#", "AGENT", "SCORE", "RATING", "WORST REACHABLE")]
    for i, r in enumerate(ranked, 1):
        worst = r["findings"][0]["label"] if r["findings"] else "-"
        rows.append((str(i), r["label"], str(r["score"]), r["rating"], worst))
    widths = [min(max(len(row[c]) for row in rows), 48) for c in range(4)]
    for row in rows:
        cells = [row[c][:widths[c]].ljust(widths[c]) for c in range(4)]
        lines.append("  ".join(cells + [row[4]]).rstrip())
    return "\n".join(lines)
