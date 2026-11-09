from zerograph.blast import blast_radius, rank_agents, rating
from zerograph.model import Graph


def build():
    g = Graph()
    g.add_node("a1", "agent", "big")
    g.add_node("a2", "agent", "small")
    g.add_node("t", "tool", "shell tool")
    g.add_node("svc", "identity", "service")
    g.add_node("other", "identity", "other service")
    g.add_node("net", "resource", "network", 2)
    root = g.capability("host:root")
    shell = g.capability("exec:shell")
    sec = g.env_secret("API_KEY", "f.yml", 3)
    g.add_edge("a1", "t", "can call", "a.py", 10)
    g.add_edge("t", shell, "runs", "a.py", 11)
    g.add_edge("a1", "svc", "runs as", "compose.yml", 4)
    g.add_edge("svc", sec, "holds", "compose.yml", 6)
    g.add_edge("svc", "net", "attached to", "compose.yml", 7)
    g.add_edge("net", "other", "can reach", "compose.yml", 9, transitive=False)
    g.add_edge("other", root, "privileged", "compose.yml", 12)
    g.add_edge("a2", sec, "holds", "x.yml", 1)
    return g


def test_transitive_reach_and_score():
    g = build()
    r = blast_radius(g, "a1")
    assert set(r["reachable"]) == {"t", "cap:exec:shell", "svc", "secret:env:API_KEY", "net", "other"}
    # The network edge reaches `other` but does not inherit its privileged flag.
    assert "cap:host:root" not in r["reachable"]
    assert r["score"] == 7 + 5 + 2
    assert r["max_severity"] == 7 and r["rating"] == "high"


def test_findings_are_ordered_with_evidence_paths():
    r = blast_radius(build(), "a1")
    assert [f["severity"] for f in r["findings"]] == [7, 5, 2]
    shell = r["findings"][0]
    assert [s["evidence"] for s in shell["path"]] == ["a.py:10", "a.py:11"]


def test_ranking():
    ranked = rank_agents(build())
    assert [r["label"] for r in ranked] == ["big", "small"]
    assert ranked[1]["score"] == 5


def test_cycles_terminate():
    g = Graph()
    g.add_node("a", "agent", "a")
    g.add_node("b", "identity", "b")
    g.add_edge("a", "b", "x")
    g.add_edge("b", "a", "y")
    assert blast_radius(g, "a")["reachable"] == ["b"]


def test_rating_scale():
    assert [rating(s) for s in (10, 9, 8, 7, 5, 4, 3, 0)] == [
        "critical", "critical", "high", "high", "medium", "medium", "low", "low"]
