import hashlib

from pydantic import BaseModel

from app.engine.analysis_index import AnalysisIndex
from app.graph.schema import DATA_TYPES, GraphSnapshot, Sensitivity


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    source: str
    target: str
    path: list[str]
    evidence: list[str]
    conditional: bool
    recommendation: str


def detect(snapshot: GraphSnapshot, index: AnalysisIndex | None = None) -> list[Finding]:
    prepared = index or AnalysisIndex.build(snapshot, include_uncertain=True)
    prepared.validate_for(snapshot, True)
    nodes = prepared.nodes
    findings = []
    for source in snapshot.nodes:
        if not source.internet_exposed or source.authenticated:
            continue
        paths = prepared.paths(source.id, 5)
        for target_id, path in paths.items():
            target = nodes[target_id]
            if target.type not in DATA_TYPES:
                continue
            privileged = any(nodes[n].privileged for n in path)
            sensitive = target.sensitivity in {Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED}
            if not (sensitive or not target.encrypted):
                continue
            matched = []
            uncertain = False
            for a, b in zip(path, path[1:], strict=False):
                candidates = prepared.edge_pairs.get((a, b), [])
                confirmed = [e for e in candidates if e.certainty == "confirmed"]
                chosen = confirmed or candidates
                uncertain |= not bool(confirmed)
                matched.extend(item for e in chosen for item in e.evidence)
            risk = (
                "Privileged agent access to sensitive data"
                if privileged
                else "Exposed agent access to sensitive data"
            )
            findings.append(
                Finding(
                    id=hashlib.sha256((source.id + "\0" + target_id).encode()).hexdigest()[:20],
                    title=risk,
                    severity="critical" if privileged and not uncertain else "high",
                    source=source.id,
                    target=target_id,
                    path=path,
                    evidence=["Public endpoint is declared unauthenticated", *matched[:20]],
                    conditional=uncertain,
                    recommendation="Authenticate the entry point, restrict role trust and tool scope, and review data access permissions.",
                )
            )
    return sorted(findings, key=lambda f: (f.severity != "critical", f.id))
