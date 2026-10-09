import re
from dataclasses import dataclass
from typing import Protocol

from app.graph.schema import DATA_TYPES, Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity


class Analyzer(Protocol):
    def analyze(self, *, text: str, language: str): ...


@dataclass(frozen=True)
class Classification:
    tags: tuple[str, ...]
    sensitivity: Sensitivity
    basis: str = "metadata_heuristic"


RULES = {
    "PII": re.compile(
        r"\b(email|e-mail|ssn|social[_ -]?security|passport|phone|date[_ -]?of[_ -]?birth|dob)\b", re.I
    ),
    "PCI": re.compile(r"\b(card[_ -]?number|credit[_ -]?card|cvv|pan|payment[_ -]?card)\b", re.I),
    "PHI": re.compile(r"\b(patient|diagnosis|medical[_ -]?record|health[_ -]?record|prescription)\b", re.I),
    "Credentials": re.compile(r"\b(password|api[_ -]?key|private[_ -]?key|access[_ -]?token|secret)\b", re.I),
}


# Explicit classification tags (``data-class=PII``, ``Sensitivity=restricted``, ...): keys
# compared without case or separators, values split on separators and matched without case.
CLASSIFICATION_KEYS = frozenset({"dataclass", "dataclassification", "classification", "sensitivity"})
CLASSIFICATION_LABELS = {
    "pii": "PII",
    "phi": "PHI",
    "pci": "PCI",
    "credential": "Credentials",
    "credentials": "Credentials",
}
CLASSIFICATION_LEVELS = {"confidential": Sensitivity.CONFIDENTIAL, "restricted": Sensitivity.RESTRICTED}
_SEPARATORS = re.compile(r"[\s,;/|+]+")


def tag_classification(tags: list[tuple[str, str]]) -> tuple[set[str], Sensitivity | None]:
    """Labels and the highest explicit sensitivity level declared by classification tags."""
    labels: set[str] = set()
    levels: list[Sensitivity] = []
    for key, value in tags[:256]:
        if re.sub(r"[^a-z0-9]", "", str(key).lower()) not in CLASSIFICATION_KEYS:
            continue
        for token in _SEPARATORS.split(str(value).strip().lower()[:256]):
            if token in CLASSIFICATION_LABELS:
                labels.add(CLASSIFICATION_LABELS[token])
            elif token in CLASSIFICATION_LEVELS:
                levels.append(CLASSIFICATION_LEVELS[token])
    order = list(Sensitivity)
    return labels, (max(levels, key=order.index) if levels else None)


def build_presidio() -> Analyzer:
    from presidio_analyzer import AnalyzerEngine

    return AnalyzerEngine()


def classify_metadata(
    fields: list[str],
    analyzer: Analyzer | None = None,
    tags: list[tuple[str, str]] | None = None,
) -> Classification:
    """Labels from metadata words and, when given, explicit ``(key, value)`` classification tags."""
    # Only labels/schema metadata are accepted. Matched values are never returned or logged.
    text = " ".join(fields)[:20000]
    labels = {tag for tag, pattern in RULES.items() if pattern.search(text)}
    if analyzer is not None:
        for result in analyzer.analyze(text=text, language="en"):
            if result.score >= 0.6:
                labels.add("PII")
    declared, level = tag_classification(tags or [])
    labels |= declared
    sensitivity = (
        Sensitivity.RESTRICTED
        if labels & {"PHI", "PCI", "Credentials"}
        else (Sensitivity.CONFIDENTIAL if "PII" in labels else Sensitivity.INTERNAL)
    )
    if level is not None:
        order = list(Sensitivity)
        sensitivity = max(sensitivity, level, key=order.index)
    basis = "classification_tag" if declared or level is not None else "metadata_heuristic"
    return Classification(tuple(sorted(labels)), sensitivity, basis)


def enrich_node(
    node: Node,
    fields: list[str],
    analyzer: Analyzer | None = None,
    tags: list[tuple[str, str]] | None = None,
) -> Node:
    result = classify_metadata(fields, analyzer, tags)
    order = list(Sensitivity)
    sensitivity = max([node.sensitivity, result.sensitivity], key=order.index)
    return node.model_copy(
        update={
            "tags": sorted(set(node.tags) | set(result.tags)),
            "sensitivity": sensitivity,
            "metadata": {**node.metadata, "classification_basis": result.basis},
        }
    )


def classification_edges(snapshot: GraphSnapshot) -> GraphSnapshot:
    """Attach category annotations without turning data labels into access paths."""
    nodes = {node.id: node for node in snapshot.nodes}
    edges = {edge.id: edge for edge in snapshot.edges}
    for node in snapshot.nodes:
        if node.type not in DATA_TYPES:
            continue
        for tag in node.tags:
            if tag not in RULES:
                continue
            category_id = f"classification:{tag}"
            nodes[category_id] = Node(
                id=category_id,
                name=tag,
                type=NodeType.CATEGORY,
                provider="classification",
                sensitivity=node.sensitivity,
            )
            edge = Edge(
                source=node.id,
                target=category_id,
                type=EdgeType.PII,
                certainty="declared",
                evidence=["Metadata classification; validate against data contents"],
            )
            edges[edge.id] = edge
    return snapshot.model_copy(update={"nodes": list(nodes.values()), "edges": list(edges.values())})
