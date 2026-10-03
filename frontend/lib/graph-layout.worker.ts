import cytoscape from "cytoscape";
import type { LayoutInput } from "./graph-layout";
const scope = self as unknown as {
  onmessage: (event: MessageEvent<LayoutInput>) => void;
  postMessage: (data: unknown) => void;
};
scope.onmessage = ({ data }) => {
  if (
    !Array.isArray(data.nodes) ||
    !Array.isArray(data.edges) ||
    data.nodes.length > 500 ||
    data.edges.length > 2000
  ) {
    scope.postMessage([]);
    return;
  }
  const initial = data.nodes.map((id, i) => ({
    id,
    x: 250 * Math.cos((i * 2 * Math.PI) / Math.max(1, data.nodes.length)),
    y: 250 * Math.sin((i * 2 * Math.PI) / Math.max(1, data.nodes.length)),
  }));
  const graph = cytoscape({
    headless: true,
    styleEnabled: false,
    elements: [
      ...initial.map((p) => ({
        data: { id: p.id },
        position: { x: p.x, y: p.y },
      })),
      ...data.edges.map((e) => ({ data: e })),
    ],
  });
  try {
    graph
      .layout({
        name: "cose",
        randomize: false,
        animate: false,
        fit: false,
        numIter: 500,
        nodeRepulsion: () => 6000,
        idealEdgeLength: () => 100,
        componentSpacing: 80,
      })
      .run();
    scope.postMessage(
      graph
        .nodes()
        .map((n) => ({ id: n.id(), x: n.position("x"), y: n.position("y") })),
    );
  } finally {
    graph.destroy();
  }
};
