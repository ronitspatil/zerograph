import cytoscape from "cytoscape";
import type { LayoutInput, Position } from "./graph-layout";

export function computePositions(data: LayoutInput): Position[] {
  const initial = data.nodes.map((id, i) => ({
    id,
    x: 250 * Math.cos((i * 2 * Math.PI) / Math.max(1, data.nodes.length)),
    y: 250 * Math.sin((i * 2 * Math.PI) / Math.max(1, data.nodes.length)),
  }));
  const graph = cytoscape({
    headless: true,
    styleEnabled: true,
    style: [{ selector: "node", style: { width: 38, height: 38 } }],
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
        boundingBox: { x1: 0, y1: 0, w: 1000, h: 700 },
        randomize: false,
        animate: false,
        fit: false,
        numIter: 500,
        nodeRepulsion: () => 6000,
        idealEdgeLength: () => 100,
        componentSpacing: 80,
      })
      .run();
    return graph
      .nodes()
      .map((n) => ({ id: n.id(), x: n.position("x"), y: n.position("y") }));
  } finally {
    graph.destroy();
  }
}
