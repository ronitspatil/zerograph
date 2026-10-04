import type { GraphData } from "./types";
export interface Position {
  id: string;
  x: number;
  y: number;
}
export interface LayoutInput {
  nodes: string[];
  edges: { id: string; source: string; target: string }[];
  attributes?: Record<string, { type: string; account: string }>;
}
export function layoutInput(graph: GraphData): LayoutInput | null {
  if (graph.nodes.length > 500 || graph.edges.length > 2000) return null;
  const ids = new Set(graph.nodes.map((n) => n.id));
  if (
    ids.size !== graph.nodes.length ||
    graph.edges.some((e) => !ids.has(e.source) || !ids.has(e.target))
  )
    return null;
  return {
    nodes: graph.nodes.map((n) => n.id),
    attributes: Object.fromEntries(
      graph.nodes.map((n) => [n.id, { type: n.type, account: n.account_id }]),
    ),
    edges: graph.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
    })),
  };
}
export function circlePositions(ids: string[]): Position[] {
  return ids.map((id, i) => ({
    id,
    x: 250 * Math.cos((i * 2 * Math.PI) / Math.max(1, ids.length)),
    y: 250 * Math.sin((i * 2 * Math.PI) / Math.max(1, ids.length)),
  }));
}
export interface LayoutWorker {
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  postMessage: (input: LayoutInput) => void;
  terminate: () => void;
}
export function startLayout(
  input: LayoutInput,
  apply: (positions: Position[]) => void,
  factory: () => LayoutWorker = () =>
    new Worker(
      new URL("./graph-layout.worker.ts", import.meta.url),
    ) as unknown as LayoutWorker,
): () => void {
  if (input.nodes.length > 500 || input.edges.length > 2000) return () => {};
  let active = true;
  let worker: LayoutWorker;
  try {
    worker = factory();
  } catch {
    return () => {};
  }
  const stop = () => {
    if (!active) return;
    active = false;
    clearTimeout(timer);
    worker.onmessage = null;
    worker.onerror = null;
    worker.terminate();
  };
  const timer = setTimeout(stop, 10000);
  worker.onmessage = (event) => {
    if (!active) return;
    const positions: unknown = event.data;
    const ids = new Set(input.nodes);
    if (
      Array.isArray(positions) &&
      positions.length === ids.size &&
      positions.every(
        (p) =>
          p &&
          typeof p.id === "string" &&
          ids.delete(p.id) &&
          Number.isFinite(p.x) &&
          Number.isFinite(p.y),
      )
    )
      apply(positions as Position[]);
    stop();
  };
  worker.onerror = stop;
  try {
    worker.postMessage(input);
  } catch {
    stop();
  }
  return stop;
}

/** Label priority within this visible slice only; never a global importance score. */
export function overviewAnchors(graph: GraphData): Set<string> {
  const degree = new Map(graph.nodes.map((n) => [n.id, 0]));
  for (const edge of graph.edges) {
    if (degree.has(edge.source))
      degree.set(edge.source, degree.get(edge.source)! + 1);
    if (degree.has(edge.target))
      degree.set(edge.target, degree.get(edge.target)! + 1);
  }
  return new Set(
    graph.nodes
      .filter((n) => n.type === "CloudRole")
      .sort(
        (a, b) =>
          degree.get(b.id)! - degree.get(a.id)! || a.id.localeCompare(b.id),
      )
      .slice(0, 16)
      .map((n) => n.id),
  );
}

export interface LabelBounds {
  id: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

/** Greedy visible-priority labels using actual rendered bounds, with breathing room. */
export function spacedLabels(
  labels: LabelBounds[],
  width: number,
  height: number,
): Set<string> {
  const chosen: LabelBounds[] = [];
  for (const box of labels) {
    if (
      ![box.x1, box.y1, box.x2, box.y2].every(Number.isFinite) ||
      box.x1 < 0 ||
      box.y1 < 0 ||
      box.x2 > width ||
      box.y2 > height ||
      box.x2 <= box.x1 ||
      box.y2 <= box.y1
    )
      continue;
    if (
      chosen.some(
        (other) =>
          box.x1 < other.x2 + 6 &&
          box.x2 + 6 > other.x1 &&
          box.y1 < other.y2 + 6 &&
          box.y2 + 6 > other.y1,
      )
    )
      continue;
    chosen.push(box);
  }
  return new Set(chosen.map((box) => box.id));
}
