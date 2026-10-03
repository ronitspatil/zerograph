import type { GraphData } from "./types";
export interface Position {
  id: string;
  x: number;
  y: number;
}
export interface LayoutInput {
  nodes: string[];
  edges: { id: string; source: string; target: string }[];
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
