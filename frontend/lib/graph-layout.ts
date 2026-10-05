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

function visibleDegree(graph: GraphData): Map<string, number> {
  const degree = new Map(graph.nodes.map((n) => [n.id, 0]));
  for (const edge of graph.edges) {
    if (degree.has(edge.source))
      degree.set(edge.source, degree.get(edge.source)! + 1);
    if (degree.has(edge.target))
      degree.set(edge.target, degree.get(edge.target)! + 1);
  }
  return degree;
}

/** Label priority within this visible slice only; never a global importance score. */
export function overviewAnchors(graph: GraphData): Set<string> {
  const degree = visibleDegree(graph);
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

/** Small slices label every node at overview zoom; larger ones label anchors only. */
export const OVERVIEW_ALL_LABELS_MAX_NODES = 80;
/** Above this zoom every node becomes a label candidate. */
export const DETAIL_ZOOM = 1.35;

/**
 * Ordered label candidates for the current view. Earlier ids win collisions.
 * `required` labels (the focused node and its neighborhood) are always shown.
 */
export function labelCandidates(
  graph: GraphData & { view?: { mode: "sample" | "neighborhood" | "roles" } },
  anchors: Set<string>,
  state: { zoom: number; focus: string | null; neighbors?: Iterable<string> },
): { order: string[]; required: Set<string> } {
  if (state.focus) {
    const required = new Set([state.focus, ...(state.neighbors ?? [])]);
    return { order: [...required], required };
  }
  const degree = visibleDegree(graph);
  const rest = graph.nodes
    .filter((n) => !anchors.has(n.id))
    .sort(
      (a, b) =>
        degree.get(b.id)! - degree.get(a.id)! || a.id.localeCompare(b.id),
    )
    .map((n) => n.id);
  const detail = state.zoom > DETAIL_ZOOM;
  const small =
    graph.view?.mode !== "roles" &&
    graph.nodes.length <= OVERVIEW_ALL_LABELS_MAX_NODES;
  return {
    order: detail || small ? [...anchors, ...rest] : [...anchors],
    required: new Set(),
  };
}

/** Upper bound on a label's model-space font size, so far-out zoom shrinks text instead of drawing huge glyphs. */
const MAX_LABEL_SCALE = 4.5;

/** Model-space font size that renders at `px` screen pixels at this zoom. */
export function labelFontSize(px: number, zoom: number): number {
  if (!(zoom > 0)) return px;
  return Math.min(px * MAX_LABEL_SCALE, px / zoom);
}

export interface LabelBounds {
  id: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

function validBox(box: LabelBounds): boolean {
  return (
    [box.x1, box.y1, box.x2, box.y2].every(Number.isFinite) &&
    box.x2 > box.x1 &&
    box.y2 > box.y1
  );
}

function overlaps(a: LabelBounds, b: LabelBounds, gap: number): boolean {
  return (
    a.x1 < b.x2 + gap &&
    a.x2 + gap > b.x1 &&
    a.y1 < b.y2 + gap &&
    a.y2 + gap > b.y1
  );
}

/**
 * Greedy visible-priority labels using actual rendered bounds, with breathing room.
 * Required labels are always kept; optional labels must fit inside the viewport,
 * clear every kept label, and not cover another node (`obstacles`, keyed by node id).
 */
export function spacedLabels(
  labels: LabelBounds[],
  width: number,
  height: number,
  options: { required?: Set<string>; obstacles?: LabelBounds[] } = {},
): Set<string> {
  const required = options.required ?? new Set<string>();
  const obstacles = (options.obstacles ?? []).filter(validBox);
  const chosen: LabelBounds[] = labels.filter(
    (box) => required.has(box.id) && validBox(box),
  );
  for (const box of labels) {
    if (
      required.has(box.id) ||
      !validBox(box) ||
      box.x1 < 0 ||
      box.y1 < 0 ||
      box.x2 > width ||
      box.y2 > height
    )
      continue;
    if (chosen.some((other) => overlaps(box, other, 6))) continue;
    if (obstacles.some((node) => node.id !== box.id && overlaps(box, node, 2)))
      continue;
    chosen.push(box);
  }
  return new Set(chosen.map((box) => box.id));
}

export interface Bounds {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

/** Highest zoom a fit may reach, so small slices keep labels and dots in proportion to the UI. */
export const MAX_FIT_ZOOM = 1.2;

/**
 * Fit node bounds into the canvas, leaving room for the labels drawn under nodes,
 * the overlaid legend and controls, and capping zoom for small slices.
 */
export function fitViewport(
  nodes: Bounds,
  width: number,
  height: number,
  minZoom = 0.05,
): { zoom: number; pan: { x: number; y: number } } {
  const narrow = width < 700;
  const side = narrow ? 48 : 84; // about half the widest label, plus a gutter
  const top = 28;
  const bottom = narrow ? 64 : 72; // label line under the lowest node plus the legend
  const w = Math.max(1, nodes.x2 - nodes.x1);
  const h = Math.max(1, nodes.y2 - nodes.y1);
  const usableW = Math.max(1, width - 2 * side);
  const usableH = Math.max(1, height - top - bottom);
  const zoom = Math.max(
    minZoom,
    Math.min(MAX_FIT_ZOOM, usableW / w, usableH / h),
  );
  const cx = (nodes.x1 + nodes.x2) / 2;
  const cy = (nodes.y1 + nodes.y2) / 2;
  return {
    zoom,
    pan: {
      x: side + usableW / 2 - cx * zoom,
      y: top + usableH / 2 - cy * zoom,
    },
  };
}
