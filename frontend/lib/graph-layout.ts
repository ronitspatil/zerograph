import { formatCount } from "./format";
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
  /** "packed" fills a disc for in-place cluster expansion; default: role constellations. */
  mode?: "constellations" | "packed";
}
export interface LayoutLimits {
  nodes: number;
  edges: number;
}
/** Explorer and detail views (canvas renderer, readable labels). */
export const EXPLORE_LIMITS: LayoutLimits = { nodes: 500, edges: 2000 };
/** Global-map members shown in place (WebGL renderer). */
export const MEMBER_LIMITS: LayoutLimits = { nodes: 5000, edges: 20000 };
export function layoutLimits(input: Pick<LayoutInput, "mode">): LayoutLimits {
  return input.mode === "packed" ? MEMBER_LIMITS : EXPLORE_LIMITS;
}
export function layoutInput(
  graph: GraphData,
  limits: LayoutLimits = EXPLORE_LIMITS,
): LayoutInput | null {
  if (graph.nodes.length > limits.nodes || graph.edges.length > limits.edges)
    return null;
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
  /** Called once when the worker ends without valid positions (error, timeout, bad output). */
  fail?: () => void,
): () => void {
  const limits = layoutLimits(input);
  if (input.nodes.length > limits.nodes || input.edges.length > limits.edges)
    return () => {};
  let active = true;
  let applied = false;
  let worker: LayoutWorker;
  try {
    worker = factory();
  } catch {
    fail?.();
    return () => {};
  }
  const stop = () => {
    if (!active) return;
    active = false;
    if (!applied) queueMicrotask(() => fail?.());
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
    ) {
      applied = true;
      apply(positions as Position[]);
    }
    stop();
  };
  worker.onerror = stop;
  try {
    worker.postMessage(input);
  } catch {
    stop();
  }
  // The caller cancelling is not a failure.
  return () => {
    applied = true;
    stop();
  };
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

/** Small slices label every node at overview zoom; larger ones label a spread-out selection. */
export const OVERVIEW_ALL_LABELS_MAX_NODES = 80;
/** Above this zoom every node becomes a label candidate. */
export const DETAIL_ZOOM = 1.35;
/**
 * Screen cell, in pixels, that holds at most one overview label candidate:
 * about one label wide and a few lines tall, so candidates cover every region
 * of the slice (the dense core and its satellites) instead of piling up on hubs.
 */
export const LABEL_CELL = { width: 150, height: 56 };
/**
 * Overview labels on wide and narrow canvases: `limit` caps how many show, and
 * `backdrops` how many may sit over other dots (a dense core's hubs), drawn on
 * a backdrop.
 */
export const OVERVIEW_LABELS = {
  wide: { limit: 22, backdrops: 3 },
  narrow: { limit: 8, backdrops: 4 },
};

const DATA_STORES = new Set(["Database", "VectorStore", "S3Bucket"]);

/**
 * Overview label priority within this visible slice: visible degree (the hubs
 * of each region), boosted for what an operator scans for first: nodes on a
 * finding path, exposed agents and MCP servers, and sensitive data stores.
 * Never a global importance score.
 */
export function labelPriority(
  graph: GraphData,
  risk: Set<string> = new Set(),
): Map<string, number> {
  const degree = visibleDegree(graph);
  return new Map(
    graph.nodes.map((n) => {
      let score = degree.get(n.id)!;
      if (risk.has(n.id)) score += 3;
      if (n.type === "AIAgent" || n.type === "MCPServer")
        score += n.internet_exposed ? 3 : 1;
      if (
        DATA_STORES.has(n.type) &&
        (n.sensitivity === "restricted" || n.sensitivity === "confidential")
      )
        score += 2;
      if (n.privileged) score += 1;
      return [n.id, score];
    }),
  );
}

/**
 * One candidate per grid cell (the highest-priority node in it), ordered by
 * priority. `cell` is in the same units as the positions; cells are anchored at
 * the model origin, so panning never reshuffles the choice.
 */
export function spreadCandidates(
  positions: Position[],
  priority: Map<string, number>,
  cell: { width: number; height: number },
): string[] {
  const rank = (id: string) => priority.get(id) ?? 0;
  const better = (a: string, b: string) =>
    rank(a) - rank(b) || b.localeCompare(a);
  const best = new Map<string, string>();
  for (const p of positions) {
    if (!Number.isFinite(p.x) || !Number.isFinite(p.y)) continue;
    const key = `${Math.floor(p.x / cell.width)}:${Math.floor(p.y / cell.height)}`;
    const current = best.get(key);
    if (current === undefined || better(p.id, current) > 0) best.set(key, p.id);
  }
  return [...best.values()].sort((a, b) => better(b, a));
}

/**
 * Ordered label candidates for the current view. Earlier ids win collisions.
 * `required` labels (the focused node and its neighborhood) are always shown;
 * With `positions` (model coordinates), large overview slices pick candidates
 * spread across the canvas (`spread`: show them with OVERVIEW_LABELS);
 * without positions they fall back to the role anchors.
 */
export function labelCandidates(
  graph: GraphData & { view?: { mode: "sample" | "neighborhood" | "roles" } },
  anchors: Set<string>,
  state: {
    zoom: number;
    focus: string | null;
    neighbors?: Iterable<string>;
    positions?: Position[];
    risk?: Set<string>;
  },
): {
  order: string[];
  required: Set<string>;
  spread: boolean;
} {
  if (state.focus) {
    const required = new Set([state.focus, ...(state.neighbors ?? [])]);
    return { order: [...required], required, spread: false };
  }
  const degree = visibleDegree(graph);
  const detail = state.zoom > DETAIL_ZOOM;
  const small =
    graph.view?.mode !== "roles" &&
    graph.nodes.length <= OVERVIEW_ALL_LABELS_MAX_NODES;
  if (detail || small) {
    const rest = graph.nodes
      .filter((n) => !anchors.has(n.id))
      .sort(
        (a, b) =>
          degree.get(b.id)! - degree.get(a.id)! || a.id.localeCompare(b.id),
      )
      .map((n) => n.id);
    return {
      order: [...anchors, ...rest],
      required: new Set(),
      spread: false,
    };
  }
  if (!state.positions || !(state.zoom > 0))
    return {
      order: [...anchors],
      required: new Set(),
      spread: false,
    };
  const order = spreadCandidates(
    state.positions,
    labelPriority(graph, state.risk),
    {
      width: LABEL_CELL.width / state.zoom,
      height: LABEL_CELL.height / state.zoom,
    },
  );
  return {
    order,
    required: new Set(),
    spread: true,
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

/** True when a label box touches any screen overlay (legend, controls, status chips). */
export function underOverlay(
  box: LabelBounds,
  blocked: LabelBounds[],
): boolean {
  return blocked.some(
    (overlay) => validBox(overlay) && overlaps(box, overlay, 0),
  );
}

/**
 * Greedy visible-priority labels using actual rendered bounds, with breathing room.
 * Required labels are kept unless they would sit under a screen overlay
 * (`blocked`: legend, zoom controls); optional labels must also fit inside the
 * viewport, clear every kept label, and not cover another node (`obstacles`,
 * keyed by node id); the first `backdrops` optional labels that would cover a
 * node are kept anyway, for a caller that draws them on a backdrop. At most
 * `limit` optional labels are kept.
 */
export function spacedLabels(
  labels: LabelBounds[],
  width: number,
  height: number,
  options: {
    required?: Set<string>;
    obstacles?: LabelBounds[];
    blocked?: LabelBounds[];
    backdrops?: number;
    limit?: number;
  } = {},
): Set<string> {
  const required = options.required ?? new Set<string>();
  let backdrops = options.backdrops ?? 0;
  let room = options.limit ?? Infinity;
  const obstacles = (options.obstacles ?? []).filter(validBox);
  const blocked = options.blocked ?? [];
  const chosen: LabelBounds[] = labels.filter(
    (box) =>
      required.has(box.id) && validBox(box) && !underOverlay(box, blocked),
  );
  for (const box of labels) {
    if (room <= 0) break;
    if (
      required.has(box.id) ||
      !validBox(box) ||
      box.x1 < 0 ||
      box.y1 < 0 ||
      box.x2 > width ||
      box.y2 > height
    )
      continue;
    if (underOverlay(box, blocked)) continue;
    if (chosen.some((other) => overlaps(box, other, 6))) continue;
    if (
      obstacles.some((node) => node.id !== box.id && overlaps(box, node, 0))
    ) {
      if (backdrops <= 0) continue;
      backdrops--;
    }
    chosen.push(box);
    room--;
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
export const MAX_FIT_ZOOM = 1.8;

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

/** Explains a visible slice with entities but no relationships among them; else null. */
export function relationshipHint(
  graph: Pick<GraphData, "nodes" | "edges"> & {
    view?: { mode: "sample" | "neighborhood" | "roles" };
  },
): string | null {
  const count = graph.nodes.length;
  if (!count || graph.edges.length) return null;
  if (graph.view?.mode === "roles")
    return count === 1
      ? "This role has no direct role links in this view."
      : `These ${formatCount(count)} roles have no direct role links between them in this view.`;
  const subject =
    count === 1
      ? "This entity has no relationships in this view."
      : `These ${formatCount(count)} entities have no relationships between them in this view.`;
  return `${subject} Search for an entity or open a neighborhood to see its connections.`;
}
