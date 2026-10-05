import type { LabelBounds, Position } from "./graph-layout";
import type { ClusterLink, ClusterSummary } from "./types";

/** Server bounds: at most 300 clusters per level and 2000 links per response. */
export const MAX_CLUSTER_NODES = 300;
export const MAX_CLUSTER_LINKS = 2000;
const MIN_DIAMETER = 14;
const MAX_DIAMETER = 76;

/** Model-space diameter: area grows with member count, between 14 and 76. */
export function clusterDiameter(size: number, largest: number): number {
  if (!(largest > 1) || !(size > 1)) return MIN_DIAMETER;
  const share = Math.sqrt((Math.min(size, largest) - 1) / (largest - 1));
  return MIN_DIAMETER + (MAX_DIAMETER - MIN_DIAMETER) * share;
}

/** Link stroke width: logarithmic in relationship count, 0.6 to 6. */
export function linkWidth(weight: number, heaviest: number): number {
  if (!(heaviest > 1) || !(weight > 1)) return 0.6;
  return 0.6 + 5.4 * (Math.log(weight) / Math.log(heaviest));
}

/** Valid, bounded input or null (the caller shows an explicit bounds message). */
export function clusterLayoutInput(
  clusters: ClusterSummary[],
  links: ClusterLink[],
): { clusters: ClusterSummary[]; links: ClusterLink[] } | null {
  if (clusters.length > MAX_CLUSTER_NODES || links.length > MAX_CLUSTER_LINKS)
    return null;
  const ids = new Set(clusters.map((c) => c.id));
  if (ids.size !== clusters.length) return null;
  return {
    clusters,
    links: links.filter(
      (l) => ids.has(l.source) && ids.has(l.target) && l.source !== l.target,
    ),
  };
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/**
 * Deterministic layout for at most 300 super-nodes: the largest clusters start
 * near the centre on a golden-angle spiral, linked clusters are pulled together
 * (by log link weight), and overlaps are pushed apart so every circle and its
 * label stays legible. Pure and bounded (O(iterations x n^2), n <= 300).
 */
export function clusterPositions(
  clusters: ClusterSummary[],
  links: ClusterLink[],
  iterations = 80,
): Position[] {
  const n = clusters.length;
  if (!n) return [];
  const largest = Math.max(...clusters.map((c) => c.size));
  const order = clusters
    .map((c, i) => ({ c, i }))
    .sort((a, b) => b.c.size - a.c.size || a.c.id.localeCompare(b.c.id));
  const radius = clusters.map((c) => clusterDiameter(c.size, largest) / 2);
  const x = new Float64Array(n);
  const y = new Float64Array(n);
  const spacing =
    order.reduce((sum, { i }) => sum + radius[i], 0) / n + MIN_DIAMETER;
  order.forEach(({ i }, rank) => {
    const r = spacing * 1.6 * Math.sqrt(rank);
    x[i] = r * Math.cos(rank * GOLDEN_ANGLE);
    y[i] = r * Math.sin(rank * GOLDEN_ANGLE);
  });
  const index = new Map(clusters.map((c, i) => [c.id, i]));
  const heaviest = Math.max(1, ...links.map((l) => l.weight));
  const springs = links
    .map((l) => ({
      a: index.get(l.source)!,
      b: index.get(l.target)!,
      w: 0.02 + 0.08 * (Math.log(1 + l.weight) / Math.log(1 + heaviest)),
    }))
    .filter(({ a, b }) => a !== undefined && b !== undefined);
  // Room for a label under one circle and above the next; small levels, which
  // show every label, get more.
  const gap = n < 40 ? 26 + 30 * (1 - n / 40) : 26;
  const separate = (): boolean => {
    let moved = false;
    for (let a = 0; a < n; a++) {
      for (let b = a + 1; b < n; b++) {
        let dx = x[b] - x[a];
        let dy = y[b] - y[a];
        const need = radius[a] + radius[b] + gap;
        let distance = Math.hypot(dx, dy);
        if (distance >= need) continue;
        if (distance < 1e-6) {
          // Deterministic separation for coincident centres.
          dx = Math.cos(a + b);
          dy = Math.sin(a + b);
          distance = 1;
        }
        const push = (need - distance) / 2 / distance;
        moved = true;
        x[a] -= dx * push;
        y[a] -= dy * push;
        x[b] += dx * push;
        y[b] += dy * push;
      }
    }
    return moved;
  };
  for (let step = 0; step < iterations; step++) {
    const cool = 1 - step / iterations;
    for (const { a, b, w } of springs) {
      const dx = x[b] - x[a];
      const dy = y[b] - y[a];
      const rest = radius[a] + radius[b] + gap * 2;
      const distance = Math.hypot(dx, dy) || 1;
      if (distance <= rest) continue;
      const pull = ((distance - rest) * w * cool) / distance;
      x[a] += dx * pull;
      y[a] += dy * pull;
      x[b] -= dx * pull;
      y[b] -= dy * pull;
    }
    separate();
  }
  // Springs can win against overlap pushes in dense levels: finish with overlap-only passes.
  for (let pass = 0; pass < 60; pass++) if (!separate()) break;
  return clusters.map((c, i) => ({ id: c.id, x: x[i], y: y[i] }));
}

const KIND_NOTES: Record<ClusterSummary["kind"], string> = {
  community: "Densely connected group",
  isolated: "Entities with no relationships",
  group: "Several small groups packed together",
  part: "Part of a larger group",
  range: "Range of groups",
};

export function kindNote(kind: ClusterSummary["kind"]): string {
  return KIND_NOTES[kind] ?? "Group";
}

/** Largest facets first, then the rest summed, for a compact sidebar list. */
export function topFacets(
  facets: Record<string, number>,
  limit = 5,
): { name: string; count: number }[] {
  const ranked = Object.entries(facets)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  if (ranked.length <= limit) return ranked;
  const rest = ranked.slice(limit - 1).reduce((sum, f) => sum + f.count, 0);
  return [...ranked.slice(0, limit - 1), { name: "Other", count: rest }];
}

/** Cluster labels render at this fixed screen size at every zoom. */
export const LABEL_FONT_PX = 12;
/** Longest label line before an ellipsis, in screen pixels. */
export const LABEL_MAX_WIDTH = 170;
/** Label line height under a circle (text, backdrop padding and margin). */
export const LABEL_LINE = 22;

/** Estimated rendered width of a 12px label (used when the canvas cannot measure). */
export function estimateLabelWidth(label: string): number {
  return Math.min(LABEL_MAX_WIDTH, 6.6 * label.length + 6);
}

/** Screen box of a cluster label drawn under (or above) its circle (12px text, at most 170px wide). */
export function clusterLabelBox(
  id: string,
  width: number,
  x: number,
  y: number,
  diameter: number,
  side: LabelSide = "below",
): LabelBounds {
  const w = Math.min(LABEL_MAX_WIDTH, width) + 6;
  const top =
    side === "below" ? y + diameter / 2 + 3 : y - diameter / 2 - 3 - 17;
  return { id, x1: x - w / 2, y1: top, x2: x + w / 2, y2: top + 17 };
}

export type LabelSide = "below" | "above";

/**
 * Collision-aware labels in priority order (largest cluster first), with the
 * rules of `spacedLabels`: required labels (hovered, selected) are always shown
 * below their circle; any other label must fit inside the canvas and keep 6px
 * from every placed label. In addition a label never covers the circle of a
 * cluster that ranks before it (`obstacles`, keyed by cluster id; `rank` gives the
 * priority of every cluster), so a small cluster's label cannot hide a larger
 * cluster, while the largest clusters stay labeled in dense levels. A label that
 * does not fit below its circle tries above it.
 */
export function placeLabels(
  candidates: { id: string; below: LabelBounds; above: LabelBounds }[],
  width: number,
  height: number,
  options: {
    required?: Set<string>;
    obstacles?: LabelBounds[];
    rank?: Map<string, number>;
  } = {},
): Map<string, LabelSide> {
  const required = options.required ?? new Set<string>();
  const obstacles = (options.obstacles ?? []).filter(validBox);
  const rank = options.rank ?? new Map<string, number>();
  const rankOf = (id: string) => rank.get(id) ?? Number.MAX_SAFE_INTEGER;
  const placed = new Map<string, LabelSide>();
  const chosen: LabelBounds[] = [];
  for (const c of candidates)
    if (required.has(c.id) && validBox(c.below)) {
      placed.set(c.id, "below");
      chosen.push(c.below);
    }
  const fits = (box: LabelBounds) => {
    if (
      !validBox(box) ||
      box.x1 < 0 ||
      box.y1 < 0 ||
      box.x2 > width ||
      box.y2 > height ||
      chosen.some((other) => boxesOverlap(box, other, 6))
    )
      return false;
    const own = rankOf(box.id);
    return !obstacles.some(
      (node) =>
        node.id !== box.id &&
        rankOf(node.id) < own &&
        boxesOverlap(box, node, 0),
    );
  };
  for (const c of candidates) {
    if (placed.has(c.id)) continue;
    for (const side of ["below", "above"] as const)
      if (fits(c[side])) {
        placed.set(c.id, side);
        chosen.push(c[side]);
        break;
      }
  }
  return placed;
}

function validBox(box: LabelBounds): boolean {
  return (
    [box.x1, box.y1, box.x2, box.y2].every(Number.isFinite) &&
    box.x2 > box.x1 &&
    box.y2 > box.y1
  );
}

function boxesOverlap(a: LabelBounds, b: LabelBounds, gap: number): boolean {
  return (
    a.x1 < b.x2 + gap &&
    a.x2 + gap > b.x1 &&
    a.y1 < b.y2 + gap &&
    a.y2 + gap > b.y1
  );
}

/**
 * Screen box a label must not cover: the square inscribed in another cluster's
 * circle. Only circles at least `minDiameter` on screen count; smaller dots may
 * sit under a label's backdrop.
 */
export function circleObstacle(
  id: string,
  x: number,
  y: number,
  diameter: number,
  minDiameter = 16,
): LabelBounds | null {
  if (!(diameter >= minDiameter)) return null;
  const half = (diameter / 2) * Math.SQRT1_2;
  return { id, x1: x - half, y1: y - half, x2: x + half, y2: y + half };
}

/** Labels offered at a zoom relative to the fitted view: the largest 14, more as you zoom in. */
export function labelBudget(relativeZoom: number): number {
  const scale = Number.isFinite(relativeZoom) ? Math.max(1, relativeZoom) : 1;
  return Math.min(MAX_CLUSTER_NODES, Math.round(14 * scale * scale));
}

/**
 * Largest on-screen circle diameter for a level: a share of the canvas per
 * cluster, so four clusters do not fill the canvas and 300 still get room.
 */
export function maxCircleDiameter(
  count: number,
  width: number,
  height: number,
): number {
  const area = Math.max(1, width) * Math.max(1, height);
  const share = 0.3 * Math.sqrt(area / Math.max(1, count));
  return Math.min(
    Math.max(48, Math.min(88, share)),
    Math.min(width, height) / 3,
  );
}

export interface FitNode {
  x: number;
  y: number;
  /** Model-space radius. */
  r: number;
  /** Screen width of the label under the circle, or 0 when it is not reserved. */
  label: number;
}

export interface FitPadding {
  top: number;
  right: number;
  bottom: number;
  left: number;
}

/**
 * Fit circles and the labels reserved under them into the canvas. Labels have a
 * fixed screen size, so the extent at zoom z is linear in z per node and the
 * largest zoom that fits is found by bisection. Zoom is capped so the largest
 * circle renders at most `maxDiameter` pixels.
 */
export function fitClusters(
  nodes: FitNode[],
  width: number,
  height: number,
  padding: FitPadding,
  options: { minZoom: number; maxZoom: number },
): { zoom: number; pan: { x: number; y: number } } {
  const usableW = Math.max(1, width - padding.left - padding.right);
  const usableH = Math.max(1, height - padding.top - padding.bottom);
  const extent = (zoom: number) => {
    let x1 = Infinity;
    let x2 = -Infinity;
    let y1 = Infinity;
    let y2 = -Infinity;
    for (const n of nodes) {
      const half = Math.max(n.r * zoom, n.label / 2);
      x1 = Math.min(x1, n.x * zoom - half);
      x2 = Math.max(x2, n.x * zoom + half);
      y1 = Math.min(y1, (n.y - n.r) * zoom);
      y2 = Math.max(y2, (n.y + n.r) * zoom + (n.label ? LABEL_LINE : 0));
    }
    return { x1, x2, y1, y2 };
  };
  const fits = (zoom: number) => {
    const e = extent(zoom);
    return e.x2 - e.x1 <= usableW && e.y2 - e.y1 <= usableH;
  };
  let zoom = options.maxZoom;
  if (nodes.length && !fits(zoom)) {
    let low = options.minZoom;
    let high = options.maxZoom;
    for (let step = 0; step < 40; step++) {
      const mid = (low + high) / 2;
      if (fits(mid)) low = mid;
      else high = mid;
    }
    zoom = low;
  }
  if (!nodes.length) return { zoom, pan: { x: width / 2, y: height / 2 } };
  const e = extent(zoom);
  return {
    zoom,
    pan: {
      x: padding.left + (usableW - (e.x2 - e.x1)) / 2 - e.x1,
      y: padding.top + (usableH - (e.y2 - e.y1)) / 2 - e.y1,
    },
  };
}

/** Members shown in place on the map at once (server bound, WebGL renderer). */
export const MAX_VISIBLE_MEMBERS = 5000;
/** Model-space distance unit of the packed member layout (one member per pi units^2). */
export const MEMBER_SPACING = 3;
/** Model-space diameter of a member dot shown in place. */
export const MEMBER_DOT = 3.2;

/** Radius of the disc that holds `count` members laid out in place (never smaller than the circle). */
export function expansionRadius(count: number, clusterRadius = 0): number {
  return Math.max(
    clusterRadius,
    MEMBER_SPACING * Math.sqrt(Math.max(1, count)) + MEMBER_DOT,
  );
}

/**
 * Map a packed layout (centred near the origin, radius about sqrt(n)) into the
 * expanded cluster's disc at (cx, cy). Returns the positions and the disc radius.
 */
export function placeInDisc(
  positions: Position[],
  cx: number,
  cy: number,
  clusterRadius: number,
): { positions: Position[]; radius: number } {
  if (!positions.length) return { positions, radius: clusterRadius };
  let mx = 0;
  let my = 0;
  for (const p of positions) {
    mx += p.x;
    my += p.y;
  }
  mx /= positions.length;
  my /= positions.length;
  let reach = 0;
  for (const p of positions)
    reach = Math.max(reach, Math.hypot(p.x - mx, p.y - my));
  // Small groups spread to the circle they replace; large ones keep their density.
  const target = Math.max(
    clusterRadius * 0.8,
    MEMBER_SPACING * Math.max(reach, 1),
  );
  const scale = reach > 0 ? target / reach : 0;
  return {
    positions: positions.map((p) => ({
      id: p.id,
      x: cx + (p.x - mx) * scale,
      y: cy + (p.y - my) * scale,
    })),
    radius: Math.max(clusterRadius, target + MEMBER_DOT),
  };
}

/**
 * Make room for expanded discs without a re-layout: only circles that overlap
 * an expanded (pinned) disc or a moved neighbour are pushed outward, along the
 * line between centres, until every pair keeps `gap`. Pinned circles never move.
 * Returns new positions for every circle (unchanged ones keep their values).
 */
export function makeRoom(
  circles: { id: string; x: number; y: number; r: number; pinned?: boolean }[],
  gap = 26,
  passes = 80,
): Position[] {
  const n = circles.length;
  const x = Float64Array.from(circles, (c) => c.x);
  const y = Float64Array.from(circles, (c) => c.y);
  for (let pass = 0; pass < passes; pass++) {
    let moved = false;
    for (let a = 0; a < n; a++) {
      for (let b = a + 1; b < n; b++) {
        const pa = !!circles[a].pinned;
        const pb = !!circles[b].pinned;
        if (pa && pb) continue;
        let dx = x[b] - x[a];
        let dy = y[b] - y[a];
        const need = circles[a].r + circles[b].r + gap;
        let distance = Math.hypot(dx, dy);
        if (distance >= need) continue;
        if (distance < 1e-6) {
          dx = Math.cos(a + b);
          dy = Math.sin(a + b);
          distance = 1;
        }
        const push = (need - distance) / distance;
        moved = true;
        // A pinned disc pushes the other circle the whole way; free pairs share it.
        const shareA = pa ? 0 : pb ? 1 : 0.5;
        const shareB = 1 - shareA;
        x[a] -= dx * push * shareA;
        y[a] -= dy * push * shareA;
        x[b] += dx * push * shareB;
        y[b] += dy * push * shareB;
      }
    }
    if (!moved) break;
  }
  return circles.map((c, i) => ({ id: c.id, x: x[i], y: y[i] }));
}
