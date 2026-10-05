import type { Position } from "./graph-layout";
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
  const gap = 26; // Room for the label under each circle.
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

/** Screen box of a cluster label drawn under its circle (12px text, at most 170px wide). */
export function clusterLabelBox(
  id: string,
  label: string,
  x: number,
  y: number,
  diameter: number,
): { id: string; x1: number; y1: number; x2: number; y2: number } {
  const width = Math.min(170, 6.6 * label.length + 6);
  const top = y + diameter / 2 + 3;
  return { id, x1: x - width / 2, y1: top, x2: x + width / 2, y2: top + 17 };
}

/** Labels offered at a zoom relative to the fitted view: the largest 14, more as you zoom in. */
export function labelBudget(relativeZoom: number): number {
  const scale = Number.isFinite(relativeZoom) ? Math.max(1, relativeZoom) : 1;
  return Math.min(MAX_CLUSTER_NODES, Math.round(14 * scale * scale));
}
