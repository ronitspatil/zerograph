import { describe, expect, it } from "vitest";
import {
  circleObstacle,
  clusterDiameter,
  clusterLabelBox,
  clusterLayoutInput,
  estimateLabelWidth,
  fitClusters,
  LABEL_LINE,
  labelBudget,
  clusterPositions,
  linkWidth,
  maxCircleDiameter,
  placeLabels,
  topFacets,
} from "@/lib/cluster-layout";
import { spacedLabels } from "@/lib/graph-layout";
import type { ClusterSummary } from "@/lib/types";

const cluster = (id: string, size: number): ClusterSummary => ({
  id,
  parent_id: null,
  depth: 0,
  kind: "community",
  label: id,
  representative_id: id,
  size,
  child_count: 0,
  member_count: size,
  internal_edges: 0,
  boundary_edges: 0,
  dominant_type: "CloudRole",
  types: {},
  accounts: {},
});

describe("cluster layout", () => {
  it("sizes circles by area and links by log weight within fixed bounds", () => {
    expect(clusterDiameter(1, 1000)).toBe(14);
    expect(clusterDiameter(1000, 1000)).toBe(76);
    expect(clusterDiameter(250, 1000)).toBeGreaterThan(
      clusterDiameter(100, 1000),
    );
    expect(clusterDiameter(5000, 1000)).toBe(76);
    expect(linkWidth(1, 100)).toBe(0.6);
    expect(linkWidth(100, 100)).toBeCloseTo(6);
    expect(linkWidth(10, 100)).toBeCloseTo(3.3);
  });

  it("is deterministic and keeps 300 circles apart", () => {
    const clusters = Array.from({ length: 300 }, (_, i) =>
      cluster(`c${i}`, i === 0 ? 34000 : 1 + ((i * 37) % 900)),
    );
    const links = clusters.slice(1, 120).map((c, i) => ({
      source: clusters[i].id,
      target: c.id,
      weight: 1 + i,
    }));
    const started = performance.now();
    const first = clusterPositions(clusters, links);
    expect(performance.now() - started).toBeLessThan(2000);
    expect(clusterPositions(clusters, links)).toEqual(first);
    const largest = 34000;
    let overlaps = 0;
    for (let a = 0; a < first.length; a++)
      for (let b = a + 1; b < first.length; b++) {
        const need =
          (clusterDiameter(clusters[a].size, largest) +
            clusterDiameter(clusters[b].size, largest)) /
          2;
        if (Math.hypot(first[a].x - first[b].x, first[a].y - first[b].y) < need)
          overlaps++;
      }
    expect(overlaps).toBe(0);
    expect(
      first.every((p) => Number.isFinite(p.x) && Number.isFinite(p.y)),
    ).toBe(true);
  });

  it("refuses out-of-bounds input and drops dangling links", () => {
    const many = Array.from({ length: 301 }, (_, i) => cluster(`c${i}`, 1));
    expect(clusterLayoutInput(many, [])).toBeNull();
    expect(
      clusterLayoutInput([cluster("a", 1), cluster("a", 2)], []),
    ).toBeNull();
    const input = clusterLayoutInput(
      [cluster("a", 1), cluster("b", 2)],
      [
        { source: "a", target: "b", weight: 1 },
        { source: "a", target: "zzz", weight: 1 },
      ],
    );
    expect(input?.links).toHaveLength(1);
  });

  it("folds small facets into Other", () => {
    expect(topFacets({ a: 5, b: 4, c: 3 }, 5)).toHaveLength(3);
    expect(topFacets({ a: 9, b: 4, c: 3, d: 2, e: 1, f: 1 }, 3)).toEqual([
      { name: "a", count: 9 },
      { name: "b", count: 4 },
      { name: "Other", count: 7 },
    ]);
  });

  it("keeps densely linked levels free of overlaps", () => {
    const clusters = Array.from({ length: 64 }, (_, i) =>
      cluster(`d${i}`, 600 + ((i * 97) % 2500)),
    );
    const links = clusters.flatMap((a, i) =>
      clusters
        .slice(i + 1)
        .map((b) => ({ source: a.id, target: b.id, weight: 50 })),
    );
    const positions = clusterPositions(clusters, links.slice(0, 1813));
    const largest = Math.max(...clusters.map((c) => c.size));
    for (let a = 0; a < positions.length; a++)
      for (let b = a + 1; b < positions.length; b++) {
        const need =
          (clusterDiameter(clusters[a].size, largest) +
            clusterDiameter(clusters[b].size, largest)) /
          2;
        expect(
          Math.hypot(
            positions[a].x - positions[b].x,
            positions[a].y - positions[b].y,
          ),
        ).toBeGreaterThanOrEqual(need);
      }
  });

  it("budgets labels by zoom and places their boxes under the circle", () => {
    expect(labelBudget(1)).toBe(14);
    expect(labelBudget(0.5)).toBe(14);
    expect(labelBudget(2)).toBe(56);
    expect(labelBudget(100)).toBe(300);
    expect(labelBudget(Number.NaN)).toBe(14);
    const box = clusterLabelBox(
      "c",
      estimateLabelWidth("x".repeat(100)),
      100,
      50,
      20,
    );
    expect(box.x2 - box.x1).toBe(176);
    expect(box.y1).toBe(63);
    expect(box.y2 - box.y1).toBe(17);
    expect(clusterLabelBox("c", 40, 100, 50, 20).x2 - 100).toBe(23);
  });

  it("keeps labels apart and off larger clusters, moving one above its circle when needed", () => {
    const candidate = (id: string, x: number, y: number, d: number) => ({
      id,
      below: clusterLabelBox(id, 80, x, y, d, "below"),
      above: clusterLabelBox(id, 80, x, y, d, "above"),
    });
    const rank = new Map([
      ["big", 0],
      ["small", 1],
    ]);
    expect(circleObstacle("dot", 0, 0, 8)).toBeNull();
    // "small" sits right above "big": its label below would cross the larger circle.
    const candidates = [
      candidate("big", 200, 150, 60),
      candidate("small", 200, 100, 30),
    ];
    const placed = placeLabels(candidates, 400, 300, {
      obstacles: [
        circleObstacle("big", 200, 150, 60)!,
        circleObstacle("small", 200, 100, 30)!,
      ],
      rank,
    });
    expect(placed.get("big")).toBe("below");
    expect(placed.get("small")).toBe("above");
    expect(candidates[1].above.y2).toBeLessThanOrEqual(100 - 15);
    // The larger cluster's label may cover a smaller circle (it draws above it).
    const reversed = [
      candidate("big", 200, 100, 60),
      candidate("small", 200, 150, 30),
    ];
    const covering = placeLabels(reversed, 400, 300, {
      obstacles: [
        circleObstacle("big", 200, 100, 60)!,
        circleObstacle("small", 200, 150, 30)!,
      ],
      rank,
    });
    expect(covering.get("big")).toBe("below");
    expect(covering.get("small")).toBe("below");
    // Labels never overlap each other.
    const crowded = [
      candidate("big", 200, 100, 20),
      candidate("small", 230, 100, 20),
    ];
    expect([...placeLabels(crowded, 400, 300, { rank }).keys()]).toEqual([
      "big",
      "small",
    ]);
    expect(placeLabels(crowded, 400, 300, { rank }).get("small")).toBe("above");
    // No room inside the canvas: dropped, unless required (hovered or selected).
    const edge = [candidate("small", 200, 10, 30)];
    expect(placeLabels(edge, 400, 30, { rank }).size).toBe(0);
    expect(
      placeLabels(edge, 400, 30, { rank, required: new Set(["small"]) }).get(
        "small",
      ),
    ).toBe("below");
  });

  it("bounds circle size by canvas and cluster count", () => {
    expect(maxCircleDiameter(4, 894, 540)).toBe(88);
    expect(maxCircleDiameter(4, 310, 460)).toBeCloseTo(
      0.3 * Math.sqrt((310 * 460) / 4),
    );
    expect(maxCircleDiameter(300, 894, 540)).toBe(48);
    expect(maxCircleDiameter(1, 120, 90)).toBe(30);
  });

  it("fits circles and their reserved labels inside the padded canvas", () => {
    const padding = { top: 16, right: 56, bottom: 60, left: 16 };
    const nodes = [
      { x: -80, y: 0, r: 38, label: 150 },
      { x: 80, y: 0, r: 38, label: 0 },
      { x: 0, y: 120, r: 7, label: 120 },
    ];
    const capped = fitClusters(nodes, 900, 540, padding, {
      minZoom: 0.05,
      maxZoom: 88 / 76,
    });
    // Four clusters on a large canvas: the size cap wins, not the canvas.
    expect(capped.zoom).toBeCloseTo(88 / 76);
    const tight = fitClusters(nodes, 300, 400, padding, {
      minZoom: 0.05,
      maxZoom: 3,
    });
    const z = tight.zoom;
    expect(z).toBeLessThan(88 / 76);
    const px = (x: number) => x * z + tight.pan.x;
    const py = (y: number) => y * z + tight.pan.y;
    for (const n of nodes) {
      const half = Math.max(n.r * z, n.label / 2);
      expect(px(n.x) - half).toBeGreaterThanOrEqual(padding.left - 0.5);
      expect(px(n.x) + half).toBeLessThanOrEqual(300 - padding.right + 0.5);
      expect(py(n.y) - n.r * z).toBeGreaterThanOrEqual(padding.top - 0.5);
      expect(
        py(n.y) + n.r * z + (n.label ? LABEL_LINE : 0),
      ).toBeLessThanOrEqual(400 - padding.bottom + 0.5);
    }
    expect(
      fitClusters([], 300, 200, padding, { minZoom: 0.05, maxZoom: 2 }).pan,
    ).toEqual({
      x: 150,
      y: 100,
    });
  });
});
