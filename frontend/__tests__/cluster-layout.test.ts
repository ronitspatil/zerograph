import { describe, expect, it } from "vitest";
import {
  clusterDiameter,
  clusterLayoutInput,
  clusterPositions,
  linkWidth,
  topFacets,
} from "@/lib/cluster-layout";
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
});
