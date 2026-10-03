import { describe, expect, it } from "vitest";
import { computePositions } from "@/lib/graph-layout-engine";
describe("real headless Cytoscape packing", () => {
  for (const connected of [false, true]) {
    it(`fits 250 ${connected ? "connected" : "disconnected"} nodes in two dimensions`, () => {
      const nodes = Array.from({ length: 250 }, (_, i) => `n${i}`);
      const edges = connected
        ? nodes.slice(1).map((id, i) => ({
            id: `e${i}`,
            source: nodes[Math.floor(i / 5)],
            target: id,
          }))
        : [];
      const positions = computePositions({ nodes, edges });
      expect(positions).toHaveLength(250);
      expect(new Set(positions.map((p) => p.id)).size).toBe(250);
      expect(
        positions.every((p) => Number.isFinite(p.x) && Number.isFinite(p.y)),
      ).toBe(true);
      const width =
        Math.max(...positions.map((p) => p.x)) -
        Math.min(...positions.map((p) => p.x));
      const height =
        Math.max(...positions.map((p) => p.y)) -
        Math.min(...positions.map((p) => p.y));
      expect(width).toBeGreaterThan(100);
      expect(height).toBeGreaterThan(100);
      expect(width / height).toBeGreaterThan(0.25);
      expect(width / height).toBeLessThan(4);
      expect(width).toBeLessThanOrEqual(1100);
      expect(height).toBeLessThanOrEqual(800);
    });
  }
});
