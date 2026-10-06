import { describe, expect, it } from "vitest";
import {
  computePositions,
  partitionCommunities,
} from "@/lib/graph-layout-engine";
describe("bounded role community geometry", () => {
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
      expect(width).toBeLessThanOrEqual(1200);
      expect(height).toBeLessThanOrEqual(900);
    });
  }
});

describe("slices without relationships", () => {
  it("pack into one compact disc, banded by entity type, not a sparse grid", () => {
    const nodes = Array.from({ length: 250 }, (_, i) => `n${i}`);
    const attributes = Object.fromEntries(
      nodes.map((id, i) => [
        id,
        { type: i % 2 ? "CloudRole" : "AIAgent", account: "a" },
      ]),
    );
    const positions = computePositions({ nodes, edges: [], attributes });
    expect(new Set(positions.map((p) => p.id)).size).toBe(250);
    const distance = (p: { x: number; y: number }) => Math.hypot(p.x, p.y);
    expect(Math.max(...positions.map(distance))).toBeLessThan(450);
    // Agents (ranked first) fill the centre, roles the outer band.
    const mean = (type: string) => {
      const ring = positions.filter((p) => attributes[p.id].type === type);
      return ring.reduce((sum, p) => sum + distance(p), 0) / ring.length;
    };
    expect(mean("AIAgent")).toBeLessThan(mean("CloudRole"));
    expect(
      computePositions({ nodes: [...nodes].reverse(), edges: [], attributes }),
    ).toEqual(positions);
  });
});

describe("topology-derived role communities", () => {
  const input = {
    nodes: ["r1", "r2", "worker", "tool", "data", "foreign"],
    attributes: {
      r1: { type: "CloudRole", account: "a" },
      r2: { type: "CloudRole", account: "a" },
      worker: { type: "ServiceAccount", account: "a" },
      tool: { type: "MCPServer", account: "a" },
      data: { type: "Database", account: "a" },
      foreign: { type: "ServiceAccount", account: "b" },
    },
    edges: [
      { id: "e1", source: "worker", target: "r1" },
      { id: "e2", source: "tool", target: "worker" },
      { id: "e3", source: "r2", target: "data" },
      { id: "e4", source: "r1", target: "r2" },
      { id: "e5", source: "foreign", target: "r1" },
    ],
  };
  it("uses actual adjacency while retaining role seeds and account boundaries", () => {
    const communities = partitionCommunities(input);
    expect(communities.find((c) => c[0] === "r1")).toEqual([
      "r1",
      "tool",
      "worker",
    ]);
    expect(communities.find((c) => c[0] === "r2")).toEqual(["r2", "data"]);
    expect(communities.find((c) => c[0] === "foreign")).toEqual(["foreign"]);
    const positions = computePositions(input);
    const p = (id: string) => positions.find((n) => n.id === id)!;
    expect(
      Math.hypot(p("r1").x - p("r2").x, p("r1").y - p("r2").y),
    ).toBeGreaterThan(150);
    expect(
      Math.hypot(p("worker").x - p("r1").x, p("worker").y - p("r1").y),
    ).toBeLessThan(80);
  });
  it("is deterministic despite API row ordering and never invents members", () => {
    expect(
      computePositions({
        ...input,
        nodes: [...input.nodes].reverse(),
        edges: [...input.edges].reverse(),
      }),
    ).toEqual(computePositions(input));
    expect(partitionCommunities(input).flat().sort()).toEqual(
      [...input.nodes].sort(),
    );
  });
});
