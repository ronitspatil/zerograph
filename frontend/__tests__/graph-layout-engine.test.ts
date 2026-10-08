import { afterEach, describe, expect, it, vi } from "vitest";
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
  });
  it("lets would-be singletons join a role across accounts in the explorer", () => {
    const soft = partitionCommunities(input, { strictAccounts: false });
    // Same-account members are claimed first; "foreign" then joins r1's community.
    expect(soft.find((c) => c[0] === "r1")).toEqual([
      "r1",
      "foreign",
      "tool",
      "worker",
    ]);
    expect(soft.find((c) => c[0] === "r2")).toEqual(["r2", "data"]);
    expect(soft.flat().sort()).toEqual([...input.nodes].sort());
  });
  it("places linked nodes close and each member nearest its own role", () => {
    // Formerly roles sat in separate grid cells (r1-r2 over 150 apart even though
    // linked); a graph layout keeps every relationship short instead.
    const positions = computePositions(input);
    const p = (id: string) => positions.find((n) => n.id === id)!;
    const d = (a: string, b: string) =>
      Math.hypot(p(a).x - p(b).x, p(a).y - p(b).y);
    for (const edge of input.edges)
      expect(d(edge.source, edge.target)).toBeLessThan(120);
    expect(d("worker", "r1")).toBeLessThan(d("worker", "r2"));
    expect(d("data", "r2")).toBeLessThan(d("data", "r1"));
    expect(d("r1", "r2")).toBeGreaterThan(20);
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

/** A multi-account slice: 25 roles granting 150 shared data assets, 75 identities. */
function slice() {
  let seed = 11;
  const random = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const roles = Array.from({ length: 25 }, (_, i) => `role:${i}`);
  const data = Array.from({ length: 150 }, (_, i) => `data:${i}`);
  const people = Array.from({ length: 75 }, (_, i) => `svc:${i}`);
  const nodes = [...roles, ...data, ...people];
  const attributes = Object.fromEntries(
    nodes.map((id, i) => [
      id,
      {
        type: id.startsWith("role")
          ? "CloudRole"
          : id.startsWith("data")
            ? "S3Bucket"
            : "ServiceAccount",
        account: `account-${i % 40}`,
      },
    ]),
  );
  const edges: { id: string; source: string; target: string }[] = [];
  data.forEach((id, i) => {
    edges.push({ id: `g${i}`, source: roles[i % 25], target: id });
    edges.push({
      id: `h${i}`,
      source: roles[Math.floor(random() * 25)],
      target: id,
    });
  });
  people.forEach((id, i) =>
    edges.push({ id: `a${i}`, source: id, target: roles[i % 25] }),
  );
  return { nodes, edges, attributes };
}

describe("graph layout of connected explorer slices", () => {
  it("keeps relationships short and leaves no lattice", () => {
    const input = slice();
    const positions = computePositions(input);
    const at = new Map(positions.map((p) => [p.id, p]));
    const d = (a: string, b: string) =>
      Math.hypot(at.get(a)!.x - at.get(b)!.x, at.get(a)!.y - at.get(b)!.y);
    const median = (values: number[]) =>
      values.sort((a, b) => a - b)[values.length >> 1];
    const edge = median(input.edges.map((e) => d(e.source, e.target)));
    const ids = input.nodes;
    const random = median(
      ids.map((id, i) => d(id, ids[(i * 97 + 31) % ids.length])),
    );
    expect(edge).toBeLessThan(random * 0.5);
    // No column of six or more nodes on one x coordinate (the old cell grid).
    const columns = new Map<number, number>();
    for (const p of positions)
      columns.set(
        Math.round(p.x / 2),
        (columns.get(Math.round(p.x / 2)) ?? 0) + 1,
      );
    expect(Math.max(...columns.values())).toBeLessThan(6);
    // No two dots on top of each other.
    for (let i = 0; i < positions.length; i++)
      for (let j = i + 1; j < positions.length; j++)
        expect(
          Math.hypot(
            positions[i].x - positions[j].x,
            positions[i].y - positions[j].y,
          ),
        ).toBeGreaterThan(4);
  });
  it("centres a hub among its neighbours and keeps components together", () => {
    const leaves = Array.from({ length: 12 }, (_, i) => `leaf:${i}`);
    const input = {
      nodes: ["hub", ...leaves, "a", "b", "c"],
      attributes: {
        hub: { type: "CloudRole", account: "x" },
        ...Object.fromEntries(
          leaves.map((id, i) => [id, { type: "S3Bucket", account: `y${i}` }]),
        ),
      },
      edges: [
        ...leaves.map((id, i) => ({ id: `e${i}`, source: "hub", target: id })),
        { id: "ab", source: "a", target: "b" },
        { id: "bc", source: "b", target: "c" },
      ],
    };
    const positions = computePositions(input);
    const at = new Map(positions.map((p) => [p.id, p]));
    const cx = leaves.reduce((sum, id) => sum + at.get(id)!.x, 0) / 12,
      cy = leaves.reduce((sum, id) => sum + at.get(id)!.y, 0) / 12;
    expect(
      Math.hypot(at.get("hub")!.x - cx, at.get("hub")!.y - cy),
    ).toBeLessThan(10);
    // The separate chain stays near the star instead of drifting away.
    const xs = positions.map((p) => p.x),
      ys = positions.map((p) => p.y);
    expect(Math.max(...xs) - Math.min(...xs)).toBeLessThan(400);
    expect(Math.max(...ys) - Math.min(...ys)).toBeLessThan(400);
  });
  it("lays out 500 nodes and 2,000 relationships within a bounded time", () => {
    const nodes = Array.from({ length: 500 }, (_, i) => `n${i}`);
    const edges = Array.from({ length: 2000 }, (_, i) => ({
      id: `e${i}`,
      source: nodes[(i * 7) % 500],
      target: nodes[(i * 13 + 1 + Math.floor(i / 500)) % 500],
    })).filter((e) => e.source !== e.target);
    const started = performance.now();
    const positions = computePositions({ nodes, edges });
    // Fixed iteration count; generous bound so a busy CI machine still passes.
    expect(performance.now() - started).toBeLessThan(3000);
    expect(positions).toHaveLength(500);
    expect(computePositions({ nodes, edges })).toEqual(positions);
  });
  describe("under machine load", () => {
    afterEach(() => vi.restoreAllMocks());
    it("gives the same positions when the clock jumps mid-layout", () => {
      const nodes = Array.from({ length: 300 }, (_, i) => `n${i}`);
      const edges = Array.from({ length: 900 }, (_, i) => ({
        id: `e${i}`,
        source: nodes[(i * 7) % 300],
        target: nodes[(i * 11 + 1 + Math.floor(i / 300)) % 300],
      })).filter((e) => e.source !== e.target);
      const calm = computePositions({ nodes, edges });
      // Every clock read appears a full second later, as on a starved CPU.
      let now = 0;
      vi.spyOn(Date, "now").mockImplementation(() => (now += 1000));
      vi.spyOn(performance, "now").mockImplementation(() => (now += 1000));
      expect(computePositions({ nodes, edges })).toEqual(calm);
    });
  });
});
