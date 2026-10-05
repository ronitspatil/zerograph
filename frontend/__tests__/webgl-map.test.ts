import { afterEach, describe, expect, it, vi } from "vitest";
import cytoscape from "cytoscape";
import { createGraph, resetWebglSupport, webglSupported } from "@/lib/renderer";
import { packedPositions } from "@/lib/graph-layout-engine";
import {
  EXPLORE_LIMITS,
  layoutInput,
  MEMBER_LIMITS,
  startLayout,
  type LayoutInput,
  type LayoutWorker,
} from "@/lib/graph-layout";
import {
  expansionRadius,
  makeRoom,
  MAX_VISIBLE_MEMBERS,
  MEMBER_SPACING,
  placeInDisc,
} from "@/lib/cluster-layout";

vi.mock("cytoscape", () => ({
  default: vi.fn((options: { renderer?: { webgl?: boolean } }) => {
    if (options.renderer?.webgl) throw new Error("Could not create canvas");
    return { options };
  }),
}));

afterEach(() => {
  resetWebglSupport();
  vi.mocked(cytoscape).mockClear();
});

function members(n: number, roles = Math.ceil(n / 50)): LayoutInput {
  const nodes = Array.from({ length: n }, (_, i) => `m${i}`);
  const attributes = Object.fromEntries(
    nodes.map((id, i) => [
      id,
      { type: i < roles ? "CloudRole" : "ServiceAccount", account: "a" },
    ]),
  );
  const edges = nodes
    .slice(roles)
    .map((id, i) => ({ id: `e${i}`, source: id, target: `m${i % roles}` }));
  return { mode: "packed", nodes, edges, attributes };
}

describe("WebGL renderer selection", () => {
  it("detects WebGL once and treats a missing context as unsupported", () => {
    // jsdom has no WebGL context.
    expect(webglSupported()).toBe(false);
    resetWebglSupport(true);
    expect(webglSupported()).toBe(true);
  });

  it("falls back to the canvas renderer when WebGL initialisation fails", () => {
    resetWebglSupport(true);
    const container = document.createElement("div");
    container.appendChild(document.createElement("canvas"));
    const { renderer } = createGraph({ container }, true);
    expect(renderer).toBe("canvas");
    expect(container.childElementCount).toBe(0);
    const calls = vi
      .mocked(cytoscape)
      .mock.calls.map(([options]) => options as Record<string, unknown>);
    expect(calls[0].renderer).toEqual({ name: "canvas", webgl: true });
    expect(calls[1].renderer).toBeUndefined();
    // The large-view canvas fallback pans a cached texture.
    expect(calls[1].textureOnViewport).toBe(true);
    // Once failed, later views go straight to canvas.
    expect(webglSupported()).toBe(false);
  });

  it("uses the canvas renderer for small detail views and without support", () => {
    resetWebglSupport(false);
    expect(createGraph({}, true).renderer).toBe("canvas");
    resetWebglSupport(true);
    const small = createGraph({}, false);
    expect(small.renderer).toBe("canvas");
    expect(
      (vi.mocked(cytoscape).mock.calls.at(-1)![0] as Record<string, unknown>)
        .textureOnViewport,
    ).toBeUndefined();
  });
});

describe("in-place member layout", () => {
  it("keeps the explorer at 500 nodes and allows 5,000 for packed members", () => {
    expect(EXPLORE_LIMITS).toEqual({ nodes: 500, edges: 2000 });
    expect(MEMBER_LIMITS).toEqual({ nodes: 5000, edges: 20000 });
    expect(MAX_VISIBLE_MEMBERS).toBe(5000);
    const big = {
      revision: "r",
      warnings: [],
      nodes: Array.from({ length: 501 }, (_, i) => ({ id: `n${i}` })),
      edges: [],
    } as never;
    expect(layoutInput(big)).toBeNull();
    expect(layoutInput(big, MEMBER_LIMITS)?.nodes).toHaveLength(501);
    expect(packedPositions(members(5001))).toEqual([]);
  });

  it("fills a disc of radius about sqrt(n) with every member once, deterministically", () => {
    const input = members(5000);
    const started = performance.now();
    const positions = packedPositions(input);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(new Set(positions.map((p) => p.id))).toEqual(new Set(input.nodes));
    expect(positions.every((p) => Number.isFinite(p.x + p.y))).toBe(true);
    const reach = Math.max(...positions.map((p) => Math.hypot(p.x, p.y)));
    expect(reach).toBeGreaterThan(Math.sqrt(5000) * 0.8);
    expect(reach).toBeLessThan(Math.sqrt(5000) * 2.5);
    expect(packedPositions(input)).toEqual(positions);
    // A role's community stays together: its members sit near each other.
    const at = new Map(positions.map((p) => [p.id, p]));
    const role = at.get("m0")!;
    const own = input.edges
      .filter((e) => e.target === "m0")
      .map((e) => at.get(e.source)!);
    const spread = Math.max(
      ...own.map((p) => Math.hypot(p.x - role.x, p.y - role.y)),
    );
    expect(spread).toBeLessThan(reach / 2);
  });

  it("places members inside the expanded cluster and sizes the disc by member count", () => {
    const { positions, radius } = placeInDisc(
      packedPositions(members(500)),
      100,
      -40,
      20,
    );
    const cx = positions.reduce((s, p) => s + p.x, 0) / positions.length;
    const cy = positions.reduce((s, p) => s + p.y, 0) / positions.length;
    expect(cx).toBeCloseTo(100, 6);
    expect(cy).toBeCloseTo(-40, 6);
    for (const p of positions)
      expect(Math.hypot(p.x - 100, p.y + 40)).toBeLessThanOrEqual(radius);
    expect(radius).toBeGreaterThan(MEMBER_SPACING * Math.sqrt(500) * 0.8);
    expect(expansionRadius(5000)).toBeGreaterThan(expansionRadius(500));
    // A handful of members spreads over the circle it replaces.
    expect(placeInDisc(packedPositions(members(3, 1)), 0, 0, 30).radius).toBe(
      30,
    );
  });

  it("moves only the circles an expanded disc overlaps, and never the disc", () => {
    const circles = [
      { id: "big", x: 0, y: 0, r: 200, pinned: true },
      { id: "near", x: 150, y: 0, r: 10 },
      { id: "chain", x: 230, y: 0, r: 10 },
      { id: "far", x: 1000, y: 1000, r: 10 },
    ];
    const moved = new Map(makeRoom(circles, 20).map((p) => [p.id, p]));
    expect(moved.get("big")).toEqual({ id: "big", x: 0, y: 0 });
    expect(moved.get("far")).toEqual({ id: "far", x: 1000, y: 1000 });
    for (const id of ["near", "chain"]) {
      const p = moved.get(id)!;
      expect(Math.hypot(p.x, p.y)).toBeGreaterThanOrEqual(230 - 1e-6);
    }
    const near = moved.get("near")!;
    const chain = moved.get("chain")!;
    expect(
      Math.hypot(chain.x - near.x, chain.y - near.y),
    ).toBeGreaterThanOrEqual(40 - 1e-6);
  });

  it("reports a failed worker so the caller can lay out on the main thread", async () => {
    const fail = vi.fn();
    const worker: LayoutWorker = {
      onmessage: null,
      onerror: null,
      postMessage() {
        queueMicrotask(() => worker.onerror?.(new Event("error")));
      },
      terminate: vi.fn(),
    };
    startLayout(members(10), vi.fn(), () => worker, fail);
    await new Promise((r) => setTimeout(r, 0));
    expect(fail).toHaveBeenCalledTimes(1);
    // Cancelling is not a failure.
    const quiet = vi.fn();
    const idle: LayoutWorker = { ...worker, postMessage() {} };
    startLayout(members(10), vi.fn(), () => idle, quiet)();
    await new Promise((r) => setTimeout(r, 0));
    expect(quiet).not.toHaveBeenCalled();
    // A packed input above 500 nodes is accepted; above 5,000 it is not started.
    const factory = vi.fn(() => ({ ...idle }));
    startLayout(members(2000), vi.fn(), factory)();
    expect(factory).toHaveBeenCalledTimes(1);
    startLayout(members(5001), vi.fn(), factory)();
    expect(factory).toHaveBeenCalledTimes(1);
  });
});
