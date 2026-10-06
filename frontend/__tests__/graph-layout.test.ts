import { afterEach, describe, expect, it, vi } from "vitest";
import {
  circlePositions,
  DETAIL_ZOOM,
  fitViewport,
  labelCandidates,
  LABEL_CELL,
  labelFontSize,
  labelPriority,
  MAX_FIT_ZOOM,
  OVERVIEW_ALL_LABELS_MAX_NODES,
  overviewAnchors,
  relationshipHint,
  spacedLabels,
  spreadCandidates,
  layoutInput,
  startLayout,
  type LayoutInput,
  type LayoutWorker,
} from "@/lib/graph-layout";
import type { GraphNode } from "@/lib/types";
const input: LayoutInput = {
  nodes: ["a", "b"],
  edges: [{ id: "e", source: "a", target: "b" }],
};
function worker(): LayoutWorker {
  return {
    onmessage: null,
    onerror: null,
    postMessage: vi.fn(),
    terminate: vi.fn(),
  };
}
afterEach(() => vi.useRealTimers());
describe("bounded off-thread layout lifecycle", () => {
  it("starts from repeatable immediately usable positions", () => {
    expect(circlePositions(input.nodes)).toEqual(circlePositions(input.nodes));
    expect(circlePositions(input.nodes)[0]).not.toEqual(
      circlePositions(input.nodes)[1],
    );
  });
  it("rejects graph oversize or invisible endpoints before creating a worker", () => {
    const factory = vi.fn();
    startLayout({ nodes: Array(501).fill("x"), edges: [] }, vi.fn(), factory);
    startLayout(
      { nodes: [], edges: Array(2001).fill(input.edges[0]) },
      vi.fn(),
      factory,
    );
    expect(factory).not.toHaveBeenCalled();
    expect(
      layoutInput({
        revision: "r",
        nodes: [],
        edges: [
          {
            ...input.edges[0],
            type: "CAN_READ",
            actions: [],
            certainty: "confirmed",
            evidence: [],
          },
        ],
        warnings: [],
      }),
    ).toBeNull();
  });
  it("accepts one finite result and terminates without reordering node identity", () => {
    const w = worker(),
      apply = vi.fn();
    startLayout(input, apply, () => w);
    expect(w.postMessage).toHaveBeenCalledWith(input);
    w.onmessage?.({
      data: [
        { id: "b", x: 10, y: 20 },
        { id: "a", x: 30, y: 40 },
      ],
    } as MessageEvent);
    expect(apply).toHaveBeenCalledOnce();
    expect(w.terminate).toHaveBeenCalledOnce();
  });
  it("cancellation ignores a queued obsolete result", () => {
    const w = worker(),
      apply = vi.fn();
    const cancel = startLayout(input, apply, () => w);
    const queued = w.onmessage;
    cancel();
    queued?.({
      data: [
        { id: "a", x: 1, y: 2 },
        { id: "b", x: 2, y: 3 },
      ],
    } as MessageEvent);
    expect(apply).not.toHaveBeenCalled();
    expect(w.terminate).toHaveBeenCalledOnce();
  });
  it("invalid coordinates, duplicate IDs and foreign IDs retain preset fallback", () => {
    for (const data of [
      [
        { id: "a", x: NaN, y: 0 },
        { id: "b", x: 0, y: 0 },
      ],
      [
        { id: "a", x: 0, y: 0 },
        { id: "a", x: 0, y: 0 },
      ],
      [
        { id: "a", x: 0, y: 0 },
        { id: "outside", x: 0, y: 0 },
      ],
    ]) {
      const w = worker(),
        apply = vi.fn();
      startLayout(input, apply, () => w);
      w.onmessage?.({ data } as MessageEvent);
      expect(apply).not.toHaveBeenCalled();
      expect(w.terminate).toHaveBeenCalledOnce();
    }
  });
  it("timeout or worker failure terminates without doing work on the main thread", () => {
    vi.useFakeTimers();
    const w = worker(),
      apply = vi.fn();
    startLayout(input, apply, () => w);
    vi.advanceTimersByTime(10000);
    expect(w.terminate).toHaveBeenCalledOnce();
    expect(apply).not.toHaveBeenCalled();
    const failed = worker();
    startLayout(input, apply, () => failed);
    failed.onerror?.(new Event("error"));
    expect(failed.terminate).toHaveBeenCalledOnce();
  });
});

it("caps overview role labels by visible degree with deterministic ties", () => {
  const nodes = Array.from({ length: 40 }, (_, i) => ({
    id: `r${String(i).padStart(2, "0")}`,
    name: "Role",
    type: "CloudRole" as const,
    provider: "fixture",
    account_id: "a",
    sensitivity: "internal" as const,
    tags: [],
    internet_exposed: false,
    authenticated: true,
    encrypted: true,
    privileged: false,
    metadata: {},
  }));
  const graph = {
    revision: "r",
    nodes,
    edges: [
      {
        id: "e",
        source: "r39",
        target: "r38",
        type: "ASSUMES_ROLE" as const,
        actions: [],
        certainty: "confirmed" as const,
        evidence: [],
      },
    ],
    warnings: [],
  };
  const anchors = overviewAnchors(graph);
  expect(anchors.size).toBe(16);
  expect(anchors.has("r39")).toBe(true);
  expect(anchors.has("r38")).toBe(true);
  expect([
    ...overviewAnchors({ ...graph, nodes: [...nodes].reverse() }),
  ]).toEqual([...anchors]);
});

it("thins dense role labels using rendered boxes, priority, viewport and breathing room", () => {
  const boxes = [
    { id: "first", x1: 0, y1: 10, x2: 82, y2: 20 },
    { id: "overlap", x1: 55, y1: 10, x2: 137, y2: 20 },
    { id: "next", x1: 110, y1: 10, x2: 192, y2: 20 },
    { id: "too-close", x1: 193, y1: 10, x2: 250, y2: 20 },
    { id: "second-row", x1: 55, y1: 50, x2: 137, y2: 60 },
    { id: "clipped", x1: 260, y1: 10, x2: 340, y2: 20 },
    { id: "invalid", x1: NaN, y1: 0, x2: 20, y2: 20 },
  ];
  expect([...spacedLabels(boxes, 300, 100)]).toEqual([
    "first",
    "next",
    "second-row",
  ]);
  expect([...spacedLabels([boxes[1], boxes[0], boxes[2]], 300, 100)]).toEqual([
    "overlap",
  ]);
});

describe("graph label legibility", () => {
  const node = (id: string, type: "CloudRole" | "AIAgent" = "AIAgent") => ({
    id,
    name: id,
    type,
    provider: "fixture",
    account_id: "a",
    sensitivity: "internal" as const,
    tags: [],
    internet_exposed: false,
    authenticated: true,
    encrypted: true,
    privileged: false,
    metadata: {},
  });
  const edge = (source: string, target: string) => ({
    id: `${source}-${target}`,
    source,
    target,
    type: "CAN_READ" as const,
    actions: [],
    certainty: "confirmed" as const,
    evidence: [],
  });

  it("keeps labels one screen size at every zoom, shrinking only far out", () => {
    for (const zoom of [0.5, 1, 1.8, 2.5])
      expect(labelFontSize(11, zoom) * zoom).toBeCloseTo(11);
    expect(labelFontSize(11, 0.05) * 0.05).toBeLessThan(11);
    expect(labelFontSize(11, 0)).toBe(11);
  });

  it("orders candidates by role anchors, then visible degree, with focus always shown", () => {
    const graph = {
      revision: "r",
      nodes: [node("leaf"), node("hub"), node("role", "CloudRole")],
      edges: [edge("hub", "leaf"), edge("hub", "role")],
      warnings: [],
    };
    const anchors = overviewAnchors(graph);
    expect(labelCandidates(graph, anchors, { zoom: 1, focus: null })).toEqual({
      order: ["role", "hub", "leaf"],
      required: new Set(),
      spread: false,
    });
    const focused = labelCandidates(graph, anchors, {
      zoom: 1,
      focus: "leaf",
      neighbors: ["hub"],
    });
    expect(focused.order).toEqual(["leaf", "hub"]);
    expect(focused.required).toEqual(new Set(["leaf", "hub"]));
  });

  it("labels only anchors at overview for role maps and large slices, everything when zoomed in", () => {
    const big = {
      revision: "r",
      nodes: [
        node("role", "CloudRole"),
        ...Array.from({ length: OVERVIEW_ALL_LABELS_MAX_NODES }, (_, i) =>
          node(`n${i}`),
        ),
      ],
      edges: [],
      warnings: [],
    };
    const anchors = overviewAnchors(big);
    expect(
      labelCandidates(big, anchors, { zoom: 1, focus: null }).order,
    ).toEqual(["role"]);
    expect(
      labelCandidates(big, anchors, { zoom: DETAIL_ZOOM + 0.1, focus: null })
        .order,
    ).toHaveLength(big.nodes.length);
    const roles = {
      ...big,
      nodes: big.nodes.slice(0, 3),
      view: { mode: "roles" as const },
    };
    expect(
      labelCandidates(roles, overviewAnchors(roles), { zoom: 1, focus: null })
        .order,
    ).toEqual(["role"]);
  });

  it("spreads overview candidates across the canvas, one per cell, by priority", () => {
    const priority = new Map([
      ["core-hub", 40],
      ["core-2", 30],
      ["east", 2],
      ["east-quiet", 1],
      ["south", 1],
    ]);
    const positions = [
      { id: "core-2", x: 10, y: 10 },
      { id: "core-hub", x: 20, y: 12 },
      { id: "east", x: 400, y: 0 },
      { id: "east-quiet", x: 410, y: 5 },
      { id: "south", x: 0, y: 300 },
      { id: "nowhere", x: NaN, y: 0 },
    ];
    const cell = { width: 150, height: 56 };
    expect(spreadCandidates(positions, priority, cell)).toEqual([
      "core-hub",
      "east",
      "south",
    ]);
    // Deterministic: input order and panning (same cells) never change the result.
    expect(spreadCandidates([...positions].reverse(), priority, cell)).toEqual([
      "core-hub",
      "east",
      "south",
    ]);
    // Ties break by id.
    expect(
      spreadCandidates(
        [
          { id: "b", x: 0, y: 0 },
          { id: "a", x: 1, y: 1 },
        ],
        new Map(),
        cell,
      ),
    ).toEqual(["a"]);
  });

  it("boosts finding paths, exposed agents and sensitive stores over plain leaves", () => {
    const graph = {
      revision: "r",
      nodes: [
        node("plain-role", "CloudRole"),
        { ...node("agent"), internet_exposed: true },
        {
          ...node("store", "CloudRole"),
          type: "Database" as const,
          sensitivity: "restricted" as const,
        },
        node("risky", "CloudRole"),
      ],
      edges: [],
      warnings: [],
    };
    const priority = labelPriority(graph, new Set(["risky"]));
    expect(priority.get("plain-role")).toBe(0);
    expect(priority.get("agent")).toBeGreaterThan(priority.get("store")!);
    expect(priority.get("store")).toBeGreaterThan(0);
    expect(priority.get("risky")).toBeGreaterThan(0);
  });

  it("labels a spread of large overview slices, and falls back to anchors", () => {
    const nodes = [
      node("hub", "CloudRole"),
      ...Array.from({ length: OVERVIEW_ALL_LABELS_MAX_NODES }, (_, i) =>
        node(`n${i}`),
      ),
    ];
    const big = {
      revision: "r",
      nodes,
      edges: nodes.slice(1, 6).map((n) => edge("hub", n.id)),
      warnings: [],
    };
    // Everything piled in one cell except one far satellite.
    const positions = nodes.map((n, i) => ({
      id: n.id,
      x: i === 7 ? 1000 : i % 3,
      y: 0,
    }));
    const zoom = 1;
    const spread = labelCandidates(big, overviewAnchors(big), {
      zoom,
      focus: null,
      positions,
    });
    expect(spread.order).toEqual(["hub", "n6"]);
    expect(spread.spread).toBe(true);
    // Before a layout reports positions, only the role anchors are candidates.
    expect(
      labelCandidates(big, overviewAnchors(big), { zoom, focus: null }),
    ).toEqual({ order: ["hub"], required: new Set(), spread: false });
    // Zoomed out, a cell covers more of the model.
    expect(
      labelCandidates(big, overviewAnchors(big), {
        zoom: LABEL_CELL.width / 2000,
        focus: null,
        positions,
      }).order,
    ).toEqual(["hub"]);
    // Focus still wins over spread.
    expect(
      labelCandidates(big, overviewAnchors(big), {
        zoom,
        focus: "n6",
        neighbors: [],
        positions,
      }).order,
    ).toEqual(["n6"]);
  });

  it("lets a few backdrop labels cover dots and caps optional labels", () => {
    const boxes = [
      { id: "hub", x1: 0, y1: 0, x2: 60, y2: 10 },
      { id: "leaf", x1: 100, y1: 0, x2: 160, y2: 10 },
      { id: "far", x1: 200, y1: 0, x2: 260, y2: 10 },
    ];
    const obstacles = [
      { id: "dot1", x1: 20, y1: 2, x2: 24, y2: 6 },
      { id: "dot2", x1: 120, y1: 2, x2: 124, y2: 6 },
    ];
    expect([
      ...spacedLabels(boxes, 400, 100, {
        obstacles,
        backdrops: 1,
      }),
    ]).toEqual(["hub", "far"]);
    expect([...spacedLabels(boxes, 400, 100, { obstacles })]).toEqual(["far"]);
    expect([
      ...spacedLabels(boxes, 400, 100, {
        required: new Set(["leaf"]),
        limit: 1,
      }),
    ]).toEqual(["leaf", "hub"]);
  });

  it("always keeps required labels and keeps optional labels off them and off other nodes", () => {
    const boxes = [
      { id: "root", x1: 0, y1: 10, x2: 80, y2: 20 },
      { id: "neighbor", x1: 40, y1: 12, x2: 120, y2: 22 },
      { id: "collides", x1: 70, y1: 10, x2: 150, y2: 20 },
      { id: "covers-dot", x1: 200, y1: 40, x2: 260, y2: 50 },
      { id: "free", x1: 200, y1: 80, x2: 260, y2: 90 },
      { id: "own-dot", x1: 300, y1: 40, x2: 360, y2: 50 },
    ];
    const obstacles = [
      { id: "other", x1: 228, y1: 43, x2: 232, y2: 47 },
      { id: "own-dot", x1: 328, y1: 38, x2: 332, y2: 42 },
    ];
    expect([
      ...spacedLabels(boxes, 400, 100, {
        required: new Set(["root", "neighbor"]),
        obstacles,
      }),
    ]).toEqual(["root", "neighbor", "free", "own-dot"]);
    // Required labels survive even when clipped by the viewport edge.
    expect([
      ...spacedLabels(
        [{ id: "edge", x1: -10, y1: 0, x2: 50, y2: 10 }],
        40,
        40,
        {
          required: new Set(["edge"]),
        },
      ),
    ]).toEqual(["edge"]);
  });

  it("fits with label and legend room and caps zoom for small slices", () => {
    const small = fitViewport({ x1: 0, y1: 0, x2: 10, y2: 10 }, 1000, 500);
    expect(small.zoom).toBe(MAX_FIT_ZOOM);
    expect(small.pan.x + 5 * small.zoom).toBeCloseTo(500);
    const wide = fitViewport({ x1: -500, y1: -50, x2: 500, y2: 50 }, 1000, 500);
    // Leftmost and rightmost nodes keep room for half a label on each side.
    expect(wide.pan.x + -500 * wide.zoom).toBeGreaterThanOrEqual(80);
    expect(wide.pan.x + 500 * wide.zoom).toBeLessThanOrEqual(920);
    const tall = fitViewport({ x1: 0, y1: -500, x2: 10, y2: 500 }, 1000, 500);
    expect(tall.pan.y + 500 * tall.zoom).toBeLessThanOrEqual(500 - 64);
    expect(
      fitViewport({ x1: 0, y1: 0, x2: 1e9, y2: 1 }, 1000, 500, 0.05).zoom,
    ).toBe(0.05);
  });
});

describe("relationship hint", () => {
  const entity = (id: string): GraphNode => ({
    id,
    name: id,
    type: "AIAgent",
    account_id: "a",
    provider: "test",
    sensitivity: "internal",
    tags: [],
    internet_exposed: false,
    authenticated: true,
    encrypted: true,
    privileged: false,
    metadata: {},
  });
  it("explains a slice whose entities share no relationships", () => {
    const nodes = ["a", "b", "c"].map(entity);
    expect(relationshipHint({ nodes, edges: [] })).toBe(
      "These 3 entities have no relationships between them in this view. Search for an entity or open a neighborhood to see its connections.",
    );
    expect(relationshipHint({ nodes: [nodes[0]], edges: [] })).toMatch(
      /^This entity has no relationships in this view\./,
    );
    expect(
      relationshipHint({ nodes, edges: [], view: { mode: "roles" } }),
    ).toBe(
      "These 3 roles have no direct role links between them in this view.",
    );
  });
  it("stays silent when relationships are visible or nothing is shown", () => {
    const nodes = ["a", "b"].map(entity);
    const edges = [
      {
        id: "e",
        source: "a",
        target: "b",
        type: "ASSUMES_ROLE",
        actions: [],
        certainty: "confirmed" as const,
        evidence: [],
      },
    ];
    expect(relationshipHint({ nodes, edges })).toBeNull();
    expect(relationshipHint({ nodes: [], edges: [] })).toBeNull();
  });
});
