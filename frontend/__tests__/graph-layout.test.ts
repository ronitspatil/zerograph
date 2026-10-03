import { afterEach, describe, expect, it, vi } from "vitest";
import {
  circlePositions,
  overviewAnchors,
  layoutInput,
  startLayout,
  type LayoutInput,
  type LayoutWorker,
} from "@/lib/graph-layout";
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
