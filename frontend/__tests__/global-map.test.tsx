import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Console } from "@/components/console";
import { GlobalMap, UNAVAILABLE_RETRY_MS } from "@/components/global-map";
import { api, ApiError } from "@/lib/api";
import type {
  ClusterDetail,
  ClusterMap,
  ClusterSummary,
  GraphNode,
  GraphView,
} from "@/lib/types";
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  api: vi.fn(),
}));
vi.mock("next/dynamic", () => ({ default: () => () => <div>Canvas</div> }));

const NOTICE =
  "Clusters group entities by graph structure only. They are not permission or trust boundaries; membership in a cluster implies no access.";
const cluster = (
  id: string,
  size: number,
  extra: Partial<ClusterSummary> = {},
): ClusterSummary => ({
  id,
  parent_id: null,
  depth: 0,
  kind: "community",
  label: `Group ${id}`,
  representative_id: `role:${id}`,
  size,
  child_count: 0,
  member_count: size,
  internal_edges: 10,
  boundary_edges: 3,
  dominant_type: "CloudRole",
  types: { CloudRole: size },
  accounts: { "111111111111": size },
  ...extra,
});
const top: ClusterMap = {
  revision: "rev-1",
  clusters: [
    cluster("ca", 1200, { child_count: 2, member_count: 0 }),
    cluster("cb", 40),
  ],
  edges: [{ source: "ca", target: "cb", weight: 7 }],
  warnings: [],
  view: {
    level: 0,
    total_nodes: 1240,
    total_edges: 5000,
    total_clusters: 5,
    clusters: 2,
    shown_clusters: 2,
    links: 1,
    shown_links: 1,
    edge_limit: 1000,
    isolated_nodes: 12,
    truncated: false,
    notice: NOTICE,
  },
};
const member = (id: string): GraphNode => ({
  id,
  name: id,
  type: "CloudRole",
  account_id: "111111111111",
  provider: "aws",
  sensitivity: "internal",
  tags: [],
  internet_exposed: false,
  authenticated: true,
  encrypted: true,
  privileged: false,
  metadata: {},
});
const children: ClusterDetail = {
  revision: "rev-1",
  cluster: top.clusters[0],
  path: [{ id: "ca", label: "Group ca", size: 1200 }],
  children: [
    cluster("cc", 700, { parent_id: "ca", depth: 1 }),
    cluster("cd", 500, { parent_id: "ca", depth: 1 }),
  ],
  edges: [],
  nodes: [],
  node_edges: [],
  boundary_edges: {},
  warnings: [],
  view: {
    mode: "clusters",
    total_children: 2,
    shown_children: 2,
    total_links: 0,
    shown_links: 0,
    total_members: 0,
    shown_members: 0,
    member_limit: 500,
    total_member_edges: 0,
    shown_member_edges: 0,
    edge_limit: 2000,
    truncated: false,
    notice: NOTICE,
  },
};
const leaf: ClusterDetail = {
  ...children,
  cluster: cluster("cd", 500, { parent_id: "ca", depth: 1 }),
  path: [
    { id: "ca", label: "Group ca", size: 1200 },
    { id: "cd", label: "Group cd", size: 500 },
  ],
  children: [],
  nodes: [member("role:a"), member("role:b")],
  node_edges: [],
  boundary_edges: { "role:a": 4, "role:b": 0 },
  view: {
    ...children.view,
    mode: "members",
    total_children: 0,
    shown_children: 0,
    total_members: 500,
    shown_members: 2,
    member_limit: 2,
    total_member_edges: 900,
    shown_member_edges: 0,
    truncated: true,
  },
};
let handler: (p: string) => unknown;
beforeEach(() => {
  vi.clearAllMocks();
  handler = (p) =>
    p.startsWith("graph/clusters?")
      ? top
      : p.startsWith("graph/clusters/ca")
        ? children
        : p.startsWith("graph/clusters/cd")
          ? leaf
          : [];
  vi.mocked(api).mockImplementation(async (p) => handler(p) as never);
});

describe("global map", () => {
  it("shows top-level counts, drills down with revision pinning and hands off to explore", async () => {
    const open = vi.fn();
    render(
      <GlobalMap
        reloadKey={0}
        stale={false}
        onError={vi.fn()}
        onOpenNeighborhood={open}
      />,
    );
    const status = await screen.findByText(/2 \/ 2 top-level clusters/);
    expect(status).toHaveTextContent("1,240 entities");
    expect(status).toHaveTextContent("5,000 relationships");
    expect(status).toHaveTextContent("1 / 1 cluster links");
    expect(status).toHaveTextContent("Complete map");
    expect(screen.getAllByText(NOTICE).length).toBeGreaterThan(0);
    expect(
      screen.getByText("Clusters are structural, not permission boundaries"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Group ca · 1,200" }));
    await screen.findByText(/2 \/ 2 child clusters/);
    expect(api).toHaveBeenCalledWith(
      "graph/clusters/ca?revision=rev-1",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Group cd · 500" }));
    const members = await screen.findByText(/2 \/ 500 members/);
    expect(members).toHaveTextContent("0 / 900 relationships inside");
    expect(members).toHaveTextContent("Partial cluster");
    // Breadcrumb: back to the parent, or to the top level.
    expect(screen.getByRole("button", { name: "Group ca" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "role:a" }));
    expect(screen.getByText("Leave cluster").nextSibling).toHaveTextContent(
      "4",
    );
    fireEvent.click(screen.getByRole("button", { name: "Open neighborhood" }));
    expect(open).toHaveBeenCalledWith("role:a", "rev-1");
    fireEvent.click(screen.getByRole("button", { name: "Global map" }));
    await screen.findByText(/2 \/ 2 top-level clusters/);
  });

  it("explains a revision without computed clusters and reports other errors", async () => {
    handler = () => {
      throw new ApiError(
        "The global map is not computed for this revision yet",
        404,
      );
    };
    const onError = vi.fn();
    const view = render(
      <GlobalMap
        reloadKey={0}
        stale={false}
        onError={onError}
        onOpenNeighborhood={vi.fn()}
      />,
    );
    await screen.findByText("Global map not available yet");
    expect(onError).not.toHaveBeenCalled();
    view.unmount();
    // The worker backfills the map; the view picks it up without a reload.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let computed = false;
      handler = (p) => {
        if (!computed)
          throw new ApiError(
            "The global map is not computed for this revision yet",
            404,
          );
        return p.startsWith("graph/clusters?") ? top : [];
      };
      const retrying = render(
        <GlobalMap
          reloadKey={0}
          stale={false}
          onError={onError}
          onOpenNeighborhood={vi.fn()}
        />,
      );
      await screen.findByText(/checks again every 30 seconds/);
      computed = true;
      await vi.advanceTimersByTimeAsync(UNAVAILABLE_RETRY_MS);
      await screen.findByText(/2 \/ 2 top-level clusters/);
      retrying.unmount();
    } finally {
      vi.useRealTimers();
    }
    handler = (p) => {
      if (p.startsWith("graph/clusters/"))
        throw new ApiError("Graph revision changed", 409);
      return top;
    };
    render(
      <GlobalMap
        reloadKey={0}
        stale={false}
        onError={onError}
        onOpenNeighborhood={vi.fn()}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Group cb · 40" }),
    );
    await waitFor(() => expect(onError).toHaveBeenCalled());
    expect((onError.mock.calls[0][0] as ApiError).status).toBe(409);
  });

  it("is a third console graph view that loads only on request", async () => {
    const identity: GraphView = {
      revision: "rev-1",
      nodes: [member("Initial agent")],
      edges: [],
      warnings: [],
      view: {
        mode: "sample",
        root_id: null,
        node_limit: 250,
        edge_limit: 1000,
        truncated: false,
        total_nodes: 1,
        total_edges: 0,
      },
    };
    const fallback = handler;
    handler = (p) =>
      p.startsWith("graph/explore")
        ? identity
        : p === "me"
          ? { subject: "fixture", tenant_id: "tenant", roles: ["viewer"] }
          : p === "overview"
            ? { accounts: [], sensitivity: {} }
            : fallback(p);
    render(<Console demo={true} />);
    await screen.findByRole("button", { name: "Initial agent" });
    expect(
      vi.mocked(api).mock.calls.some(([p]) => p.startsWith("graph/clusters")),
    ).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Global map" }));
    expect(screen.getByRole("button", { name: "Global map" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await screen.findByText(/2 \/ 2 top-level clusters/);
    expect(
      screen.getByRole("heading", { name: "Global map" }),
    ).toBeInTheDocument();
  });
});
