import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Console } from "@/components/console";
import { api, ApiError } from "@/lib/api";
import type { Finding, GraphNode, GraphView } from "@/lib/types";
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: vi.fn() };
});
vi.mock("next/dynamic", () => ({
  default: () => () => <div>Bounded canvas</div>,
}));
const node: GraphNode = {
  id: "visible",
  name: "Visible agent",
  type: "AIAgent",
  account_id: "prod",
  provider: "test",
  sensitivity: "internal",
  tags: [],
  internet_exposed: false,
  authenticated: true,
  encrypted: true,
  privileged: false,
  metadata: {},
};
const graph: GraphView = {
  revision: "r1",
  nodes: [node],
  edges: [],
  warnings: [],
  view: {
    mode: "sample",
    root_id: null,
    node_limit: 250,
    edge_limit: 1000,
    truncated: true,
    total_nodes: 20000,
    total_edges: 83000,
  },
};
const finding = (index: number): Finding => ({
  id: `f${String(index).padStart(4, "0")}`,
  title: `Finding ${index}`,
  severity: "high",
  source: "visible",
  target: `data:${index}`,
  path: ["visible", `data:${index}`],
  evidence: [],
  conditional: false,
  recommendation: "Review",
});
const overview = {
  revision: "r1",
  total_nhis: 9400,
  ai_agents: 1000,
  toxic_combinations: 250,
  high_blast_radius: 0,
  data_assets: 9000,
  confirmed_edges: 1,
  uncertain_edges: 0,
  accounts: ["prod"],
  sensitivity: { public: 0, internal: 0, confidential: 0, restricted: 0 },
};
const never = () => new Promise<never>(() => {});
let handler: (path: string) => unknown;
beforeEach(() => {
  vi.clearAllMocks();
  handler = (path) => {
    if (path.startsWith("graph/explore")) return graph;
    if (path === "me")
      return { subject: "test", tenant_id: "tenant", roles: ["viewer"] };
    if (path === "overview") return overview;
    if (path.startsWith("findings")) return [];
    return [];
  };
  vi.mocked(api).mockImplementation(async (path) => handler(path) as never);
});
const calls = () => vi.mocked(api).mock.calls.map(([path]) => path);
describe("console loading", () => {
  it("renders the graph while overview and findings are still pending", async () => {
    handler = (path) =>
      path === "overview" || path.startsWith("findings")
        ? never()
        : path.startsWith("graph/explore")
          ? graph
          : path === "me"
            ? { subject: "test", tenant_id: "tenant", roles: ["viewer"] }
            : [];
    render(<Console demo={false} />);
    await screen.findByRole("button", { name: "Visible agent" });
    expect(screen.queryByText(/Connecting your workspace/)).toBeNull();
    expect(screen.getByText(/1 \/ 20,000 nodes/)).toBeInTheDocument();
    // Analysis metrics are shown as not yet known rather than zero.
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    expect(calls()).toContain("overview");
    await waitFor(() =>
      expect(calls()).toContain("findings?limit=200&revision=r1"),
    );
    expect(screen.getByText("Loading findings…")).toBeInTheDocument();
  });
  it("shows overview counts with thousands separators", async () => {
    const fallback = handler;
    handler = (path) =>
      path === "overview"
        ? { ...overview, total_nhis: 47845, ai_agents: 9764 }
        : fallback(path);
    render(<Console demo={false} />);
    expect(await screen.findByText("47,845")).toBeInTheDocument();
    expect(screen.getByText("9,764")).toBeInTheDocument();
    expect(screen.getByText("250")).toBeInTheDocument();
    expect(screen.queryByText("47845")).toBeNull();
  });
  it("keeps the graph usable when overview fails", async () => {
    handler = (path) => {
      if (path === "overview") throw new ApiError("Overview failed", 500);
      if (path.startsWith("graph/explore")) return graph;
      if (path === "me")
        return { subject: "test", tenant_id: "tenant", roles: ["viewer"] };
      return [];
    };
    render(<Console demo={false} />);
    await screen.findByRole("button", { name: "Visible agent" });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Overview failed",
    );
    expect(screen.getByText("Bounded canvas")).toBeInTheDocument();
  });
  it("pages findings for the displayed revision with the last finding as cursor", async () => {
    const first = Array.from({ length: 200 }, (_, index) => finding(index));
    const second = Array.from({ length: 50 }, (_, index) =>
      finding(200 + index),
    );
    const fallback = handler;
    handler = (path) =>
      path === "findings?limit=200&revision=r1"
        ? first
        : path === "findings?limit=200&revision=r1&cursor=f0199"
          ? second
          : fallback(path);
    render(<Console demo={false} />);
    await screen.findByRole("button", { name: "Visible agent" });
    const more = await screen.findByRole("button", {
      name: "Load more findings",
    });
    expect(screen.getByText("200 of 250 findings")).toBeInTheDocument();
    fireEvent.click(more);
    await screen.findByText("250 findings");
    expect(
      screen.queryByRole("button", { name: "Load more findings" }),
    ).toBeNull();
    expect(screen.getAllByText("Finding 249").length).toBeGreaterThan(0);
    expect(calls().filter((path) => path.startsWith("findings"))).toEqual([
      "findings?limit=200&revision=r1",
      "findings?limit=200&revision=r1&cursor=f0199",
    ]);
  });
  it("does not refetch immutable findings when a refresh returns the same revision", async () => {
    render(<Console demo={false} />);
    await screen.findByRole("button", { name: "Visible agent" });
    await waitFor(() =>
      expect(calls()).toContain("findings?limit=200&revision=r1"),
    );
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    await waitFor(() =>
      expect(calls().filter((path) => path === "overview")).toHaveLength(2),
    );
    expect(calls().filter((path) => path.startsWith("findings"))).toHaveLength(
      1,
    );
  });
  it("reports a revision change detected while paging findings", async () => {
    const fallback = handler;
    handler = (path) => {
      if (path.startsWith("findings"))
        throw new ApiError("Graph revision changed", 409);
      return fallback(path);
    };
    render(<Console demo={false} />);
    await screen.findByRole("button", { name: "Visible agent" });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The graph revision changed",
    );
  });
});
