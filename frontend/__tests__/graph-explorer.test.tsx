import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Console } from "@/components/console";
import { api, ApiError } from "@/lib/api";
import type { GraphNode, GraphView } from "@/lib/types";
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: vi.fn() };
});
vi.mock("next/dynamic", () => ({
  default: () => () => <div>Bounded canvas</div>,
}));
const node = (id: string, name = id): GraphNode => ({
  id,
  name,
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
});
const initial = node("visible", "Visible agent");
const remote = node("remote", "Remote agent");
const view = (nodes = [initial], root: string | null = null): GraphView => ({
  revision: "r1",
  nodes,
  edges: [],
  warnings: [],
  view: {
    mode: root ? "neighborhood" : "sample",
    root_id: root,
    node_limit: 250,
    edge_limit: 1000,
    truncated: true,
    total_nodes: 5000,
    total_edges: 20000,
  },
});
let role = "admin";
let handler: (path: string, options?: RequestInit) => unknown;
beforeEach(() => {
  vi.clearAllMocks();
  role = "admin";
  handler = (path) => {
    if (path.startsWith("graph/explore")) return view();
    if (path === "me")
      return { subject: "test", tenant_id: "tenant", roles: [role] };
    if (path === "overview")
      return { accounts: ["prod"], sensitivity: {}, total_nhis: 100 };
    return [];
  };
  vi.mocked(api).mockImplementation(
    async (path, options) => handler(path, options) as never,
  );
});
async function ready() {
  render(<Console demo={false} />);
  await screen.findByRole("button", { name: "Visible agent" });
}
describe("bounded graph exploration", () => {
  it("loads only bounded explore, reports partial totals and exports the visible view", async () => {
    await ready();
    expect(api).toHaveBeenCalledWith(
      "graph/explore?node_limit=250&edge_limit=1000",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(vi.mocked(api).mock.calls.some(([p]) => p === "graph")).toBe(false);
    expect(screen.getByText(/1 \/ 5,000 nodes/)).toHaveTextContent(
      "Partial view",
    );
    expect(
      screen.getByRole("button", { name: "Export visible view" }),
    ).toBeEnabled();
    expect(
      screen.getByText(/Filters apply only to visible nodes/),
    ).toBeInTheDocument();
  });
  it("searches beyond visible nodes then opens a revision-pinned neighborhood", async () => {
    await ready();
    const fallback = handler;
    handler = (p, o) =>
      p.startsWith("graph/search")
        ? { revision: "r1", nodes: [remote], has_more: true }
        : p.includes("root_id=")
          ? view([remote], "remote")
          : fallback(p, o);
    fireEvent.change(screen.getByLabelText("Search identities"), {
      target: { value: " Remote " },
    });
    const results = await screen.findByLabelText("Global identity search");
    await within(results).findByRole("button", { name: /Remote agent/ });
    expect(api).toHaveBeenCalledWith(
      "graph/search?q=Remote&limit=25&revision=r1",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(screen.getByText(/More matches exist/)).toBeInTheDocument();
    fireEvent.click(
      within(results).getByRole("button", { name: /Remote agent/ }),
    );
    await screen.findByRole("heading", { name: "Remote agent" });
    expect(api).toHaveBeenCalledWith(
      "graph/explore?root_id=remote&node_limit=250&edge_limit=1000&revision=r1",
      expect.anything(),
    );
    expect(screen.getByText(/One-hop neighborhood/)).toBeInTheDocument();
  });
  it("aborts obsolete search and ignores a late result even if transport ignores abort", async () => {
    await ready();
    let resolve!: (value: unknown) => void;
    let signal: AbortSignal | undefined;
    const fallback = handler;
    handler = (p, o) => {
      if (p.includes("q=old")) {
        signal = o?.signal as AbortSignal;
        return new Promise((r) => {
          resolve = r;
        });
      }
      if (p.includes("q=new"))
        return { revision: "r1", nodes: [remote], has_more: false };
      return fallback(p, o);
    };
    fireEvent.change(screen.getByLabelText("Search identities"), {
      target: { value: "old" },
    });
    await waitFor(() => expect(resolve).toBeDefined());
    fireEvent.change(screen.getByLabelText("Search identities"), {
      target: { value: "new" },
    });
    expect(signal?.aborted).toBe(true);
    await screen.findByRole("button", { name: /Remote agent/ });
    resolve({
      revision: "r1",
      nodes: [node("stale", "Stale agent")],
      has_more: false,
    });
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: /Stale agent/ }),
      ).not.toBeInTheDocument(),
    );
  });
  it("clears selection on revision conflict and resets without mixing old nodes", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Visible agent" }));
    const fallback = handler;
    handler = (p, o) => {
      if (p.includes("root_id=")) throw new ApiError("changed", 409);
      return fallback(p, o);
    };
    fireEvent.click(
      screen.getByRole("button", { name: "Explore neighborhood" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "revision changed",
    );
    expect(
      screen.queryByRole("heading", { name: "Visible agent" }),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText("Search identities")).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Reset to initial view" }),
    );
    await waitFor(() =>
      expect(screen.getByLabelText("Search identities")).toBeEnabled(),
    );
  });
  it("keeps viewer simulation disabled and clears selection filtered out of view", async () => {
    role = "viewer";
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Visible agent" }));
    expect(
      screen.getByRole("button", { name: "Simulate compromise" }),
    ).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Filter by identity type"), {
      target: { value: "CloudRole" },
    });
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: "Visible agent" }),
      ).not.toBeInTheDocument(),
    );
  });
  it("reports server simulation impacts beyond the visible slice", async () => {
    await ready();
    const fallback = handler;
    handler = (p, o) =>
      p === "simulate"
        ? {
            source: "visible",
            max_hops: 3,
            risk_score: 42,
            affected_nodes: ["outside"],
            affected_assets: [],
            highlighted_edges: [],
            paths: {},
            sensitivity_exposure: 0,
            centrality: 0,
            includes_uncertain: false,
            explanation: "Server analysis",
          }
        : fallback(p, o);
    fireEvent.click(screen.getByRole("button", { name: "Visible agent" }));
    fireEvent.click(
      screen.getByRole("button", { name: "Simulate compromise" }),
    );
    expect(
      await screen.findByText(/Server-side simulation: 1 affected nodes/),
    ).toBeInTheDocument();
  });
  it("retains permission denial without fabricating a neighborhood", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Visible agent" }));
    const fallback = handler;
    handler = (p, o) => {
      if (p.includes("root_id=")) throw new ApiError("Forbidden", 403);
      return fallback(p, o);
    };
    fireEvent.click(
      screen.getByRole("button", { name: "Explore neighborhood" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Forbidden");
    expect(
      screen.getByRole("button", { name: "Visible agent" }),
    ).toBeInTheDocument();
  });
  it("reset cancels a pending neighborhood and ignores its late result", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Visible agent" }));
    let resolve!: (v: unknown) => void;
    let signal: AbortSignal | undefined;
    const fallback = handler;
    handler = (p, o) => {
      if (p.includes("root_id=")) {
        signal = o?.signal as AbortSignal;
        return new Promise((r) => {
          resolve = r;
        });
      }
      return fallback(p, o);
    };
    fireEvent.click(
      screen.getByRole("button", { name: "Explore neighborhood" }),
    );
    await waitFor(() => expect(resolve).toBeDefined());
    fireEvent.click(
      screen.getByRole("button", { name: "Reset to initial view" }),
    );
    expect(signal?.aborted).toBe(true);
    resolve(view([remote], "remote"));
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Remote agent" }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByText(/Bounded initial view/)).toBeInTheDocument();
  });
  it("refresh preserves a still-visible selected identity and removes a disappeared one", async () => {
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Visible agent" }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh workspace" }));
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Visible agent" }),
      ).toBeInTheDocument(),
    );
    const fallback = handler;
    handler = (p, o) =>
      p.startsWith("graph/explore") ? view([remote]) : fallback(p, o);
    fireEvent.click(screen.getByRole("button", { name: "Refresh workspace" }));
    await screen.findByRole("button", { name: "Remote agent" });
    expect(
      screen.queryByRole("heading", { name: "Visible agent" }),
    ).not.toBeInTheDocument();
  });
});
