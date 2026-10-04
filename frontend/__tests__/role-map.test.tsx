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
import type { GraphNode, GraphView, RoleMap } from "@/lib/types";
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  api: vi.fn(),
}));
vi.mock("next/dynamic", () => ({ default: () => () => <div>Dot canvas</div> }));
const node = (
  id: string,
  type: GraphNode["type"] = "CloudRole",
  account_id = "prod",
): GraphNode => ({
  id,
  name: id,
  type,
  account_id,
  provider: "fixture",
  sensitivity: "internal",
  tags: [],
  internet_exposed: false,
  authenticated: true,
  encrypted: true,
  privileged: false,
  metadata: {},
});
const agent = node("Initial agent", "AIAgent");
const role = node("Global role A");
const other = node("Global role B", "CloudRole", "dev");
const identity: GraphView = {
  revision: "r1",
  nodes: [agent],
  edges: [],
  warnings: [],
  view: {
    mode: "sample",
    root_id: null,
    node_limit: 250,
    edge_limit: 1000,
    truncated: true,
    total_nodes: 1000,
    total_edges: 2000,
  },
};
const page = (nodes = [role], more = true): RoleMap => ({
  revision: "r1",
  nodes,
  edges: [],
  warnings: [],
  role_summaries: nodes.map((n) => ({
    role_id: n.id,
    direct_neighbors: 7,
    linked_identities: 4,
    linked_data_assets: 3,
  })),
  view: {
    mode: "roles",
    root_id: null,
    node_limit: 50,
    edge_limit: 1000,
    truncated: true,
    total_nodes: 1000,
    total_edges: 2000,
    total_roles: 100,
    total_role_edges: 150,
    role_map_truncated: true,
    has_more: more,
    next_cursor: more ? nodes.at(-1)!.id : null,
  },
});
let roleName = "admin";
let handler: (p: string, o?: RequestInit) => unknown;
beforeEach(() => {
  vi.clearAllMocks();
  roleName = "admin";
  handler = (p) =>
    p.startsWith("graph/roles")
      ? page()
      : p.startsWith("graph/explore")
        ? identity
        : p === "me"
          ? { subject: "fixture", tenant_id: "tenant", roles: [roleName] }
          : p === "overview"
            ? { accounts: ["prod", "dev"], sensitivity: {} }
            : [];
  vi.mocked(api).mockImplementation(async (p, o) => handler(p, o) as never);
});
async function ready() {
  render(<Console demo={true} />);
  await screen.findByRole("button", { name: "Initial agent" });
}
async function roles() {
  fireEvent.click(screen.getByRole("button", { name: "Role map" }));
  await screen.findByRole("button", { name: "Global role A" });
}
describe("secondary organization role map", () => {
  it("keeps default identity dots and loads globally scoped roles only on request", async () => {
    await ready();
    expect(
      screen.getByRole("button", { name: "Identity & data" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      vi.mocked(api).mock.calls.some(([p]) => p.startsWith("graph/roles")),
    ).toBe(false);
    await roles();
    expect(api).toHaveBeenCalledWith(
      "graph/roles?role_limit=50&edge_limit=1000",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(screen.getByText(/1 \/ 100 roles/)).toHaveTextContent(
      "Partial role map",
    );
    expect(screen.getByText(/1 \/ 100 roles/)).toHaveTextContent(
      "Partial workspace",
    );
    expect(screen.getByText(/Structural direct role links/)).toHaveTextContent(
      "not effective permissions",
    );
  });
  it("pins next page to the revision and clears prior selection", async () => {
    await ready();
    await roles();
    fireEvent.click(screen.getByRole("button", { name: "Global role A" }));
    const fallback = handler;
    handler = (p, o) =>
      p.includes("cursor=") ? page([other], false) : fallback(p, o);
    fireEvent.click(screen.getByRole("button", { name: "Next role page" }));
    await screen.findByRole("button", { name: "Global role B" });
    expect(api).toHaveBeenCalledWith(
      "graph/roles?role_limit=50&edge_limit=1000&cursor=Global+role+A&revision=r1",
      expect.anything(),
    );
    expect(
      screen.queryByRole("heading", { name: "Global role A" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Next role page" }),
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "First role page" }));
    await screen.findByRole("button", { name: "Global role A" });
  });
  it("reports full-revision direct counts without computing permissions from the page", async () => {
    await ready();
    await roles();
    fireEvent.click(screen.getByRole("button", { name: "Global role A" }));
    expect(
      screen.getByText("Direct structural links · whole revision"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Distinct direct neighbors").nextElementSibling,
    ).toHaveTextContent("7");
    expect(
      screen.getByText("Linked identities (including roles)")
        .nextElementSibling,
    ).toHaveTextContent("4");
    expect(
      screen.getByText("Linked data assets").nextElementSibling,
    ).toHaveTextContent("3");
  });
  it("revision409 requires first-page repinning and clears sidebar/simulation", async () => {
    await ready();
    await roles();
    fireEvent.click(screen.getByRole("button", { name: "Global role A" }));
    const fallback = handler;
    handler = (p, o) => {
      if (p.includes("cursor=")) throw new ApiError("changed", 409);
      return fallback(p, o);
    };
    fireEvent.click(screen.getByRole("button", { name: "Next role page" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "revision changed",
    );
    expect(
      screen.queryByRole("heading", { name: "Global role A" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Next role page" }),
    ).toBeDisabled();
    handler = (p, o) =>
      p.startsWith("graph/roles")
        ? { ...page(), revision: "r2" }
        : fallback(p, o);
    fireEvent.click(screen.getByRole("button", { name: "First role page" }));
    await waitFor(() =>
      expect(screen.getByLabelText("Search identities")).toBeEnabled(),
    );
  });
  it("aborts rapid mode changes and ignores an obsolete role-page response", async () => {
    await ready();
    let resolve!: (v: unknown) => void;
    let signal: AbortSignal | undefined;
    const fallback = handler;
    handler = (p, o) => {
      if (p.startsWith("graph/roles")) {
        signal = o?.signal as AbortSignal;
        return new Promise((r) => {
          resolve = r;
        });
      }
      return fallback(p, o);
    };
    fireEvent.click(screen.getByRole("button", { name: "Role map" }));
    await waitFor(() => expect(resolve).toBeDefined());
    fireEvent.click(screen.getByRole("button", { name: "Identity & data" }));
    expect(signal?.aborted).toBe(true);
    resolve(page());
    await screen.findByRole("button", { name: "Initial agent" });
    expect(
      screen.queryByRole("button", { name: "Global role A" }),
    ).not.toBeInTheDocument();
  });
  it("global search selection returns to the bounded identity neighborhood", async () => {
    await ready();
    await roles();
    const fallback = handler;
    handler = (p, o) =>
      p.startsWith("graph/search")
        ? { revision: "r1", nodes: [agent], has_more: false }
        : fallback(p, o);
    fireEvent.change(screen.getByLabelText("Search identities"), {
      target: { value: "Initial" },
    });
    const results = screen.getByLabelText("Global identity search");
    fireEvent.click(
      await within(results).findByRole("button", { name: /Initial agent/ }),
    );
    await screen.findByRole("button", { name: "Initial agent" });
    expect(
      screen.getByRole("button", { name: "Identity & data" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(api).toHaveBeenCalledWith(
      "graph/explore?root_id=Initial+agent&node_limit=250&edge_limit=1000&revision=r1",
      expect.anything(),
    );
  });
  it("resets visible-only filters on mode change and honors viewer simulation permissions", async () => {
    roleName = "viewer";
    await ready();
    fireEvent.change(screen.getByLabelText("Filter by identity type"), {
      target: { value: "AIAgent" },
    });
    await roles();
    expect(screen.getByLabelText("Filter by identity type")).toHaveValue("");
    fireEvent.click(screen.getByRole("button", { name: "Global role A" }));
    expect(
      screen.getByRole("button", { name: "Simulate compromise" }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Explore neighborhood" }),
    );
    await screen.findByRole("button", { name: "Initial agent" });
    expect(
      screen.getByRole("button", { name: "Identity & data" }),
    ).toHaveAttribute("aria-pressed", "true");
  });
  it("empty role map is not an empty workspace or demo ingestion invitation", async () => {
    await ready();
    const fallback = handler;
    handler = (p, o) =>
      p.startsWith("graph/roles")
        ? {
            ...page([], false),
            view: {
              ...page([], false).view,
              total_roles: 0,
              total_role_edges: 0,
              role_map_truncated: false,
            },
          }
        : fallback(p, o);
    fireEvent.click(screen.getByRole("button", { name: "Role map" }));
    expect(
      await screen.findByRole("heading", {
        name: "No roles in this workspace",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Load sample environment" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/0 \/ 0 roles/)).toHaveTextContent(
      "Complete role map",
    );
    expect(screen.getByText(/0 \/ 0 roles/)).toHaveTextContent("1000 nodes");
  });
  it("exports only the visible role page and summaries matching its filtered IDs", async () => {
    await ready();
    const fallback = handler;
    handler = (p, o) =>
      p.startsWith("graph/roles") ? page([role, other]) : fallback(p, o);
    await roles();
    fireEvent.change(screen.getByLabelText("Filter by account"), {
      target: { value: "prod" },
    });
    let blob!: Blob;
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: vi.fn((b: Blob) => {
        blob = b;
        return "blob:test";
      }),
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      value: vi.fn(),
    });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    fireEvent.click(
      screen.getByRole("button", { name: "Export visible role page" }),
    );
    const text = await new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.readAsText(blob);
    });
    const exported = JSON.parse(text);
    expect(exported.export_scope).toBe("current visible role-map page");
    expect(exported.nodes.map((n: GraphNode) => n.id)).toEqual([role.id]);
    expect(
      exported.role_summaries.map((s: { role_id: string }) => s.role_id),
    ).toEqual([role.id]);
    click.mockRestore();
  });
});
