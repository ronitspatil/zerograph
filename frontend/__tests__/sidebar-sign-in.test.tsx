import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Console } from "@/components/console";
import { api, ApiError } from "@/lib/api";
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: vi.fn() };
});
vi.mock("next/dynamic", () => ({
  default: () => () => <div>Bounded canvas</div>,
}));
const notice = "Single sign-on isn’t configured — ask your administrator.";
let me: Record<string, unknown>;
const never = () => new Promise<never>(() => {});
const graph = {
  revision: "r1",
  nodes: [],
  edges: [],
  warnings: [],
  view: {
    mode: "sample",
    root_id: null,
    node_limit: 250,
    edge_limit: 1000,
    truncated: false,
    total_nodes: 0,
    total_edges: 0,
  },
};
beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
  me = { subject: "demo", tenant_id: "demo", roles: ["admin"] };
  vi.mocked(api).mockImplementation(
    async (path) =>
      (path === "me"
        ? me
        : path.startsWith("graph/")
          ? graph
          : path === "overview"
            ? never()
            : []) as never,
  );
});
const bottom = () => document.querySelector(".sidebar-bottom") as HTMLElement;

describe("sidebar sign-in", () => {
  it("offers one-click organization sign-in in the demo when SSO is configured", async () => {
    render(<Console demo sso />);
    const link = within(bottom()).getByRole("link", {
      name: "Sign in with your organization",
    });
    expect(link).toHaveAttribute("href", "/api/auth/login");
    expect(link).toHaveTextContent("Sign in");
    expect(
      within(bottom()).queryByRole("button", { name: "Sign out" }),
    ).toBeNull();
    expect(
      await within(bottom()).findByText("Demo operator"),
    ).toBeInTheDocument();
  });

  it("explains a missing SSO configuration next to the button, never a dead click", async () => {
    render(<Console demo sso={false} />);
    const button = within(bottom()).getByRole("button", {
      name: "Sign in with your organization",
    });
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText(notice)).toBeNull();
    fireEvent.click(button);
    expect(button).toHaveAttribute("aria-expanded", "true");
    const panel = document.getElementById("sidebar-sso-notice")!;
    expect(panel).toHaveAttribute("role", "status");
    expect(panel).toHaveTextContent(notice);
    // Escape, a click elsewhere and the close button all dismiss it.
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByText(notice)).toBeNull();
    expect(button).toHaveFocus();
    fireEvent.click(button);
    fireEvent.pointerDown(document.body);
    expect(screen.queryByText(notice)).toBeNull();
    fireEvent.click(button);
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(notice)).toBeNull();
  });

  it("keeps Sign in usable on the collapsed icon rail", async () => {
    window.localStorage.setItem("zg.sidebar.rail", "1");
    const { container, rerender } = render(<Console demo sso />);
    expect(container.querySelector(".app-shell.rail")).not.toBeNull();
    const link = within(bottom()).getByRole("link", {
      name: "Sign in with your organization",
    });
    expect(link).toHaveAttribute("title", "Sign in");
    rerender(<Console demo sso={false} />);
    const button = within(bottom()).getByRole("button", {
      name: "Sign in with your organization",
    });
    expect(button).toHaveAttribute("title", "Sign in");
    // jsdom lays nothing out, so the rail's narrow button opens the notice beside it.
    fireEvent.click(button);
    const panel = document.getElementById("sidebar-sso-notice")!;
    expect(panel).toHaveTextContent(notice);
    expect(panel.style.left).toBe("8px");
  });

  it("shows the organization user with Sign out, and no Sign in", async () => {
    me = {
      subject: "u1",
      name: "ada.admin",
      tenant_id: "demo",
      roles: ["admin"],
    };
    render(<Console demo={false} sso />);
    expect(await within(bottom()).findByText("ada.admin")).toBeInTheDocument();
    expect(within(bottom()).getByText("Administrator")).toBeInTheDocument();
    expect(
      within(bottom()).getByRole("button", { name: "Sign out" }),
    ).toBeInTheDocument();
    expect(
      within(bottom()).queryByRole("link", { name: /Sign in/ }),
    ).toBeNull();
    expect(
      within(bottom()).queryByRole("button", { name: /Sign in/ }),
    ).toBeNull();
  });

  it("titles Sign out on the collapsed rail", () => {
    window.localStorage.setItem("zg.sidebar.rail", "1");
    render(<Console demo={false} />);
    expect(
      within(bottom()).getByRole("button", { name: "Sign out" }),
    ).toHaveAttribute("title", "Sign out");
  });
});

describe("expired sessions", () => {
  const assign = vi.fn();
  beforeEach(() => {
    assign.mockReset();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...window.location, assign },
    });
    vi.mocked(api).mockImplementation(async () => {
      throw new ApiError("Session expired. Sign in again.", 401);
    });
  });

  it("re-enters through /login, where the demo gets a fresh session", async () => {
    render(<Console demo sso />);
    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
  });

  it("stops instead of reloading forever when the demo session keeps failing", async () => {
    window.sessionStorage.setItem("zg.session.reentry", String(Date.now()));
    render(<Console demo sso />);
    expect(
      await screen.findByText(/demo workspace couldn’t open a session/),
    ).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it("always sends an organization session back to sign-in", async () => {
    window.sessionStorage.setItem("zg.session.reentry", String(Date.now()));
    render(<Console demo={false} />);
    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
  });
});
