import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Simulator } from "@/components/simulator";
import { api } from "@/lib/api";
import type { GraphNode } from "@/lib/types";
vi.mock("@/lib/api", () => ({ api: vi.fn() }));
const node: GraphNode = {
  id: "agent:test",
  name: "Test Agent",
  type: "AIAgent",
  account_id: "prod",
  provider: "langgraph",
  sensitivity: "internal",
  tags: [],
  internet_exposed: true,
  authenticated: false,
  encrypted: true,
  privileged: false,
  metadata: {},
};
const result = {
  source: node.id,
  max_hops: 3,
  risk_score: 83,
  affected_nodes: ["db:customers"],
  affected_assets: ["db:customers"],
  highlighted_edges: [],
  paths: {},
  sensitivity_exposure: 1,
  centrality: 0.2,
  includes_uncertain: false,
  explanation: "Heuristic score, not a breach probability.",
};
beforeEach(() => vi.clearAllMocks());
describe("Blast radius simulator", () => {
  it("loads a confirmed-only scenario and reports affected assets", async () => {
    vi.mocked(api).mockResolvedValue(result);
    const onResult = vi.fn();
    render(<Simulator node={node} onResult={onResult} onClose={vi.fn()} />);
    expect(screen.getByLabelText("Traversal depth")).toHaveValue("3");
    await waitFor(() =>
      expect(screen.getByText("db:customers")).toBeInTheDocument(),
    );
    expect(
      JSON.parse(vi.mocked(api).mock.calls[0][1]!.body as string)
        .include_uncertain,
    ).toBe(false);
    expect(onResult).toHaveBeenCalledWith(result);
  });
  it("changes hop count and opts into uncertain paths", async () => {
    vi.mocked(api).mockResolvedValue(result);
    render(<Simulator node={node} onResult={vi.fn()} onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Traversal depth"), {
      target: { value: "5" },
    });
    fireEvent.click(
      screen.getByLabelText("Include conditional and declared access"),
    );
    await waitFor(() => expect(api).toHaveBeenCalled());
    const body = JSON.parse(
      vi.mocked(api).mock.calls.at(-1)![1]!.body as string,
    );
    expect(body).toMatchObject({ max_hops: 5, include_uncertain: true });
  });
  it("shows backend errors instead of a fabricated result", async () => {
    vi.mocked(api).mockRejectedValue(new Error("Identity not found"));
    render(<Simulator node={node} onResult={vi.fn()} onClose={vi.fn()} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Identity not found",
    );
  });
  it("closes the drawer", () => {
    const close = vi.fn();
    render(<Simulator node={node} onResult={vi.fn()} onClose={close} />);
    fireEvent.click(screen.getByRole("button", { name: "Close simulator" }));
    expect(close).toHaveBeenCalledOnce();
  });
});
