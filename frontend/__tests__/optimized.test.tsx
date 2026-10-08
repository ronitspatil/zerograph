import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Proposals } from "@/components/proposals";
import { OptimizerTiles } from "@/components/optimizer-tiles";
import { OptimizedBar, overlayStatus } from "@/components/optimized";
import { api } from "@/lib/api";
import {
  edgeRemoved,
  getProposalSet,
  overlaySets,
  resetProposalSet,
  selectionBody,
  setCustomSet,
  setProposalSetKind,
} from "@/lib/optimized";
import type { OptimizerOverview, Proposal, WhatIfSide } from "@/lib/types";
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  api: vi.fn(),
}));

const side = (epi: number, core = epi - 0.3): WhatIfSide => ({
  granted_weight: 100,
  needed_weight: 50,
  granted_weight_excl_hubs: 80,
  needed_weight_excl_hubs: 40,
  epi,
  epi_excl_hubs: core,
});

describe("Proposal set and overlay sets", () => {
  beforeEach(() => resetProposalSet());
  it("selects the high tier, the accepted set or custom IDs", () => {
    expect(selectionBody(getProposalSet())).toEqual({ tier: "high" });
    setProposalSetKind("custom"); // ignored: no custom IDs yet
    expect(getProposalSet().kind).toBe("high");
    setProposalSetKind("accepted");
    expect(selectionBody(getProposalSet())).toEqual({ decision: "accepted" });
    setCustomSet(["p1", "p2", "p1"], "High · lake", "rev");
    expect(selectionBody(getProposalSet())).toEqual({
      proposal_ids: ["p1", "p2"],
    });
  });
  it("matches grants and hops by pair and kind", () => {
    const sets = overlaySets({
      removed_edges: [
        { source: "r", target: "b", kind: "grant" },
        { source: "s", target: "r", kind: "hop" },
      ],
      disabled_nodes: ["x"],
    });
    expect(
      edgeRemoved(sets, { source: "r", target: "b", type: "CAN_READ" }),
    ).toBe(true);
    expect(
      edgeRemoved(sets, { source: "r", target: "b", type: "CAN_WRITE" }),
    ).toBe(true);
    // A hop between the same pair is not a removed grant, and vice versa.
    expect(
      edgeRemoved(sets, { source: "r", target: "b", type: "ASSUMES_ROLE" }),
    ).toBe(false);
    expect(
      edgeRemoved(sets, { source: "s", target: "r", type: "ASSUMES_ROLE" }),
    ).toBe(true);
    expect(sets.disabled.has("x")).toBe(true);
  });
  it("describes the optimized slice with formatted counts", () => {
    const text = overlayStatus(
      true,
      {
        overlay: {
          revision: "rev",
          selected: 35074,
          removed_edges: [],
          disabled_nodes: [],
          slice: {
            nodes: 400,
            outside_model: 0,
            grants_removed: 126,
            hops_cut: 0,
            disabled_nodes: 1,
          },
          totals: {
            grants_removed: 29454,
            restricted_grants_removed: 10,
            hops_cut: 0,
            disabled_nodes: 5613,
          },
          applied: {},
          skipped: {},
          notice: "",
        },
        sets: null,
        busy: false,
        error: "",
      },
      getProposalSet(),
    );
    expect(text).toContain("126 edges removed");
    expect(text).toContain("1 node disabled");
    expect(text).toContain("29,454 grants");
    expect(text).toContain("simulated, not applied");
    expect(overlayStatus(false, {} as never, getProposalSet())).toMatch(
      /^Current/,
    );
  });
  it("toggles Current and Optimized with pressed state", () => {
    const toggle = vi.fn();
    render(
      <OptimizedBar optimized={false} onToggle={toggle} status="Current" />,
    );
    expect(screen.getByRole("button", { name: "Current" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    fireEvent.click(screen.getByRole("button", { name: "Optimized" }));
    expect(toggle).toHaveBeenCalledWith(true);
  });
});

describe("Optimizer overview tiles", () => {
  it("shows EPI now to accepted and high tier, dormant, restricted and rollout", async () => {
    const data: OptimizerOverview = {
      revision: "rev",
      evidence: { status: "attested" },
      now: { roles: side(0.47), identities: side(0.957, 0.603) },
      after_accepted: { roles: side(0.46), identities: side(0.956, 0.596) },
      after_high: { roles: side(0.38), identities: side(0.95, 0.411) },
      accepted: { selected: 1500, counts: {} },
      high: { selected: 35074, counts: {} },
      decisions: { accepted: 1500, rejected: 0 },
      dormant_identities: 5164,
      dormant_roles: 466,
      unused_grants: 98288,
      unused_restricted_grants: 18248,
      rollout: {
        draft: 1,
        pr_open: 2,
        merged: 1,
        verified: 3,
        revert_open: 0,
        rolled_back: 1,
        canary_watching: 1,
      },
      notice: "",
    };
    vi.mocked(api).mockResolvedValue(data as never);
    await act(async () => {
      render(<OptimizerTiles reloadKey={0} onOpenQueue={() => {}} />);
    });
    expect(screen.getByText("95.7% → 95.6%")).toBeInTheDocument();
    expect(screen.getByText(/Without hubs 60.3% → 41.1%/)).toBeInTheDocument();
    expect(screen.getByText("5,164")).toBeInTheDocument();
    expect(screen.getByText("18,248")).toBeInTheDocument();
    expect(screen.getByText(/1,500 accepted/)).toBeInTheDocument();
    expect(screen.getByText("PRs open").nextSibling).toHaveTextContent("2");
  });
});

const row = (id: string, tier: Proposal["tier"], topic: string): Proposal =>
  ({
    id,
    ordinal: Number(id.slice(-2)),
    type: "remove_grant",
    tier,
    base_tier: tier,
    status: "proposed",
    topic_id: topic,
    subject_id: "role:a",
    subject_name: "lake-reader",
    subject_type: "CloudRole",
    target_id: "pay:0",
    target_name: "payments",
    weight: 10,
    identities: 1,
    epi_before: 0.5,
    epi_after: 0.4,
    reasons: [],
    evidence: {},
    changes: [],
    decision: null,
  }) as Proposal;

describe("Proposal queue bulk review", () => {
  let posts: { path: string; body: unknown }[] = [];
  beforeEach(() => {
    posts = [];
    resetProposalSet();
    vi.mocked(api).mockImplementation(async (path, init) => {
      if (init?.method === "POST")
        posts.push({ path, body: JSON.parse(String(init.body)) });
      if (path === "proposals/summary")
        return {
          total: 3,
          by_tier: { high: 2, medium: 1, low: 0, inferred: 0, manual: 0 },
          by_type: {},
          topics: {
            t000000000000001: {
              total: 3,
              by_tier: { high: 2, medium: 1, low: 0, inferred: 0, manual: 0 },
              high_after: {},
            },
          },
          high_tier: { graph: null, counts: {} },
          decisions: { accepted: 0, rejected: 0 },
        } as never;
      if (path.startsWith("graph/topics"))
        return {
          topics: [{ id: "t000000000000001", label: "data-lake" }],
        } as never;
      if (path.startsWith("proposals?")) {
        const tier = new URLSearchParams(path.slice(10)).get("tier");
        const rows = [
          row("p0000000000000000001", "high", "t000000000000001"),
          row("p0000000000000000002", "high", "t000000000000001"),
          row("p0000000000000000003", "medium", "t000000000000001"),
        ].filter((p) => !tier || p.tier === tier);
        return {
          revision: "rev-1",
          proposals: rows,
          summary: {},
          view: {
            total: rows.length,
            shown: rows.length,
            limit: 50,
            cursor: null,
            next_cursor: null,
          },
        } as never;
      }
      if (path === "proposals/decisions")
        return { decided: 2, decisions: { accepted: 2 } } as never;
      return {} as never;
    });
  });

  it("keeps bulk accept within one tier and topic and confirms in place", async () => {
    const confirm = vi.spyOn(window, "confirm");
    await act(async () => {
      render(<Proposals canAdmin />);
    });
    const accept = screen.getByRole("button", { name: "Accept shown…" });
    expect(accept).toBeDisabled();
    expect(
      screen.getByText(/choose one tier and one topic/),
    ).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(
        within(screen.getByRole("group", { name: "Tier" })).getByRole(
          "button",
          {
            name: /^High/,
          },
        ),
      );
    });
    await act(async () => {
      fireEvent.change(screen.getByLabelText("Topic"), {
        target: { value: "t000000000000001" },
      });
    });
    expect(accept).toBeEnabled();
    fireEvent.click(accept);
    const confirmButton = screen.getByRole("button", {
      name: "Confirm accept 2",
    });
    expect(confirmButton).toHaveFocus();
    // Escape cancels without deciding anything.
    fireEvent.keyDown(confirmButton, { key: "Escape" });
    expect(
      screen.queryByRole("button", { name: "Confirm accept 2" }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Accept shown…" }));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Confirm accept 2" }));
    });
    const bulk = posts.find((p) => p.path === "proposals/decisions");
    expect(bulk?.body).toEqual({
      proposal_ids: ["p0000000000000000001", "p0000000000000000002"],
      state: "accepted",
      tier: "high",
      topic_id: "t000000000000001",
      revision: "rev-1",
    });
    expect(confirm).not.toHaveBeenCalled();
    expect(screen.getByText(/Accepted 2 proposals/)).toBeInTheDocument();
  });

  it("uses the shown proposals as the custom set and keeps the Advanced tool", async () => {
    await act(async () => {
      render(<Proposals canAdmin advanced={<p>Single policy tool</p>} />);
    });
    fireEvent.click(screen.getByRole("button", { name: "Use as custom set" }));
    expect(getProposalSet().kind).toBe("custom");
    expect(getProposalSet().ids).toHaveLength(3);
    fireEvent.click(screen.getByRole("button", { name: "Advanced" }));
    expect(screen.getByText("Single policy tool")).toBeInTheDocument();
  });

  it("does not offer bulk accept for the manual tier", async () => {
    await act(async () => {
      render(<Proposals canAdmin />);
    });
    await act(async () => {
      fireEvent.click(
        within(screen.getByRole("group", { name: "Tier" })).getByRole(
          "button",
          {
            name: /^Manual/,
          },
        ),
      );
    });
    expect(screen.getByText(/one at a time/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Accept shown…" }),
    ).toBeDisabled();
  });
});
