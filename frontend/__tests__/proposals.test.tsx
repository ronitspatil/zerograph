import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Proposals } from "@/components/proposals";
import { api, ApiError } from "@/lib/api";
import type {
  Proposal,
  ProposalDetail,
  ProposalSummary,
  WhatIfSide,
} from "@/lib/types";
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  api: vi.fn(),
}));

const side = (epi: number): WhatIfSide => ({
  granted_weight: 100,
  needed_weight: 50,
  granted_weight_excl_hubs: 80,
  needed_weight_excl_hubs: 40,
  epi,
  epi_excl_hubs: epi - 0.1,
});
const summary: ProposalSummary = {
  revision: "rev-1",
  total: 93397,
  by_tier: { high: 32361, medium: 16835, low: 43425, inferred: 0, manual: 776 },
  by_type: {
    remove_grant: 86058,
    disable_identity: 6097,
    disable_role: 466,
    merge_roles: 746,
    split_role: 27,
    scope_wildcard: 3,
    break_toxic_path: 0,
  },
  topics: {
    t000000000000001: {
      total: 10,
      by_tier: { high: 4, medium: 3, low: 2, inferred: 0, manual: 1 },
      high_after: { identities: side(0.4) },
    },
  },
  high_tier: {
    graph: {
      roles: { rows: 2, before: side(0.479), after: side(0.403) },
      identities: { rows: 3, before: side(0.983), after: side(0.979) },
    },
    counts: { grants_removed: 25798, disabled_nodes: 6563 },
  },
  evidence: { status: "attested" },
  never_auto: {
    trust: "Changes a role trust policy (who can assume which role)",
  },
  decisions: { accepted: 0, rejected: 0 },
  notice: "Proposed, not applied.",
};
const proposal: Proposal = {
  id: "p0000000000000000001",
  ordinal: 0,
  type: "remove_grant",
  tier: "high",
  base_tier: "high",
  status: "proposed",
  topic_id: "t000000000000001",
  subject_id: "role:a",
  subject_name: "lake-reader",
  subject_type: "CloudRole",
  target_id: "pay:0",
  target_name: "payments-ledger",
  weight: 10,
  identities: 12,
  epi_before: 0.7,
  epi_after: 0.5,
  reasons: [],
  evidence: {
    service: "s3",
    coverage: "sufficient",
    peers: [4, 0],
    identities_sample: ["svc:a"],
  },
  changes: [
    {
      op: "remove_grant",
      source: "role:a",
      target: "pay:0",
      edge_id: "e1",
      type: "CAN_READ",
      actions: ["s3:GetObject"],
    },
  ],
  decision: null,
};
const detail: ProposalDetail = {
  revision: "rev-1",
  proposal,
  topic: {
    id: "t000000000000001",
    name: "data-lake",
    label: "data-lake",
    reason: "Tagged",
  },
  resource: {
    id: "pay:0",
    name: "payments-ledger",
    type: "S3Bucket",
    sensitivity: "restricted",
    topic_id: "t2",
    topic: "payments-db",
    label_seed: "tag",
    label_reason: "tag topic=payments-db",
  },
  evidence: {
    status: "attested",
    window_start: "2026-07-01T00:00:00+00:00",
    window_end: "2026-10-01T00:00:00+00:00",
  },
  never_auto: {},
  graph_delta: {
    graph: {
      roles: { rows: 1, before: side(0.5), after: side(0.49) },
      identities: { rows: 1, before: side(0.983), after: side(0.982) },
    },
    counts: {},
    applied: { remove_grant: 1 },
    skipped: {},
  },
  notice: "",
};

let calls: { path: string; init?: RequestInit }[] = [];
let decided: Proposal["decision"] = null;
beforeEach(() => {
  calls = [];
  decided = null;
  vi.mocked(api).mockImplementation(async (path, init) => {
    calls.push({ path, init });
    if (path === "proposals/summary") return summary as never;
    if (path.startsWith("graph/topics"))
      return {
        revision: "rev-1",
        topics: [{ id: "t000000000000001", label: "data-lake" }],
      } as never;
    if (path.startsWith("proposals?"))
      return {
        revision: "rev-1",
        proposals: [proposal],
        summary,
        view: {
          total: 1,
          shown: 1,
          limit: 50,
          cursor: null,
          next_cursor: null,
        },
        notice: "",
      } as never;
    if (path === "proposals/simulate")
      return {
        source: "role:a",
        risk_score: 40,
        affected_assets: ["pay:0", "lake:0"],
        whatif: {
          after: { risk_score: 12, affected_assets: ["lake:0"] },
          risk_delta: -28,
          exposure_delta: -0.2,
          assets_removed: ["pay:0"],
          assets_removed_count: 1,
          nodes_removed_count: 1,
          overlay: {
            applied: { remove_grant: 1 },
            skipped: {},
            removed_edges: 1,
            disabled_nodes: 0,
          },
          notice: "",
        },
      } as never;
    if (path.endsWith("/decision")) {
      decided = {
        state: "accepted",
        actor: "alice",
        decided_at: "2026-10-07T00:00:00Z",
        revision: "rev-1",
        note: "",
        stale: false,
      };
      return {} as never;
    }
    if (path.startsWith("proposals/p"))
      return {
        ...detail,
        proposal: { ...proposal, decision: decided },
      } as never;
    throw new Error(`unexpected ${path}`);
  });
});

describe("Proposals view", () => {
  it("labels proposals as not applied and shows the high-tier what-if", async () => {
    render(<Proposals canAdmin />);
    await act(async () => {});
    expect(screen.getByText(/Proposed, not applied\./)).toBeInTheDocument();
    expect(
      screen.getByText(/pull requests come in Phase 4/),
    ).toBeInTheDocument();
    expect(screen.getByText("98.3% → 97.9%")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /High · 32,361/ }),
    ).toBeInTheDocument();
    expect(screen.getByText("1 of 1 shown")).toBeInTheDocument();
  });

  it("filters by tier and type with the API's own filters", async () => {
    render(<Proposals canAdmin />);
    await act(async () => {});
    fireEvent.click(screen.getByRole("button", { name: /High · 32,361/ }));
    await act(async () => {});
    expect(calls.at(-1)?.path).toContain("tier=high");
    fireEvent.change(screen.getByLabelText("Type"), {
      target: { value: "merge_roles" },
    });
    await act(async () => {});
    expect(calls.at(-1)?.path).toMatch(/tier=high&type=merge_roles/);
  });

  it("opens the evidence, simulates before/after and records a decision", async () => {
    render(<Proposals canAdmin />);
    await act(async () => {});
    fireEvent.click(
      screen.getByRole("button", { name: /Remove unused grant/ }),
    );
    await act(async () => {});
    const panel = screen.getByLabelText("Proposal evidence");
    expect(
      within(panel).getByText("Proposed · not applied"),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText("tag topic=payments-db"),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText("0 of 4 granted it use it"),
    ).toBeInTheDocument();
    expect(within(panel).getByText("70.0% → 50.0%")).toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Simulate" }));
    await act(async () => {});
    expect(within(panel).getByText("40 → 12")).toBeInTheDocument();
    expect(within(panel).getByText("2 → 1")).toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Accept" }));
    await act(async () => {});
    const decision = calls.find((c) => c.path.endsWith("/decision"));
    expect(JSON.parse(String(decision?.init?.body))).toEqual({
      state: "accepted",
      revision: "rev-1",
    });
    expect(within(panel).getByText(/Accepted by alice/)).toBeInTheDocument();
  });

  it("keeps decisions read-only for non-administrators", async () => {
    render(<Proposals canAdmin={false} />);
    await act(async () => {});
    fireEvent.click(
      screen.getByRole("button", { name: /Remove unused grant/ }),
    );
    await act(async () => {});
    expect(screen.getByRole("button", { name: "Accept" })).toBeDisabled();
    expect(
      screen.getByText(/Administrators record decisions/),
    ).toBeInTheDocument();
  });

  it("explains a revision whose proposals are not built yet", async () => {
    vi.mocked(api).mockImplementation(async () => {
      throw new ApiError(
        "Proposals are not computed for this revision yet",
        404,
      );
    });
    render(<Proposals canAdmin />);
    await act(async () => {});
    expect(screen.getByText("Proposals not available yet")).toBeInTheDocument();
  });
});
