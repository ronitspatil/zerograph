import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Rollout, rolloutStatus } from "@/components/rollout";
import { api } from "@/lib/api";
import type { RolloutChange, RolloutList } from "@/lib/types";
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  api: vi.fn(),
}));

const change = (patch: Partial<RolloutChange>): RolloutChange => ({
  id: "c1",
  scope: "role",
  topic_id: "t1",
  subject_id: "arn:aws:iam::1:role/lake-reader",
  subject_name: "lake-reader",
  state: "draft",
  canary: false,
  held: false,
  held_reason: "",
  revision: "rev-1",
  proposal_ids: ["p1"],
  proposal_count: 3,
  draft_count: 0,
  principals: ["arn:aws:iam::1:role/lake-reader"],
  files: [
    {
      path: "lake-reader/inline-a.json",
      principal: "arn:aws:iam::1:role/lake-reader",
      op: "rewrite",
      policy_kind: "inline",
      policy_name: "a",
    },
  ],
  pr_url: null,
  pr_requested: false,
  merged_at: null,
  watch_days: 7,
  watch_ends: null,
  watch_remaining_days: null,
  verified_at: null,
  flagged_at: null,
  flag: null,
  revert_pr_url: null,
  revert_requested: false,
  revert_error: null,
  rolled_back_at: null,
  created_at: "2026-10-07T00:00:00Z",
  ...patch,
});

const list: RolloutList = {
  changes: [
    change({
      id: "c1",
      canary: true,
      state: "merged",
      pr_url: "https://github.com/acme/policies/pull/1",
      watch_remaining_days: 4.5,
    }),
    change({
      id: "c2",
      subject_name: "lake-writer",
      held: true,
      held_reason: "Waiting for canary lake-reader: watching for AccessDenied",
    }),
    change({
      id: "c3",
      subject_name: "crm-etl",
      state: "revert_open",
      pr_url: "https://github.com/acme/policies/pull/2",
      revert_pr_url: "https://github.com/acme/policies/pull/3",
      flag: { events: 2, pairs: [] },
    }),
  ],
  canaries: {},
  watch_days: 7,
  denied_threshold: 1,
  gitops_configured: true,
  notice: "",
};

let calls: string[] = [];
beforeEach(() => {
  calls = [];
  vi.mocked(api).mockImplementation(async (path) => {
    calls.push(path);
    if (path === "rollout") return list as never;
    return {} as never;
  });
});

describe("Rollout panel", () => {
  it("labels states, canary countdown, holds, flags and links", async () => {
    render(<Rollout canAdmin />);
    await act(async () => {});
    expect(
      screen.getByText(/Nothing is applied by ZeroGraph\./),
    ).toBeInTheDocument();
    expect(screen.getByText("Canary watch · 4.5 d left")).toBeInTheDocument();
    expect(screen.getByText("Waiting for canary")).toBeInTheDocument();
    expect(
      screen.getByText(/AccessDenied after merge: 2 events/),
    ).toBeInTheDocument();
    expect(screen.getByText("Revert: acme/policies/pull/3")).toHaveAttribute(
      "href",
      "https://github.com/acme/policies/pull/3",
    );
    const held = screen.getByText("lake-writer").closest("article")!;
    expect(
      within(held).getByRole("button", { name: "Open PR" }),
    ).toBeDisabled();
  });

  it("opens a revert pull request and records merges for administrators only", async () => {
    render(<Rollout canAdmin />);
    await act(async () => {});
    const canary = screen.getByText("lake-reader").closest("article")!;
    fireEvent.click(
      within(canary).getByRole("button", { name: "Open revert PR" }),
    );
    await act(async () => {});
    expect(calls).toContain("rollout/changes/c1/revert");
    expect(screen.getByText(/Revert pull request opened/)).toBeInTheDocument();
    const reverting = screen.getByText("crm-etl").closest("article")!;
    fireEvent.click(
      within(reverting).getByRole("button", { name: "Mark reverted" }),
    );
    await act(async () => {});
    expect(calls).toContain("rollout/changes/c3/reverted");
  });

  it("shows a merge warning and a refused revert on a merged change", async () => {
    const refused =
      "The change is not on the base branch (not merged, or already reverted); nothing to revert";
    vi.mocked(api).mockImplementation(async (path) => {
      calls.push(path);
      if (path === "rollout")
        return {
          ...list,
          changes: [
            change({
              id: "c4",
              subject_name: "etl-runner",
              state: "pr_open",
              pr_url: "https://github.com/acme/policies/pull/4",
            }),
            change({
              id: "c5",
              subject_name: "lake-auditor",
              state: "merged",
              watch_remaining_days: 6,
              flag: { events: 1, pairs: [] },
              revert_error: refused,
            }),
          ],
        } as never;
      return {
        state: "merged",
        warning:
          "The Git provider does not show this pull request as merged; recorded anyway.",
      } as never;
    });
    render(<Rollout canAdmin />);
    await act(async () => {});
    expect(screen.getByText(`Revert failed: ${refused}`)).toBeInTheDocument();
    const auditor = screen.getByText("lake-auditor").closest("article")!;
    expect(
      within(auditor).getByRole("button", { name: "Open revert PR" }),
    ).toBeEnabled();
    const pending = screen.getByText("etl-runner").closest("article")!;
    fireEvent.click(
      within(pending).getByRole("button", { name: "Mark merged" }),
    );
    await act(async () => {});
    expect(calls).toContain("rollout/changes/c4/merged");
    expect(
      screen.getByText(
        /Recorded as merged.*Warning: The Git provider does not show/,
      ),
    ).toBeInTheDocument();
  });

  it("keeps actions disabled for viewers", async () => {
    render(<Rollout canAdmin={false} />);
    await act(async () => {});
    for (const button of screen.getAllByRole("button"))
      expect(button).toBeDisabled();
  });

  it("summarizes states", () => {
    expect(rolloutStatus(change({ state: "verified" }))).toBe("Verified");
    expect(rolloutStatus(change({ state: "pr_open" }))).toBe("PR open");
    expect(rolloutStatus(change({ state: "rolled_back" }))).toBe("Rolled back");
  });
});
