import type { ProposalTier, ProposalType } from "@/lib/types";

export const TIERS: ProposalTier[] = [
  "high",
  "medium",
  "low",
  "inferred",
  "manual",
];

export const TIER_LABELS: Record<ProposalTier, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  inferred: "Inferred",
  manual: "Manual",
};

/** What each tier rests on (shown as the tier's tooltip and in the evidence panel). */
export const TIER_HINTS: Record<ProposalTier, string> = {
  high: "Unused through the full attested window; the asset is outside the role's topic",
  medium: "Unused through the full attested window, inside the role's topic",
  low: "Unused by this role, but most same-topic peers granted it use it",
  inferred:
    "Coverage too short or stale; the peer baseline says it is not needed",
  manual: "On the never-auto list: a person decides",
};

export const TYPE_LABELS: Record<ProposalType, string> = {
  remove_grant: "Remove unused grant",
  disable_identity: "Disable dormant identity",
  disable_role: "Disable dormant role",
  merge_roles: "Merge near-duplicate roles",
  split_role: "Split over-broad role",
  scope_wildcard: "Scope wildcard grant",
  break_toxic_path: "Break toxic path",
};

export const TYPES = Object.keys(TYPE_LABELS) as ProposalType[];

export const COVERAGE_LABELS: Record<string, string> = {
  sufficient: "Sufficient (90 days, fresh, complete)",
  partial: "Complete but short or stale",
  none: "Not covered",
};

/** "47.9%" style index text with one decimal (EPI deltas are often small). */
export function epiPrecise(value: number | null | undefined): string {
  return typeof value === "number" && Number.isFinite(value)
    ? `${(value * 100).toFixed(1)}%`
    : "—";
}
