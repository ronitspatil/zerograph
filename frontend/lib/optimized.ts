import { useSyncExternalStore } from "react";

/**
 * The proposal set behind every "Optimized" view (explorer overlay, topic page, topics
 * lens): the whole high tier, the proposals the tenant accepted, or a custom set picked
 * in the proposal queue. One shared choice, so every view shows the same what-if.
 * Simulated only: nothing is applied.
 */
export type ProposalSetKind = "high" | "accepted" | "custom";

export interface ProposalSet {
  kind: ProposalSetKind;
  /** Custom set: proposal IDs and where they came from (e.g. "High · data-lake"). */
  ids: string[];
  label: string;
  /** Revision the custom IDs were picked on (IDs are stable, but only this one is shown). */
  revision: string;
}

/** The server accepts at most this many explicit proposal IDs per request. */
export const MAX_CUSTOM = 2000;

export const SET_LABELS: Record<ProposalSetKind, string> = {
  high: "High tier",
  accepted: "Accepted",
  custom: "Custom set",
};

let current: ProposalSet = { kind: "high", ids: [], label: "", revision: "" };
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

export function getProposalSet(): ProposalSet {
  return current;
}

export function setProposalSetKind(kind: ProposalSetKind): void {
  if (kind === "custom" && !current.ids.length) return;
  if (current.kind === kind) return;
  current = { ...current, kind };
  emit();
}

/** Use these queue proposals as the custom set (and select it). */
export function setCustomSet(ids: string[], label: string, revision: string) {
  current = {
    kind: "custom",
    ids: [...new Set(ids)].slice(0, MAX_CUSTOM),
    label,
    revision,
  };
  emit();
}

/** Test hook. */
export function resetProposalSet(): void {
  current = { kind: "high", ids: [], label: "", revision: "" };
  emit();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useProposalSet(): ProposalSet {
  return useSyncExternalStore(subscribe, getProposalSet, getProposalSet);
}

/** Request body fields selecting the set (POST /proposals/overlay, /links, /metrics). */
export function selectionBody(
  set: ProposalSet,
): { tier: "high" } | { decision: "accepted" } | { proposal_ids: string[] } {
  if (set.kind === "accepted") return { decision: "accepted" };
  if (set.kind === "custom") return { proposal_ids: set.ids };
  return { tier: "high" };
}

/** Short description of the set for count lines ("High tier", "Custom set: 12 · High · lake"). */
export function setDescription(set: ProposalSet): string {
  if (set.kind !== "custom") return SET_LABELS[set.kind];
  return `Custom set (${set.ids.length.toLocaleString("en-US")}${set.label ? ` · ${set.label}` : ""})`;
}

/** Key of a directed relationship, for matching overlay edges. */
export function pairKey(source: string, target: string): string {
  return `${source}\u0000${target}`;
}

const GRANT_TYPES = new Set(["CAN_READ", "CAN_WRITE"]);

/** The overlay as sets the canvases apply: removed edge pairs by kind and disabled nodes. */
export interface OverlaySets {
  grants: Set<string>;
  hops: Set<string>;
  disabled: Set<string>;
}

export function overlaySets(overlay: {
  removed_edges: { source: string; target: string; kind: "grant" | "hop" }[];
  disabled_nodes: string[];
}): OverlaySets {
  const grants = new Set<string>();
  const hops = new Set<string>();
  for (const edge of overlay.removed_edges)
    (edge.kind === "grant" ? grants : hops).add(
      pairKey(edge.source, edge.target),
    );
  return { grants, hops, disabled: new Set(overlay.disabled_nodes) };
}

/** An edge the overlay removes: a grant (read/write) or a hop between the same pair. */
export function edgeRemoved(
  sets: OverlaySets,
  edge: { source: string; target: string; type: string },
): boolean {
  const key = pairKey(edge.source, edge.target);
  return GRANT_TYPES.has(edge.type) ? sets.grants.has(key) : sets.hops.has(key);
}
