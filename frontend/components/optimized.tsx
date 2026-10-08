"use client";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import {
  overlaySets,
  type OverlaySets,
  type ProposalSet,
  type ProposalSetKind,
  selectionBody,
  setDescription,
  setProposalSetKind,
  SET_LABELS,
  useProposalSet,
} from "@/lib/optimized";
import type { SliceOverlay } from "@/lib/types";

const count = formatCount;

/**
 * "Current | Optimized" switch and the proposal set the optimized state shows (high tier,
 * accepted, or a custom set picked in the proposal queue).
 */
export function OptimizedSwitch({
  optimized,
  onToggle,
  disabled = false,
  label = "Graph state",
}: {
  optimized: boolean;
  onToggle: (optimized: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  const set = useProposalSet();
  return (
    <div className="optimized-switch">
      <div className="graph-view-switch" role="group" aria-label={label}>
        <button
          type="button"
          aria-pressed={!optimized}
          disabled={disabled}
          onClick={() => onToggle(false)}
        >
          Current
        </button>
        <button
          type="button"
          aria-pressed={optimized}
          disabled={disabled}
          onClick={() => onToggle(true)}
        >
          Optimized
        </button>
      </div>
      <label className="optimized-set">
        <span>Proposal set</span>
        <select
          value={set.kind}
          disabled={disabled}
          onChange={(e) =>
            setProposalSetKind(e.target.value as ProposalSetKind)
          }
        >
          <option value="high">{SET_LABELS.high}</option>
          <option value="accepted">{SET_LABELS.accepted}</option>
          <option value="custom" disabled={!set.ids.length}>
            {set.ids.length
              ? `${SET_LABELS.custom} (${count(set.ids.length)})`
              : `${SET_LABELS.custom} (pick in the queue)`}
          </option>
        </select>
      </label>
    </div>
  );
}

/** The switch with one status line; the bar keeps one height in both states. */
export function OptimizedBar({
  status,
  ...props
}: {
  optimized: boolean;
  onToggle: (optimized: boolean) => void;
  status: string;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <div className="optimized-bar">
      <OptimizedSwitch {...props} />
      <span className="optimized-status" role="status" title={status}>
        {status}
      </span>
    </div>
  );
}

export interface SliceOverlayState {
  overlay: SliceOverlay | null;
  sets: OverlaySets | null;
  busy: boolean;
  error: string;
}

/**
 * The optimized overlay of a visible slice (at most 500 entity IDs) for the shared proposal
 * set, fetched while ``enabled``. Pinned to ``revision``: a 409 goes to ``onStale``.
 */
export function useSliceOverlay(
  enabled: boolean,
  revision: string,
  nodeIds: string[],
  onStale?: (e: unknown) => void,
): SliceOverlayState {
  const set = useProposalSet();
  const [state, setState] = useState<SliceOverlayState>({
    overlay: null,
    sets: null,
    busy: false,
    error: "",
  });
  const key = useMemo(() => nodeIds.join("\u0000"), [nodeIds]);
  useEffect(() => {
    if (!enabled || !revision || !nodeIds.length) {
      setState({ overlay: null, sets: null, busy: false, error: "" });
      return;
    }
    const controller = new AbortController();
    setState((previous) => ({ ...previous, busy: true, error: "" }));
    api<SliceOverlay>("proposals/overlay", {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({
        ...selectionBody(set),
        node_ids: nodeIds.slice(0, 500),
        revision,
      }),
    }).then(
      (overlay) => {
        if (controller.signal.aborted) return;
        setState({
          overlay,
          sets: overlaySets(overlay),
          busy: false,
          error: "",
        });
      },
      (e) => {
        if (controller.signal.aborted) return;
        if (e instanceof ApiError && e.status === 409) onStale?.(e);
        setState({
          overlay: null,
          sets: null,
          busy: false,
          error: e instanceof Error ? e.message : "Optimized view failed",
        });
      },
    );
    return () => controller.abort();
    // nodeIds is keyed by its content (key).
  }, [enabled, revision, key, set, onStale]);
  return state;
}

/** One status line for an optimized slice: what is shown and the set's graph-wide totals. */
export function overlayStatus(
  optimized: boolean,
  state: SliceOverlayState,
  set: ProposalSet,
): string {
  if (!optimized) return "Current graph: access as granted today.";
  if (state.error) return `Optimized view unavailable: ${state.error}`;
  const overlay = state.overlay;
  if (!overlay) return `Optimized (${setDescription(set)}): loading…`;
  if (!overlay.selected)
    return `${setDescription(set)}: no proposals selected, nothing would change.`;
  const { slice, totals } = overlay;
  const n = (value: number, one: string, many: string) =>
    `${count(value)} ${value === 1 ? one : many}`;
  return (
    `${setDescription(set)} · in view: ${n(slice.grants_removed + slice.hops_cut, "edge", "edges")} removed, ` +
    `${n(slice.disabled_nodes, "node", "nodes")} disabled · whole graph: ${n(totals.grants_removed, "grant", "grants")}, ` +
    `${n(totals.hops_cut, "hop", "hops")}, ${n(totals.disabled_nodes, "node", "nodes")} · simulated, not applied`
  );
}
