"use client";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import { epiPrecise } from "@/lib/proposals";
import type { OptimizerOverview, WhatIfSide } from "@/lib/types";

const count = formatCount;

function arrow(now: WhatIfSide | undefined, after: WhatIfSide | undefined) {
  return `${epiPrecise(now?.epi)} → ${epiPrecise(after?.epi)}`;
}

function arrowCore(now: WhatIfSide | undefined, after: WhatIfSide | undefined) {
  return `${epiPrecise(now?.epi_excl_hubs)} → ${epiPrecise(after?.epi_excl_hubs)}`;
}

/**
 * Overview tiles for the optimizer: graph-wide identity excess privilege now and after the
 * accepted proposals and after the whole high tier (with and without hub roles), dormant
 * identities, unused grants on restricted data, and the rollout of accepted proposals.
 * What-if only: nothing is applied. One fixed grid, so loading never moves the page.
 */
export function OptimizerTiles({
  reloadKey,
  onOpenQueue,
}: {
  reloadKey: number;
  onOpenQueue: () => void;
}) {
  const [data, setData] = useState<OptimizerOverview | null>(null);
  const [note, setNote] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    api<OptimizerOverview>("proposals/overview", { signal: controller.signal })
      .then((found) => {
        if (controller.signal.aborted) return;
        setData(found);
        setNote("");
      })
      .catch((e) => {
        if (controller.signal.aborted) return;
        setData(null);
        setNote(
          e instanceof ApiError && e.status === 404
            ? "Proposals are not computed for this revision yet."
            : e instanceof Error
              ? e.message
              : "Optimizer overview unavailable",
        );
      });
    return () => controller.abort();
  }, [reloadKey]);
  const ready = !!data && data.evidence.status !== "none";
  const rollout = data?.rollout;
  return (
    <section className="optimizer-tiles" aria-label="Least-privilege optimizer">
      <div className="metric-card">
        <span>Identity EPI now → accepted</span>
        <strong>
          {ready
            ? arrow(data.now.identities, data.after_accepted.identities)
            : "—"}
        </strong>
        <small>
          {ready
            ? `Without hubs ${arrowCore(data.now.identities, data.after_accepted.identities)} · ${count(data.accepted.selected)} accepted`
            : note || "Excess privilege index, what-if"}
        </small>
      </div>
      <div className="metric-card">
        <span>Identity EPI now → high tier</span>
        <strong>
          {ready ? arrow(data.now.identities, data.after_high.identities) : "—"}
        </strong>
        <small>
          {ready
            ? `Without hubs ${arrowCore(data.now.identities, data.after_high.identities)} · ${count(data.high.selected)} proposals`
            : "If every high-tier proposal were applied"}
        </small>
      </div>
      <div className="metric-card">
        <span>Dormant identities</span>
        <strong>{data ? count(data.dormant_identities) : "—"}</strong>
        <small>
          {data
            ? `${count(data.dormant_roles)} dormant roles · no observed use`
            : "No observed use in the window"}
        </small>
      </div>
      <div className="metric-card">
        <span>Unused restricted grants</span>
        <strong>{data ? count(data.unused_restricted_grants) : "—"}</strong>
        <small>
          {data
            ? `of ${count(data.unused_grants)} unused grants`
            : "Granted, never used"}
        </small>
      </div>
      <div className="metric-card optimizer-rollout">
        <span>Rollout</span>
        <dl>
          <dt>PRs open</dt>
          <dd>{rollout ? count(rollout.pr_open) : "—"}</dd>
          <dt>Canary watching</dt>
          <dd>{rollout ? count(rollout.canary_watching) : "—"}</dd>
          <dt>Verified</dt>
          <dd>{rollout ? count(rollout.verified) : "—"}</dd>
          <dt>Rolled back</dt>
          <dd>{rollout ? count(rollout.rolled_back) : "—"}</dd>
        </dl>
        <button type="button" className="text-link" onClick={onOpenQueue}>
          Review proposals
        </button>
      </div>
    </section>
  );
}
