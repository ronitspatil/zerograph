"use client";
import { formatCount, formatPercent } from "@/lib/format";
import type {
  ExcessPrivilegeTile,
  PrivilegeAggregate,
  PrivilegeBasis,
  UsageEvidence,
} from "@/lib/types";

/** How needed access was established; always shown beside an index. */
export const BASIS_LABELS: Record<PrivilegeBasis, string> = {
  used: "Used (attested evidence)",
  inferred: "Inferred (peer baseline)",
  none: "Granted only (no usage evidence)",
};

export const EVIDENCE_LABELS: Record<UsageEvidence["status"], string> = {
  none: "No usage evidence",
  partial: "Usage evidence, not sufficient",
  attested: "Attested usage evidence",
};

/** The excess-privilege index as a percentage of granted weight that is not needed. */
export function epiText(value: number | null | undefined): string {
  return formatPercent(value);
}

/** "used", "inferred", "none" or a mix, from basis counts. */
export function basisText(aggregate: PrivilegeAggregate): string {
  const { used = 0, inferred = 0, none = 0 } = aggregate.basis;
  if (used && inferred)
    return `${formatCount(used)} used · ${formatCount(inferred)} inferred`;
  if (inferred) return BASIS_LABELS.inferred;
  if (used) return BASIS_LABELS.used;
  return none ? BASIS_LABELS.none : "—";
}

export function windowText(evidence: {
  window_start?: string | null;
  window_end?: string | null;
}): string {
  if (!evidence.window_start || !evidence.window_end) return "—";
  const day = (iso: string) => iso.slice(0, 10);
  return `${day(evidence.window_start)} to ${day(evidence.window_end)}`;
}

/** Granted vs needed (used or inferred), with and without hub roles. */
export function PrivilegeRows({
  label,
  aggregate,
}: {
  label: string;
  aggregate: PrivilegeAggregate;
}) {
  return (
    <>
      <dt>{label} EPI</dt>
      <dd>{epiText(aggregate.epi)}</dd>
      <dt>Without hub roles</dt>
      <dd>{epiText(aggregate.epi_excl_hubs)}</dd>
      <dt>Granted / needed weight</dt>
      <dd>
        {formatCount(aggregate.granted_weight)} /{" "}
        {formatCount(aggregate.needed_weight)}
      </dd>
      <dt>Needed from</dt>
      <dd>{basisText(aggregate)}</dd>
    </>
  );
}

/**
 * Overview tile: graph-wide excess privilege, always decomposed with and without
 * hub roles, with unused and dormant counts and the evidence it rests on.
 */
export function ExcessPrivilegePanel({
  tile,
  onOpenSources,
}: {
  tile: ExcessPrivilegeTile | null | undefined;
  onOpenSources?: () => void;
}) {
  const ready = tile && tile.status !== "none";
  return (
    <div className="panel summary-panel privilege-panel">
      <div className="panel-heading">
        <h2>Excess privilege</h2>
      </div>
      <div className="summary-number">
        <b>{ready ? epiText(tile.identities.epi) : "—"}</b>
        <span>of granted sensitivity weight not needed</span>
      </div>
      <div className="sidebar-stat">
        <span>Without hub roles</span>
        <b>{ready ? epiText(tile.identities.epi_excl_hubs) : "—"}</b>
      </div>
      <div className="sidebar-stat">
        <span>Roles (with / without hubs)</span>
        <b>
          {ready
            ? `${epiText(tile.roles.epi)} / ${epiText(tile.roles.epi_excl_hubs)}`
            : "—"}
        </b>
      </div>
      <div className="sidebar-stat">
        <span>Unused grants (restricted data)</span>
        <b>
          {ready
            ? `${formatCount(tile.unused_grants)} (${formatCount(tile.unused_restricted_grants)})`
            : "—"}
        </b>
      </div>
      <div className="sidebar-stat">
        <span>Dormant identities</span>
        <b>{ready ? formatCount(tile.dormant_identities) : "—"}</b>
      </div>
      <p title="Granted access counts as needed only where use was observed, or where same-topic peers use it.">
        {!tile
          ? "Computed with the relationship topics of the current revision."
          : ready
            ? `${EVIDENCE_LABELS[tile.status]} · ${windowText(tile)} · needed from ${basisText(tile.identities).toLowerCase()}.`
            : "Upload a CloudTrail export in Data sources to compare granted access with observed use."}
      </p>
      {onOpenSources && tile?.status === "none" && (
        <button type="button" className="text-link" onClick={onOpenSources}>
          Upload usage evidence
        </button>
      )}
    </div>
  );
}

/**
 * "98.2% → 97.9%", the one way a before/after share is shown; its change in
 * percentage points (formatPp) leads the caption underneath.
 */
export function ShareChange({
  before,
  after,
}: {
  before: number | null | undefined;
  after: number | null | undefined;
}) {
  return (
    <span>
      {formatPercent(before)} → {formatPercent(after)}
    </span>
  );
}
