"use client";
import { formatCount } from "@/lib/format";
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
  return typeof value === "number" && Number.isFinite(value)
    ? `${Math.round(value * 100)}%`
    : "—";
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
      <h3>Excess privilege</h3>
      <div className="summary-number">
        <b>{ready ? epiText(tile.identities.epi) : "—"}</b>
        <span>
          of identities&apos; granted sensitivity weight is not needed
        </span>
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
      <p>
        {!tile
          ? "Computed with the relationship topics of the current revision."
          : ready
            ? `${EVIDENCE_LABELS[tile.status]} · ${windowText(tile)} · needed from ${basisText(tile.identities).toLowerCase()}. Granted access only counts as needed where use was observed (or peers use it).`
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
