"use client";
import {
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import {
  COVERAGE_LABELS,
  epiPrecise,
  TIER_HINTS,
  TIER_LABELS,
  TIERS,
  TYPE_LABELS,
  TYPES,
} from "@/lib/proposals";
import type {
  Proposal,
  ProposalDetail,
  ProposalDraft,
  ProposalList,
  ProposalSimulation,
  ProposalSummary,
  ProposalTier,
  ProposalType,
  TopicMap,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Rollout } from "@/components/rollout";
import { setCustomSet, useProposalSet } from "@/lib/optimized";

const PAGE = 50;
const count = formatCount;

type Filters = {
  tier: ProposalTier | "";
  type: ProposalType | "";
  topic: string;
  state: "" | "pending" | "accepted" | "rejected";
};

function query(filters: Filters, cursor: number | null, revision?: string) {
  const params = new URLSearchParams({ limit: String(PAGE) });
  if (filters.tier) params.set("tier", filters.tier);
  if (filters.type) params.set("type", filters.type);
  if (filters.topic) params.set("topic", filters.topic);
  if (filters.state) params.set("state", filters.state);
  if (cursor !== null) params.set("cursor", String(cursor));
  if (revision) params.set("revision", revision);
  return params.toString();
}

/**
 * Least-privilege proposals of the current revision: filters by tier, type, topic and
 * decision, the evidence behind one proposal, a before/after blast-radius simulation
 * and accept/reject; accepted, eligible proposals become draft pull requests (Create PR) and
 * the Rollout tab tracks them. Nothing is applied by ZeroGraph.
 */
export function Proposals({
  canAdmin,
  focus = null,
  advanced,
  advancedCount = 0,
}: {
  canAdmin: boolean;
  /** Open the queue filtered to a topic (and tier), e.g. from a topic page. */
  focus?: { topic: string; tier: ProposalTier | ""; key: number } | null;
  /** The single-policy remediation tool, kept under Advanced. */
  advanced?: ReactNode;
  advancedCount?: number;
}) {
  const [tab, setTab] = useState<"proposals" | "rollout" | "advanced">(
    "proposals",
  );
  const [rolloutKey, setRolloutKey] = useState(0);
  useEffect(() => {
    if (focus) setTab("proposals");
  }, [focus]);
  return (
    <>
      <div
        className="graph-view-switch"
        role="group"
        aria-label="Proposals, rollout or advanced"
      >
        <button
          type="button"
          aria-pressed={tab === "proposals"}
          onClick={() => setTab("proposals")}
        >
          Proposals
        </button>
        <button
          type="button"
          aria-pressed={tab === "rollout"}
          onClick={() => {
            setRolloutKey((k) => k + 1);
            setTab("rollout");
          }}
        >
          Rollout
        </button>
        {advanced && (
          <button
            type="button"
            aria-pressed={tab === "advanced"}
            onClick={() => setTab("advanced")}
          >
            Advanced
            {advancedCount > 0 ? ` · ${formatCount(advancedCount)}` : ""}
          </button>
        )}
      </div>
      {tab === "rollout" ? (
        <Rollout canAdmin={canAdmin} refreshKey={rolloutKey} />
      ) : tab === "advanced" ? (
        <section className="advanced-remediation" aria-label="Advanced">
          <div className="notice">
            <b>Advanced: single policy.</b> Trim one pasted IAM policy against
            usage you supply. The proposal queue is the primary way to
            remediate; use this for a policy outside the collected graph.
          </div>
          {advanced}
        </section>
      ) : (
        <ProposalQueue
          key={focus?.key ?? 0}
          canAdmin={canAdmin}
          initial={focus}
        />
      )}
    </>
  );
}

function ProposalQueue({
  canAdmin,
  initial,
}: {
  canAdmin: boolean;
  initial?: { topic: string; tier: ProposalTier | "" } | null;
}) {
  const [summary, setSummary] = useState<ProposalSummary | null>(null);
  const [topics, setTopics] = useState<Map<string, string>>(new Map());
  const [filters, setFilters] = useState<Filters>({
    tier: initial?.tier ?? "",
    type: "",
    topic: initial?.topic ?? "",
    state: "",
  });
  const [confirming, setConfirming] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkStatus, setBulkStatus] = useState("");
  const proposalSet = useProposalSet();
  const [list, setList] = useState<ProposalList | null>(null);
  const [rows, setRows] = useState<Proposal[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<ProposalDetail | null>(null);
  const [simulation, setSimulation] = useState<ProposalSimulation | null>(null);
  const [draft, setDraft] = useState<ProposalDraft | null>(null);
  const [prStatus, setPrStatus] = useState("");
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [simulationError, setSimulationError] = useState("");
  const [error, setError] = useState("");
  const [unavailable, setUnavailable] = useState("");
  const listRequest = useRef<AbortController | null>(null);

  const loadSummary = useCallback(async () => {
    try {
      const [found, map] = await Promise.all([
        api<ProposalSummary>("proposals/summary"),
        api<TopicMap>("graph/topics?edge_limit=1").catch(() => null),
      ]);
      setSummary(found);
      setUnavailable("");
      if (map) setTopics(new Map(map.topics.map((t) => [t.id, t.label])));
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setUnavailable(e.message);
      else setError(e instanceof Error ? e.message : "Proposals failed");
    }
  }, []);

  const loadPage = useCallback(
    async (which: Filters, cursor: number | null, revision?: string) => {
      listRequest.current?.abort();
      const controller = new AbortController();
      listRequest.current = controller;
      setBusy(true);
      try {
        const page = await api<ProposalList>(
          `proposals?${query(which, cursor, revision)}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setList(page);
        setRows((current) =>
          cursor === null ? page.proposals : [...current, ...page.proposals],
        );
      } catch (e) {
        if (controller.signal.aborted) return;
        if (e instanceof ApiError && e.status === 404)
          setUnavailable(e.message);
        else setError(e instanceof Error ? e.message : "Proposals failed");
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    },
    [],
  );

  useEffect(() => {
    void loadSummary();
    return () => listRequest.current?.abort();
  }, [loadSummary]);
  useEffect(() => {
    void loadPage(filters, null);
  }, [filters, loadPage]);

  const open = async (proposal: Proposal) => {
    setSelected(proposal.id);
    setSimulation(null);
    setSimulationError("");
    setError("");
    setDraft(null);
    setPrStatus("");
    try {
      const [found, text] = await Promise.all([
        api<ProposalDetail>(
          `proposals/${proposal.id}?revision=${list?.revision ?? ""}`,
        ),
        api<ProposalDraft>(`proposals/${proposal.id}/draft`).catch(() => null),
      ]);
      setDetail(found);
      setDraft(text);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Proposal failed");
    }
  };

  const simulate = async () => {
    if (!detail) return;
    setSimulating(true);
    setSimulationError("");
    try {
      setSimulation(
        await api<ProposalSimulation>("proposals/simulate", {
          method: "POST",
          body: JSON.stringify({
            proposal_ids: [detail.proposal.id],
            revision: detail.revision,
          }),
        }),
      );
    } catch (e) {
      // Shown inside the simulation box (one clamped line): the layout never moves.
      setSimulationError(e instanceof Error ? e.message : "Simulation failed");
    } finally {
      setSimulating(false);
    }
  };

  const decide = async (state: "accepted" | "rejected" | "pending") => {
    if (!detail) return;
    setError("");
    try {
      await api(`proposals/${detail.proposal.id}/decision`, {
        method: "POST",
        body: JSON.stringify({ state, revision: detail.revision }),
      });
      const fresh = await api<ProposalDetail>(
        `proposals/${detail.proposal.id}?revision=${detail.revision}`,
      );
      setDetail(fresh);
      setRows((current) =>
        current.map((row) =>
          row.id === fresh.proposal.id ? fresh.proposal : row,
        ),
      );
      void loadSummary();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Decision failed");
    }
  };

  const createPr = async (scope: "role" | "topic") => {
    if (!detail) return;
    setCreating(true);
    setPrStatus("");
    try {
      const p = detail.proposal;
      const change = await api<{ id: string; subject_name: string }>(
        "rollout/changes",
        {
          method: "POST",
          body: JSON.stringify(
            scope === "role"
              ? { subject_id: p.subject_id, revision: detail.revision }
              : { topic_id: p.topic_id, revision: detail.revision },
          ),
        },
      );
      try {
        const opened = await api<{ url: string }>(
          `rollout/changes/${change.id}/pr`,
          { method: "POST" },
        );
        setPrStatus(`Draft pull request opened: ${opened.url}`);
      } catch (e) {
        setPrStatus(
          `Change saved as a draft. ${e instanceof Error ? e.message : ""}`,
        );
      }
      setDraft(
        await api<ProposalDraft>(`proposals/${p.id}/draft`).catch(() => draft),
      );
    } catch (e) {
      setPrStatus(e instanceof Error ? e.message : "Create PR failed");
    } finally {
      setCreating(false);
    }
  };

  const set = (patch: Partial<Filters>) => {
    setSelected(null);
    setDetail(null);
    setSimulation(null);
    setConfirming(false);
    setBulkStatus("");
    setFilters((current) => ({ ...current, ...patch }));
  };

  // Bulk review stays inside one tier and one topic (safety model); manual is one at a time.
  const bulkScope =
    filters.tier && filters.topic && filters.tier !== "manual"
      ? { tier: filters.tier, topic: filters.topic }
      : null;
  const bulkRows = bulkScope
    ? rows.filter(
        (p) =>
          p.tier === bulkScope.tier &&
          p.topic_id === bulkScope.topic &&
          p.decision?.state !== "accepted",
      )
    : [];
  const scopeLabel = bulkScope
    ? `${TIER_LABELS[bulkScope.tier]} · ${topics.get(bulkScope.topic) ?? bulkScope.topic}`
    : "";
  const bulkAccept = async () => {
    if (!bulkScope || !list || !bulkRows.length) return;
    setBulkBusy(true);
    setBulkStatus("");
    try {
      let decided = 0;
      for (let start = 0; start < bulkRows.length; start += 500) {
        const chunk = bulkRows.slice(start, start + 500);
        const result = await api<{ decided: number }>("proposals/decisions", {
          method: "POST",
          body: JSON.stringify({
            proposal_ids: chunk.map((p) => p.id),
            state: "accepted",
            tier: bulkScope.tier,
            topic_id: bulkScope.topic,
            revision: list.revision,
          }),
        });
        decided += result.decided;
      }
      setBulkStatus(
        `Accepted ${count(decided)} proposals (${scopeLabel}). Nothing is applied; each decision is audited.`,
      );
      setConfirming(false);
      void loadSummary();
      void loadPage(filters, null, list.revision);
    } catch (e) {
      setBulkStatus(e instanceof Error ? e.message : "Bulk decision failed");
    } finally {
      setBulkBusy(false);
    }
  };
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (confirming) confirmRef.current?.focus();
  }, [confirming]);
  const useAsSet = () => {
    if (!list || !rows.length) return;
    const parts = [
      filters.tier ? TIER_LABELS[filters.tier] : "",
      filters.topic ? (topics.get(filters.topic) ?? "") : "",
      filters.type ? TYPE_LABELS[filters.type] : "",
    ].filter(Boolean);
    setCustomSet(
      rows.map((p) => p.id),
      parts.join(" · ") || "queue",
      list.revision,
    );
    setBulkStatus(
      `${count(Math.min(rows.length, 2000))} shown proposals are now the custom set for the optimized views.`,
    );
  };

  if (unavailable)
    return (
      <div className="empty-state">
        <h3>Proposals not available yet</h3>
        <p>{unavailable}</p>
      </div>
    );

  const high = summary?.high_tier.graph;
  return (
    <section className="proposals-page">
      <div className="notice proposal-notice">
        <b>Proposed, not applied.</b> Accepted, eligible proposals become draft
        pull requests in your policy repository (Create PR); nothing is applied
        by ZeroGraph and merging happens there. No proposal removes access that
        was observed used.
      </div>
      <div className="proposal-metrics">
        <div className="metric-card">
          <span>Proposals</span>
          <strong>{summary ? count(summary.total) : "—"}</strong>
          <small>
            {summary
              ? `${count(summary.decisions.accepted)} accepted · ${count(summary.decisions.rejected)} rejected`
              : "Loading"}
          </small>
        </div>
        <div className="metric-card">
          <span>Identity EPI now → after high tier</span>
          <strong>
            {high
              ? `${epiPrecise(high.identities.before.epi)} → ${epiPrecise(high.identities.after.epi)}`
              : "—"}
          </strong>
          <small>
            {high
              ? `Without hubs ${epiPrecise(high.identities.before.epi_excl_hubs)} → ${epiPrecise(high.identities.after.epi_excl_hubs)}`
              : "Excess privilege index"}
          </small>
        </div>
        <div className="metric-card">
          <span>Role EPI now → after high tier</span>
          <strong>
            {high
              ? `${epiPrecise(high.roles.before.epi)} → ${epiPrecise(high.roles.after.epi)}`
              : "—"}
          </strong>
          <small>
            {summary
              ? `${count(summary.high_tier.counts.grants_removed ?? 0)} grants · ${count(summary.high_tier.counts.disabled_nodes ?? 0)} disabled, if all applied`
              : "What-if, not applied"}
          </small>
        </div>
      </div>
      <div
        className="proposal-filters"
        role="group"
        aria-label="Filter proposals"
      >
        <div className="proposal-tiers" role="group" aria-label="Tier">
          <button
            type="button"
            aria-pressed={!filters.tier}
            onClick={() => set({ tier: "" })}
          >
            All · {summary ? count(summary.total) : "—"}
          </button>
          {TIERS.map((tier) => (
            <button
              key={tier}
              type="button"
              title={TIER_HINTS[tier]}
              aria-pressed={filters.tier === tier}
              onClick={() => set({ tier })}
            >
              <i className={`tier-dot tier-${tier}`} aria-hidden="true" />
              {TIER_LABELS[tier]} ·{" "}
              {summary ? count(summary.by_tier[tier]) : "—"}
            </button>
          ))}
        </div>
        <label>
          Type
          <select
            value={filters.type}
            onChange={(e) => set({ type: e.target.value as ProposalType | "" })}
          >
            <option value="">All types</option>
            {TYPES.map((type) => (
              <option key={type} value={type}>
                {TYPE_LABELS[type]}
                {summary ? ` (${count(summary.by_type[type])})` : ""}
              </option>
            ))}
          </select>
        </label>
        <label>
          Topic
          <select
            value={filters.topic}
            onChange={(e) => set({ topic: e.target.value })}
          >
            <option value="">All topics</option>
            {Object.entries(summary?.topics ?? {}).map(([id, stats]) => (
              <option key={id} value={id}>
                {topics.get(id) ?? id} ({count(stats.total)})
              </option>
            ))}
          </select>
        </label>
        <label>
          Decision
          <select
            value={filters.state}
            onChange={(e) => set({ state: e.target.value as Filters["state"] })}
          >
            <option value="">Any</option>
            <option value="pending">Not decided</option>
            <option value="accepted">Accepted</option>
            <option value="rejected">Rejected</option>
          </select>
        </label>
      </div>
      <div
        className="bulk-bar"
        role="group"
        aria-label="Bulk review"
        onKeyDown={(e) => {
          if (e.key === "Escape" && confirming) setConfirming(false);
        }}
      >
        <span
          className="bulk-text"
          role="status"
          title={bulkStatus || undefined}
        >
          {bulkStatus ||
            (confirming && bulkScope
              ? `Accept ${count(bulkRows.length)} ${scopeLabel} proposals shown? Each is audited and carries forward; nothing is applied.`
              : !bulkScope
                ? filters.tier === "manual"
                  ? "Manual-tier proposals are reviewed one at a time."
                  : "Bulk review: choose one tier and one topic."
                : !canAdmin
                  ? "Administrators accept proposals in bulk."
                  : `${count(bulkRows.length)} not yet accepted of ${count(rows.length)} shown (${scopeLabel}).`)}
        </span>
        {confirming && bulkScope ? (
          <>
            <Button
              ref={confirmRef}
              size="small"
              disabled={bulkBusy || !bulkRows.length}
              onClick={() => void bulkAccept()}
            >
              {bulkBusy
                ? "Accepting…"
                : `Confirm accept ${count(bulkRows.length)}`}
            </Button>
            <Button
              variant="outline"
              size="small"
              disabled={bulkBusy}
              onClick={() => setConfirming(false)}
            >
              Cancel
            </Button>
          </>
        ) : (
          <>
            <Button
              size="small"
              disabled={!bulkScope || !canAdmin || !bulkRows.length}
              onClick={() => {
                setBulkStatus("");
                setConfirming(true);
              }}
            >
              Accept shown…
            </Button>
            <Button
              variant="outline"
              size="small"
              disabled={!rows.length}
              aria-pressed={
                proposalSet.kind === "custom" &&
                proposalSet.ids.length === Math.min(rows.length, 2000) &&
                rows.every((p, i) => i >= 2000 || proposalSet.ids[i] === p.id)
              }
              onClick={useAsSet}
            >
              Use as custom set
            </Button>
          </>
        )}
      </div>
      {error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}
      <div className="proposals-grid">
        <div className="panel proposal-list">
          <div className="panel-heading">
            <h3>Proposals</h3>
            <span className="muted">
              {list
                ? `${count(rows.length)} of ${count(list.view.total)} shown`
                : "Loading"}
            </span>
          </div>
          <div className="proposal-rows" aria-busy={busy}>
            {rows.map((p) => (
              <button
                key={p.id}
                type="button"
                className="proposal-row"
                aria-pressed={selected === p.id}
                onClick={() => void open(p)}
              >
                <span className={`tier-badge tier-${p.tier}`}>
                  {TIER_LABELS[p.tier]}
                </span>
                <span className="proposal-row-main">
                  <b>{TYPE_LABELS[p.type]}</b>
                  <small>
                    {p.subject_name}
                    {p.target_name ? ` → ${p.target_name}` : ""}
                  </small>
                </span>
                <span className="proposal-row-meta">
                  <small>{topics.get(p.topic_id) ?? "No topic"}</small>
                  <small>
                    {p.decision
                      ? p.decision.state === "accepted"
                        ? "Accepted"
                        : "Rejected"
                      : "Proposed"}
                  </small>
                </span>
              </button>
            ))}
            {list && !rows.length && (
              <p className="empty-line">No proposals match these filters.</p>
            )}
          </div>
          <div className="proposal-more">
            <Button
              variant="outline"
              disabled={busy || list?.view.next_cursor == null}
              onClick={() =>
                list &&
                void loadPage(filters, list.view.next_cursor, list.revision)
              }
            >
              {list?.view.next_cursor == null ? "All shown" : "Load more"}
            </Button>
          </div>
        </div>
        <aside className="panel proposal-detail" aria-label="Proposal evidence">
          {detail && detail.proposal.id === selected ? (
            <ProposalEvidence
              detail={detail}
              topicLabel={topics.get(detail.proposal.topic_id)}
              simulation={simulation}
              simulating={simulating}
              simulationError={simulationError}
              onSimulate={() => void simulate()}
              canAdmin={canAdmin}
              onDecide={(state) => void decide(state)}
              draft={draft}
              prStatus={prStatus}
              creating={creating}
              onCreatePr={(scope) => void createPr(scope)}
            />
          ) : (
            <div className="proposal-placeholder">
              <span className="section-label">Evidence</span>
              <p>
                Select a proposal to see its evidence, the exact grants it
                changes, and a before/after blast-radius simulation.
              </p>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}

function value(evidence: Record<string, unknown>, key: string): string {
  const found = evidence[key];
  if (found === null || found === undefined || found === "") return "—";
  return String(found);
}

function ProposalEvidence({
  detail,
  topicLabel,
  simulation,
  simulating,
  simulationError,
  onSimulate,
  canAdmin,
  onDecide,
  draft,
  prStatus,
  creating,
  onCreatePr,
}: {
  detail: ProposalDetail;
  topicLabel?: string;
  simulation: ProposalSimulation | null;
  simulating: boolean;
  simulationError: string;
  onSimulate: () => void;
  canAdmin: boolean;
  onDecide: (state: "accepted" | "rejected" | "pending") => void;
  draft: ProposalDraft | null;
  prStatus: string;
  creating: boolean;
  onCreatePr: (scope: "role" | "topic") => void;
}) {
  const p = detail.proposal;
  const evidence = p.evidence;
  const peers = Array.isArray(evidence.peers)
    ? (evidence.peers as number[])
    : null;
  const sample = Array.isArray(evidence.identities_sample)
    ? (evidence.identities_sample as string[])
    : [];
  const delta = detail.graph_delta?.graph.identities;
  const whatif = simulation?.whatif;
  return (
    <>
      <span className="section-label">Proposed · not applied</span>
      <h3>{TYPE_LABELS[p.type]}</h3>
      <span className={`tier-badge tier-${p.tier}`} title={TIER_HINTS[p.tier]}>
        {TIER_LABELS[p.tier]}
        {p.base_tier !== p.tier
          ? ` (evidence: ${TIER_LABELS[p.base_tier]})`
          : ""}
      </span>
      {p.reasons.length > 0 && (
        <ul className="proposal-reasons">
          {p.reasons.map((reason) => (
            <li key={reason}>{detail.never_auto[reason] ?? reason}</li>
          ))}
        </ul>
      )}
      <dl>
        <dt>Subject</dt>
        <dd title={p.subject_id}>{p.subject_name}</dd>
        {p.target_id && (
          <>
            <dt>Target</dt>
            <dd title={p.target_id}>{p.target_name}</dd>
          </>
        )}
        <dt>Topic</dt>
        <dd>{detail.topic?.label ?? topicLabel ?? "No topic"}</dd>
        {detail.resource && (
          <>
            <dt>Asset topic</dt>
            <dd>{detail.resource.topic}</dd>
            <dt>Labelled by</dt>
            <dd>{detail.resource.label_reason}</dd>
          </>
        )}
        {"coverage" in evidence && (
          <>
            <dt>Service coverage</dt>
            <dd>
              {value(evidence, "service")} ·{" "}
              {COVERAGE_LABELS[String(evidence.coverage)] ??
                value(evidence, "coverage")}
            </dd>
          </>
        )}
        <dt>Window</dt>
        <dd>
          {detail.evidence.window_start && detail.evidence.window_end
            ? `${detail.evidence.window_start.slice(0, 10)} to ${detail.evidence.window_end.slice(0, 10)}`
            : "No usage evidence"}
        </dd>
        <dt>Last seen</dt>
        <dd>
          {p.type === "remove_grant"
            ? "Never in the window"
            : value(evidence, "last_used_hint")}
        </dd>
        {peers && (
          <>
            <dt>Same-topic peers</dt>
            <dd>
              {count(peers[1])} of {count(peers[0])} granted it use it
            </dd>
          </>
        )}
        <dt>Identities affected</dt>
        <dd>
          {count(p.identities)}
          {sample.length ? ` (e.g. ${sample.join(", ")})` : ""}
        </dd>
        <dt>Role EPI</dt>
        <dd>
          {epiPrecise(p.epi_before)} → {epiPrecise(p.epi_after)}
        </dd>
        <dt>Graph identity EPI</dt>
        <dd>
          {delta
            ? `${epiPrecise(delta.before.epi)} → ${epiPrecise(delta.after.epi)}`
            : "Not modelled for this type"}
        </dd>
      </dl>
      <span className="section-label">Exact changes</span>
      <ul className="proposal-changes">
        {p.changes.slice(0, 12).map((change, index) => (
          <li key={`${change.op}:${change.edge_id ?? index}`}>
            <b>{change.op.replace(/_/g, " ")}</b>{" "}
            {change.source
              ? `${change.source} → ${change.target}`
              : String(change.node ?? change.role ?? change.keep ?? "")}
            {change.type ? ` · ${change.type}` : ""}
            {change.actions?.length ? ` · ${change.actions.join(", ")}` : ""}
          </li>
        ))}
        {p.changes.length > 12 && (
          <li>{count(p.changes.length - 12)} more listed in the API</li>
        )}
      </ul>
      <span className="section-label">What-if simulation</span>
      <div className="proposal-simulation">
        <Button variant="outline" disabled={simulating} onClick={onSimulate}>
          {simulating ? "Simulating" : "Simulate"}
        </Button>
        <dl>
          <dt>Blast radius (risk)</dt>
          <dd>
            {simulation
              ? `${simulation.risk_score} → ${whatif?.after.risk_score ?? simulation.risk_score}`
              : "—"}
          </dd>
          <dt>Reachable data assets</dt>
          <dd>
            {simulation
              ? `${count(simulation.affected_assets.length)} → ${count(whatif?.after.affected_assets.length ?? 0)}`
              : "—"}
          </dd>
          <dt>Assets no longer reachable</dt>
          <dd>{whatif ? count(whatif.assets_removed_count) : "—"}</dd>
          <dt>Status</dt>
          <dd
            className="proposal-sim-status"
            title={simulationError || undefined}
          >
            {simulationError
              ? `Failed: ${simulationError}`
              : simulating
                ? "Simulating"
                : simulation
                  ? "Simulated, not applied"
                  : "Not run"}
          </dd>
        </dl>
      </div>
      <span className="section-label">Review</span>
      <div className="proposal-actions">
        <Button
          disabled={!canAdmin || p.decision?.state === "accepted"}
          onClick={() => onDecide("accepted")}
        >
          Accept
        </Button>
        <Button
          variant="outline"
          disabled={!canAdmin || p.decision?.state === "rejected"}
          onClick={() => onDecide("rejected")}
        >
          Reject
        </Button>
        <Button
          variant="outline"
          disabled={!canAdmin || !p.decision}
          onClick={() => onDecide("pending")}
        >
          Clear
        </Button>
      </div>
      <small className="proposal-footnote">
        {p.decision
          ? `${p.decision.state === "accepted" ? "Accepted" : "Rejected"} by ${p.decision.actor}${p.decision.stale ? " (evidence changed since)" : ""}. `
          : ""}
        {canAdmin
          ? "Decisions carry forward to later revisions."
          : "Administrators record decisions and open pull requests."}
      </small>
      <span className="section-label">Pull request</span>
      <div className="proposal-pr">
        {draft === null ? (
          <p className="proposal-pr-text">Loading</p>
        ) : draft.pr_eligible ? (
          <>
            <div className="proposal-actions">
              <Button
                disabled={
                  !canAdmin ||
                  creating ||
                  p.decision?.state !== "accepted" ||
                  draft.change_id !== null
                }
                onClick={() => onCreatePr("role")}
              >
                Create PR
              </Button>
              <Button
                variant="outline"
                disabled={
                  !canAdmin ||
                  creating ||
                  !p.topic_id ||
                  p.decision?.state !== "accepted" ||
                  draft.change_id !== null
                }
                onClick={() => onCreatePr("topic")}
              >
                Bundle topic
              </Button>
            </div>
            <p className="proposal-pr-text" title={prStatus || undefined}>
              {prStatus ||
                (draft.change_id
                  ? "In a rollout change; see the Rollout tab."
                  : p.decision?.state === "accepted"
                    ? "Create PR opens one draft pull request for this role with all its accepted proposals; Bundle topic covers the topic's roles."
                    : "Accept the proposal first.")}
            </p>
          </>
        ) : (
          <p className="proposal-pr-text">
            Draft only, no pull request: {draft.reason}
          </p>
        )}
        {draft && <pre className="proposal-draft">{draft.text}</pre>}
      </div>
    </>
  );
}
