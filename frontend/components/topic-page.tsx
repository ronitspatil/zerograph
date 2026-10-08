"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { ArrowLeft, LoaderCircle } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import { epiPrecise, TIER_HINTS, TIER_LABELS, TIERS } from "@/lib/proposals";
import { selectionBody, setDescription, useProposalSet } from "@/lib/optimized";
import type {
  GraphNode,
  ProposalSummary,
  ProposalTier,
  TopicDetail,
  TopicGroup,
  TopicLinkRemovals,
  TopicMember,
  TopicMemberKind,
  TopicSubgraph,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  BASIS_LABELS,
  epiText,
  EVIDENCE_LABELS,
  PrivilegeRows,
  windowText,
} from "@/components/privilege";
import { FLAG_LABELS, topicEpi } from "@/components/topic-lens";
import {
  OptimizedBar,
  overlayStatus,
  useSliceOverlay,
} from "@/components/optimized";

const GraphCanvas = dynamic(
  () => import("@/components/graph-canvas").then((m) => m.GraphCanvas),
  {
    ssr: false,
    loading: () => (
      <div className="canvas-loading">
        <LoaderCircle className="spin" />
        Loading graph…
      </div>
    ),
  },
);

const count = formatCount;
const PAGE = 50;
const NO_RISK = new Set<string>();
const EMPTY_OVERLAY = {
  grants: new Set<string>(),
  hops: new Set<string>(),
  disabled: new Set<string>(),
};

const KIND_LABELS: Record<TopicMemberKind, string> = {
  resource: "Data assets",
  role: "Roles",
  identity: "Identities",
};

const GROUP_LABELS: Record<TopicGroup, string> = {
  role: "Role of this topic",
  identity: "Identity of this topic",
  resource: "Data asset of this topic",
  outside: "Data asset of another topic",
};

const SEED_LABELS: Record<string, string> = {
  tag: "Tag",
  metadata: "Metadata",
  name: "Name token",
  usage: "Observed co-use",
  coaccess: "Shared access",
  fallback: "Service type",
};

/**
 * One topic, full width: its members (paged), granted vs used per role, excess privilege
 * with its top contributors and the hub breakdown, label reasons, its proposals by tier,
 * and its bounded subgraph in the explorer canvas with a Current | Optimized switch that
 * draws what the shared proposal set would remove (red dashed) or disable (grey).
 * Everything is simulated from the stored what-if model; nothing is applied.
 */
export function TopicPage({
  topicId,
  revision,
  onBack,
  onError,
  onOpenNeighborhood,
  onReviewProposals,
}: {
  topicId: string;
  revision: string;
  onBack: () => void;
  onError: (e: unknown) => void;
  onOpenNeighborhood: (nodeId: string, revision: string) => void;
  onReviewProposals: (topicId: string, tier: ProposalTier | "") => void;
}) {
  const [detail, setDetail] = useState<TopicDetail | null>(null);
  const [contributors, setContributors] = useState<TopicMember[] | null>(null);
  const [roles, setRoles] = useState<TopicMember[]>([]);
  const [rolesNext, setRolesNext] = useState<number | null>(null);
  const [kind, setKind] = useState<TopicMemberKind>("resource");
  const [members, setMembers] = useState<TopicMember[]>([]);
  const [membersView, setMembersView] = useState<TopicDetail["view"] | null>(
    null,
  );
  const [summary, setSummary] = useState<ProposalSummary | null>(null);
  const [subgraph, setSubgraph] = useState<TopicSubgraph | null>(null);
  const [optimized, setOptimized] = useState(false);
  const [whatif, setWhatif] = useState<TopicLinkRemovals | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [busy, setBusy] = useState(false);
  const [unavailable, setUnavailable] = useState("");
  const set = useProposalSet();
  const memberRequest = useRef<AbortController | null>(null);

  const base = `graph/topics/${encodeURIComponent(topicId)}`;
  const pinned = `revision=${encodeURIComponent(revision)}`;
  const failed = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 404) setUnavailable(e.message);
      else onError(e);
    },
    [onError],
  );

  useEffect(() => {
    const controller = new AbortController();
    const signal = controller.signal;
    setDetail(null);
    setSubgraph(null);
    setSelected(null);
    setUnavailable("");
    api<TopicDetail>(`${base}?kind=role&limit=${PAGE}&${pinned}`, { signal })
      .then((found) => {
        if (signal.aborted) return;
        setDetail(found);
        setRoles(found.members);
        setRolesNext(found.view.next_offset);
      })
      .catch((e) => !signal.aborted && failed(e));
    api<TopicDetail>(`${base}?kind=role&sort=excess&limit=8&${pinned}`, {
      signal,
    })
      .then((found) => !signal.aborted && setContributors(found.members))
      .catch(() => !signal.aborted && setContributors([]));
    api<ProposalSummary>(`proposals/summary?${pinned}`, { signal })
      .then((found) => !signal.aborted && setSummary(found))
      .catch(() => {});
    api<TopicSubgraph>(`${base}/subgraph?${pinned}`, { signal })
      .then((found) => !signal.aborted && setSubgraph(found))
      .catch((e) => !signal.aborted && failed(e));
    return () => controller.abort();
  }, [base, pinned, failed]);

  const loadMembers = useCallback(
    async (which: TopicMemberKind, offset: number) => {
      memberRequest.current?.abort();
      const controller = new AbortController();
      memberRequest.current = controller;
      setBusy(true);
      try {
        const found = await api<TopicDetail>(
          `${base}?kind=${which}&offset=${offset}&limit=${PAGE}&${pinned}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setMembers((list) =>
          offset ? [...list, ...found.members] : found.members,
        );
        setMembersView(found.view);
      } catch (e) {
        if (!controller.signal.aborted) failed(e);
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    },
    [base, pinned, failed],
  );
  useEffect(() => {
    void loadMembers(kind, 0);
    return () => memberRequest.current?.abort();
  }, [kind, loadMembers]);

  const moreRoles = async () => {
    if (rolesNext === null) return;
    try {
      const found = await api<TopicDetail>(
        `${base}?kind=role&offset=${rolesNext}&limit=${PAGE}&${pinned}`,
      );
      setRoles((list) => [...list, ...found.members]);
      setRolesNext(found.view.next_offset);
    } catch (e) {
      failed(e);
    }
  };

  // The set's per-topic before/after (graph-wide evaluation, cached by the server).
  useEffect(() => {
    const controller = new AbortController();
    setWhatif(null);
    api<TopicLinkRemovals>("proposals/links", {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({ ...selectionBody(set), revision }),
    }).then(
      (found) => !controller.signal.aborted && setWhatif(found),
      () => {},
    );
    return () => controller.abort();
  }, [set, revision]);

  const nodeIds = useMemo(
    () => subgraph?.nodes.map((n) => n.id) ?? [],
    [subgraph],
  );
  const overlay = useSliceOverlay(optimized, revision, nodeIds, onError);
  // The canvas rebuilds when its graph object changes: one per subgraph.
  const canvasGraph = useMemo(
    () =>
      subgraph
        ? {
            revision: subgraph.revision,
            nodes: subgraph.nodes,
            edges: subgraph.edges,
            warnings: subgraph.warnings,
          }
        : null,
    [subgraph],
  );
  const outside = useMemo(
    () =>
      new Set(
        Object.entries(subgraph?.groups ?? {})
          .filter(([, group]) => group === "outside")
          .map(([id]) => id),
      ),
    [subgraph],
  );

  if (unavailable)
    return (
      <section className="topic-page">
        <Button variant="ghost" onClick={onBack}>
          <ArrowLeft size={14} aria-hidden="true" />
          Back to topics
        </Button>
        <div className="empty-state">
          <h3>Topic not available</h3>
          <p>{unavailable}</p>
        </div>
      </section>
    );

  const topic = detail?.topic;
  const privilege = topic?.privilege;
  const evidence =
    summary && "window_start" in summary.evidence ? summary.evidence : null;
  const measured = !!summary && summary.evidence.status !== "none";
  const proposals = summary?.topics[topicId];
  const after = whatif?.topics.find((t) => t.topic_id === topicId);
  return (
    <section className="topic-page" aria-label="Topic">
      <div className="topic-page-head">
        <Button variant="ghost" size="small" onClick={onBack}>
          <ArrowLeft size={14} aria-hidden="true" />
          Topics
        </Button>
        <div className="topic-page-title">
          <h2 title={topic?.label}>{topic?.label ?? "Loading topic…"}</h2>
          <span className="node-type">
            {topic
              ? topic.kind === "anchored"
                ? "Named topic"
                : "Unassigned group"
              : "Topic"}
          </span>
        </div>
        <p className="topic-reason">
          {topic?.reason ?? "Loading why this topic was named…"}
        </p>
      </div>
      <div className="metric-grid topic-tiles">
        <div className="metric-card">
          <span>Members</span>
          <strong>{topic ? count(topic.resources) : "—"}</strong>
          <small>
            {topic
              ? `data assets · ${count(topic.roles)} roles · ${count(topic.identities)} identities`
              : "Loading"}
          </small>
        </div>
        <div className="metric-card">
          <span>Identity EPI now → after</span>
          <strong>
            {after
              ? `${epiPrecise(topicEpi(after, "before"))} → ${epiPrecise(topicEpi(after, "after"))}`
              : "—"}
          </strong>
          <small>
            {after
              ? `Without hubs ${epiPrecise(after.identities?.before.epi_excl_hubs)} → ${epiPrecise(after.identities?.after.epi_excl_hubs)} · ${setDescription(set)}`
              : setDescription(set)}
          </small>
        </div>
        <div className="metric-card">
          <span>Role EPI now → after</span>
          <strong>
            {after
              ? `${epiPrecise(after.roles?.before.epi)} → ${epiPrecise(after.roles?.after.epi)}`
              : "—"}
          </strong>
          <small>
            {after
              ? `Without hubs ${epiPrecise(after.roles?.before.epi_excl_hubs)} → ${epiPrecise(after.roles?.after.epi_excl_hubs)}`
              : "What-if, not applied"}
          </small>
        </div>
        <div className="metric-card">
          <span>Proposals</span>
          <strong>{proposals ? count(proposals.total) : "—"}</strong>
          <small>
            {proposals
              ? `${count(proposals.by_tier.high)} high · ${count(proposals.by_tier.manual)} manual`
              : summary
                ? "No proposals for this topic"
                : "Loading"}
          </small>
        </div>
      </div>

      <section className="panel graph-panel topic-graph">
        <div className="panel-heading">
          <div>
            <h3>Topic subgraph</h3>
            <span className="muted">
              {subgraph
                ? `${count(subgraph.view.shown.role)} / ${count(subgraph.view.totals.role)} roles · ${count(subgraph.view.shown.identity)} / ${count(subgraph.view.totals.identity)} identities · ${count(subgraph.view.shown.resource)} / ${count(subgraph.view.totals.resource)} data assets · ${count(subgraph.view.shown.outside)} assets of other topics · ${count(subgraph.edges.length)} relationships${subgraph.view.truncated ? " · Partial view" : " · Complete view"}`
                : "Loading the topic's bounded subgraph…"}
            </span>
          </div>
        </div>
        <OptimizedBar
          optimized={optimized}
          onToggle={setOptimized}
          disabled={!subgraph}
          label="Current or optimized topic"
          status={overlayStatus(optimized, overlay, set)}
        />
        <div className="graph-body">
          <div className="graph-main">
            {subgraph && canvasGraph ? (
              subgraph.nodes.length ? (
                <GraphCanvas
                  graph={canvasGraph}
                  selected={selected?.id ?? null}
                  riskNodes={NO_RISK}
                  simulation={null}
                  onSelect={setSelected}
                  overlay={optimized ? (overlay.sets ?? EMPTY_OVERLAY) : null}
                  outside={outside}
                  legendExtra={[
                    {
                      text: "Other topic (lighter)",
                      className: "legend-outside",
                    },
                  ]}
                />
              ) : (
                <div className="empty-state">
                  <h3>No members to draw</h3>
                  <p>This topic has no roles, identities or data assets.</p>
                </div>
              )
            ) : (
              <div className="canvas-loading" role="status">
                <LoaderCircle className="spin" />
                Loading topic subgraph…
              </div>
            )}
            <div className="identity-list" aria-label="Select a member">
              {subgraph?.nodes.map((n) => (
                <button
                  key={n.id}
                  type="button"
                  className={selected?.id === n.id ? "selected" : ""}
                  onClick={() => setSelected(n)}
                >
                  {n.name}
                </button>
              ))}
            </div>
          </div>
          <aside
            className="node-sidebar topic-graph-sidebar"
            aria-label="Member"
          >
            {selected ? (
              <>
                <span className="section-label">
                  {GROUP_LABELS[subgraph?.groups[selected.id] ?? "resource"]}
                </span>
                <h3 title={selected.name}>{selected.name}</h3>
                <span className="node-type">{selected.type}</span>
                <dl>
                  <dt>Account</dt>
                  <dd>{selected.account_id || "Unspecified"}</dd>
                  <dt>Sensitivity</dt>
                  <dd>{selected.sensitivity}</dd>
                  {optimized && overlay.sets && (
                    <>
                      <dt>In this view</dt>
                      <dd>
                        {overlay.sets.disabled.has(selected.id)
                          ? "Disabled (what-if)"
                          : `${count(overlay.overlay?.removed_edges.filter((e) => e.source === selected.id || e.target === selected.id).length ?? 0)} edges removed`}
                      </dd>
                    </>
                  )}
                </dl>
                <Button
                  variant="outline"
                  onClick={() => onOpenNeighborhood(selected.id, revision)}
                >
                  Explore neighborhood
                </Button>
                <small className="node-id" title={selected.id}>
                  {selected.id}
                </small>
              </>
            ) : (
              <>
                <span className="section-label">Current vs optimized</span>
                <p>
                  Current shows access as granted today. Optimized draws what
                  the proposal set would remove (red dashed) and disable (grey),
                  within this view. Nothing is applied.
                </p>
                <div className="sidebar-stat">
                  <span>Removed in view</span>
                  <b>
                    {optimized && overlay.overlay
                      ? count(
                          overlay.overlay.slice.grants_removed +
                            overlay.overlay.slice.hops_cut,
                        )
                      : "—"}
                  </b>
                </div>
                <div className="sidebar-stat">
                  <span>Disabled in view</span>
                  <b>
                    {optimized && overlay.overlay
                      ? count(overlay.overlay.slice.disabled_nodes)
                      : "—"}
                  </b>
                </div>
                <div className="sidebar-stat">
                  <span>Grants removed, whole graph</span>
                  <b>
                    {optimized && overlay.overlay
                      ? count(overlay.overlay.totals.grants_removed)
                      : "—"}
                  </b>
                </div>
              </>
            )}
          </aside>
        </div>
        <div className="graph-footer">
          <span>
            Lighter nodes belong to other topics · Select a member to explore
            its neighborhood
          </span>
          <span>Revision {revision.slice(0, 8)}</span>
        </div>
      </section>

      <div className="topic-page-grid">
        <section className="panel topic-section">
          <div className="panel-heading">
            <h3>Granted vs used per role</h3>
            <span className="muted">
              {detail
                ? `${count(roles.length)} of ${count(detail.view.total)} roles`
                : "Loading"}
            </span>
          </div>
          <div className="role-bars">
            {roles.map((r) => (
              <RoleBar key={r.id} role={r} />
            ))}
            {detail && !roles.length && (
              <p className="empty-line">No roles in this topic.</p>
            )}
          </div>
          <div className="topic-section-foot">
            <span className="role-bar-key">
              <i className="needed" aria-hidden="true" /> Needed (used or
              inferred)
              <i className="excess" aria-hidden="true" /> Granted, not needed ·
              share of each role&apos;s granted weight
            </span>
            <Button
              variant="outline"
              size="small"
              disabled={rolesNext === null}
              onClick={() => void moreRoles()}
            >
              {rolesNext === null ? "All shown" : `Show ${count(PAGE)} more`}
            </Button>
          </div>
        </section>

        <section className="panel topic-section">
          <div className="panel-heading">
            <h3>Excess privilege</h3>
            <span className="muted">
              {measured && summary
                ? EVIDENCE_LABELS[summary.evidence.status as "attested"]
                : "Granted only"}
            </span>
          </div>
          <div className="topic-section-body">
            {privilege && measured ? (
              <dl>
                <PrivilegeRows
                  label="Identity"
                  aggregate={privilege.identities}
                />
                <PrivilegeRows label="Role" aggregate={privilege.roles} />
                <dt>Unused grants</dt>
                <dd>
                  {count(privilege.unused_grants)} (
                  {count(privilege.unused_restricted_grants)} restricted)
                </dd>
                <dt>Dormant identities</dt>
                <dd>{count(privilege.dormant_identities)}</dd>
              </dl>
            ) : (
              <p className="muted">
                No usage evidence for this revision: only granted access is
                known.
              </p>
            )}
            <span className="section-label">Top contributors</span>
            <ol className="contributors">
              {(contributors ?? []).map((r) => (
                <li key={r.id}>
                  <span title={r.name}>{r.name}</span>
                  <small>
                    {count(r.reach_weight - (r.needed_weight ?? 0))} weight not
                    needed · EPI {epiText(r.epi)}
                    {r.flags.includes("hub") ? " · hub" : ""}
                  </small>
                </li>
              ))}
              {contributors && !contributors.length && (
                <li>
                  <small>No roles.</small>
                </li>
              )}
            </ol>
            <small>
              {evidence
                ? `${windowText(evidence)} · roles ranked by granted minus needed sensitivity weight.`
                : "Roles ranked by granted minus needed sensitivity weight."}
            </small>
          </div>
        </section>

        <section className="panel topic-section">
          <div className="panel-heading">
            <h3>Proposals by tier</h3>
            <span className="muted">Proposed, not applied</span>
          </div>
          <div className="topic-section-body">
            <dl className="tier-counts">
              {TIERS.map((tier) => (
                <TierRow
                  key={tier}
                  tier={tier}
                  value={proposals?.by_tier[tier] ?? 0}
                  onReview={() => onReviewProposals(topicId, tier)}
                />
              ))}
              <dt>Identity EPI after high tier</dt>
              <dd>
                {epiPrecise(proposals?.high_after.identities?.epi)} (
                {epiPrecise(proposals?.high_after.identities?.epi_excl_hubs)}{" "}
                without hubs)
              </dd>
              <dt>Role EPI after high tier</dt>
              <dd>{epiPrecise(proposals?.high_after.roles?.epi)}</dd>
            </dl>
            <Button
              variant="outline"
              onClick={() => onReviewProposals(topicId, "")}
            >
              Review this topic in the queue
            </Button>
          </div>
        </section>

        <section className="panel topic-section">
          <div className="panel-heading">
            <h3>Members</h3>
            <span className="muted">
              {membersView
                ? `${count(members.length)} of ${count(membersView.total)} shown`
                : "Loading"}
            </span>
          </div>
          <div className="topic-section-body">
            <div className="topic-tabs" role="group" aria-label="Members">
              {(Object.keys(KIND_LABELS) as TopicMemberKind[]).map((k) => (
                <button
                  key={k}
                  type="button"
                  aria-pressed={kind === k}
                  onClick={() => setKind(k)}
                >
                  {KIND_LABELS[k]}
                </button>
              ))}
            </div>
            <ul className="topic-members" aria-busy={busy}>
              {members.map((m) => (
                <li key={m.id}>
                  <span title={m.name}>{m.name}</span>
                  <small>
                    {m.kind === "resource"
                      ? `${m.sensitivity} · ${SEED_LABELS[m.seed] ?? m.seed}: ${m.reason}`
                      : (m.flags.length
                          ? m.flags.map((f) => FLAG_LABELS[f] ?? f).join(", ")
                          : `${count(m.reach_resources)} data assets granted`) +
                        (m.epi != null
                          ? ` · EPI ${epiText(m.epi)} ${BASIS_LABELS[m.basis as "used"] ? `(${m.basis})` : ""}`
                          : "")}
                  </small>
                </li>
              ))}
            </ul>
            <Button
              variant="outline"
              size="small"
              disabled={busy || membersView?.next_offset == null}
              onClick={() =>
                membersView?.next_offset != null &&
                void loadMembers(kind, membersView.next_offset)
              }
            >
              {membersView?.next_offset == null
                ? "All shown"
                : `Show ${count(PAGE)} more`}
            </Button>
          </div>
        </section>
      </div>
    </section>
  );
}

function TierRow({
  tier,
  value,
  onReview,
}: {
  tier: ProposalTier;
  value: number;
  onReview: () => void;
}) {
  return (
    <>
      <dt title={TIER_HINTS[tier]}>
        <i className={`tier-dot tier-${tier}`} aria-hidden="true" />
        {TIER_LABELS[tier]}
      </dt>
      <dd>
        <button
          type="button"
          className="text-link"
          disabled={!value}
          onClick={onReview}
        >
          {count(value)}
        </button>
      </dd>
    </>
  );
}

/** Granted weight split into needed and not needed (compact stacked bar). */
function RoleBar({ role }: { role: TopicMember }) {
  const granted = role.reach_weight;
  const needed = Math.min(granted, role.needed_weight ?? 0);
  const measured = role.basis === "used" || role.basis === "inferred";
  // Each bar is the role's own granted weight (hub roles would flatten a shared scale).
  const scale = (value: number) => `${granted ? (value / granted) * 100 : 0}%`;
  return (
    <div className="role-bar">
      <div className="role-bar-label">
        <span title={role.name}>{role.name}</span>
        <small>
          {measured
            ? `${count(needed)} / ${count(granted)} · EPI ${epiText(role.epi)}`
            : `${count(granted)} granted · no evidence`}
        </small>
      </div>
      <div
        className="role-bar-track"
        role="img"
        aria-label={`${role.name}: granted weight ${count(granted)}, needed ${measured ? count(needed) : "unknown"}`}
      >
        {measured && <i className="needed" style={{ width: scale(needed) }} />}
        <i
          className={measured ? "excess" : "granted"}
          style={{ width: scale(granted - (measured ? needed : 0)) }}
        />
      </div>
    </div>
  );
}
