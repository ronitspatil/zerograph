"use client";
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import dynamic from "next/dynamic";
import { LoaderCircle, Tags } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import type {
  ClusterLink,
  ClusterSummary,
  TopicDetail,
  TopicMap,
  TopicMember,
  TopicMemberKind,
  TopicSummary,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  BASIS_LABELS,
  epiText,
  EVIDENCE_LABELS,
  PrivilegeRows,
  windowText,
} from "@/components/privilege";

const loading = () => (
  <div className="canvas-loading">
    <LoaderCircle className="spin" />
    Loading map…
  </div>
);
const ClusterCanvas = dynamic(
  () => import("@/components/cluster-canvas").then((m) => m.ClusterCanvas),
  { ssr: false, loading },
);

const count = formatCount;
/** Members fetched per page in the topic panel. */
export const TOPIC_PAGE = 50;
/** A revision without topics is backfilled by the worker; check again this often. */
export const TOPICS_RETRY_MS = 30_000;
export const TOPICS_NOTICE_FALLBACK =
  "Topics are derived from resource tags, names and access. They are not policy boundaries.";

/** Color by the share of a topic's granted weight that lies outside it (structural). */
export const SHARE_COLORS = [
  { below: 0.1, color: "#4c9a8a", text: "under 10%" },
  { below: 0.2, color: "#a7a04b", text: "10–20%" },
  { below: 0.35, color: "#d0803c", text: "20–35%" },
  { below: Infinity, color: "#d9534f", text: "35% or more" },
];
const FALLBACK_COLOR = "#73849a";

export function topicColor(topic: TopicSummary): string {
  if (topic.kind === "fallback") return FALLBACK_COLOR;
  return SHARE_COLORS.find((s) => topic.cross_weight_share < s.below)!.color;
}

export const FLAG_LABELS: Record<string, string> = {
  hub: "Hub role",
  via_hub: "Can assume a hub role",
  privileged: "Privileged",
  cross_topic: "Cross-topic access",
  restricted_outside: "Restricted data outside topic",
  dormant: "Dormant (no observed use)",
};

const KIND_LABELS: Record<TopicMemberKind, string> = {
  resource: "Data assets",
  role: "Roles",
  identity: "Identities",
};

const SEED_LABELS: Record<string, string> = {
  tag: "Tag",
  metadata: "Metadata",
  name: "Name token",
  usage: "Observed co-use",
  coaccess: "Shared access",
  fallback: "Service type",
};

const percent = (share: number) => `${Math.round(share * 100)}%`;

/** A topic drawn with the cluster canvas: circle area is the topic's sensitivity weight. */
export function topicCircle(topic: TopicSummary): ClusterSummary {
  return {
    id: topic.id,
    parent_id: null,
    depth: 0,
    kind: "community",
    label: topic.label,
    representative_id: topic.id,
    size: Math.max(1, topic.resource_weight),
    child_count: 0,
    member_count: topic.resources,
    internal_edges: 0,
    boundary_edges: topic.cross_grants_out + topic.cross_grants_in,
    dominant_type: "",
    types: topic.types,
    accounts: {},
  };
}

/**
 * Relationship topics lens of the global map: one circle per topic (data assets
 * grouped by tags, names and shared access), sized by sensitivity weight and
 * colored by how much of its roles' granted weight lies in other topics; lines
 * count cross-topic grants. Selecting a topic opens its panel: label reason,
 * counts, most over-privileged roles and paged members. Everything describes
 * granted (structural) access, not what is needed.
 */
export function TopicLens({
  reloadKey,
  stale,
  onError,
  onOpenNeighborhood,
  statusSizer,
}: {
  reloadKey: number;
  stale: boolean;
  onError: (e: unknown) => void;
  onOpenNeighborhood: (nodeId: string, revision: string) => void;
  /** The structural status line, laid invisibly under this one to keep the bar height. */
  statusSizer?: ReactNode;
}) {
  const [map, setMap] = useState<TopicMap | null>(null);
  const [unavailable, setUnavailable] = useState("");
  const [hovered, setHovered] = useState<TopicSummary | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [kind, setKind] = useState<TopicMemberKind>("resource");
  const [detail, setDetail] = useState<TopicDetail | null>(null);
  const [members, setMembers] = useState<TopicMember[]>([]);
  const [member, setMember] = useState<TopicMember | null>(null);
  const [busy, setBusy] = useState(false);
  const request = useRef<AbortController | null>(null);
  const detailRequest = useRef<AbortController | null>(null);

  const loadMap = useCallback(async () => {
    request.current?.abort();
    detailRequest.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    try {
      const result = await api<TopicMap>("graph/topics?edge_limit=1000", {
        signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      setMap(result);
      setUnavailable("");
      setSelected(null);
      setDetail(null);
      setMembers([]);
      setMember(null);
    } catch (e) {
      if (controller.signal.aborted) return;
      if (e instanceof ApiError && e.status === 404) {
        setMap(null);
        setUnavailable(e.message);
      } else onError(e);
    }
  }, [onError]);

  const loadPage = useCallback(
    async (topic: string, which: TopicMemberKind, offset: number) => {
      if (!map) return;
      detailRequest.current?.abort();
      const controller = new AbortController();
      detailRequest.current = controller;
      setBusy(true);
      const params = new URLSearchParams({
        kind: which,
        offset: String(offset),
        limit: String(TOPIC_PAGE),
        revision: map.revision,
      });
      try {
        const result = await api<TopicDetail>(
          `graph/topics/${encodeURIComponent(topic)}?${params}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setDetail(result);
        setMembers((list) =>
          offset ? [...list, ...result.members] : result.members,
        );
      } catch (e) {
        if (!controller.signal.aborted) onError(e);
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    },
    [map, onError],
  );

  const openTopic = (topic: string) => {
    setSelected(topic);
    setMember(null);
    setMembers([]);
    setDetail(null);
    void loadPage(topic, kind, 0);
  };
  const showKind = (which: TopicMemberKind) => {
    setKind(which);
    setMember(null);
    if (selected) {
      setMembers([]);
      void loadPage(selected, which, 0);
    }
  };

  useEffect(() => {
    void loadMap();
    return () => {
      request.current?.abort();
      detailRequest.current?.abort();
    };
  }, [loadMap, reloadKey]);
  useEffect(() => {
    if (!unavailable) return;
    const timer = setInterval(() => void loadMap(), TOPICS_RETRY_MS);
    return () => clearInterval(timer);
  }, [unavailable, loadMap]);

  const circles = useMemo(() => map?.topics.map(topicCircle) ?? [], [map]);
  const links: ClusterLink[] = useMemo(() => map?.edges ?? [], [map]);
  const byId = useMemo(
    () => new Map((map?.topics ?? []).map((t) => [t.id, t])),
    [map],
  );
  const captions = useMemo(
    () =>
      new Map(
        (map?.topics ?? []).map((t) => [
          t.id,
          `${t.label} · ${count(t.resources)}`,
        ]),
      ),
    [map],
  );

  if (unavailable)
    return (
      <div className="empty-state">
        <Tags size={28} aria-hidden="true" />
        <h3>Topics not available yet</h3>
        <p>{unavailable}. This view checks again every 30 seconds.</p>
      </div>
    );
  if (!map)
    // Same frame as the loaded lens (status bar, canvas, list, panel, footer): no shift.
    return (
      <>
        <div
          className={`exploration-status global-map-status${statusSizer ? " stacked" : ""}`}
        >
          <div className="status-layer">
            <span>Loading topics…</span>
          </div>
          {statusSizer && (
            <div className="status-layer sizer" aria-hidden="true">
              {statusSizer}
            </div>
          )}
        </div>
        <div className="graph-body">
          <div className="graph-main">
            <div className="canvas-loading" role="status">
              <LoaderCircle className="spin" />
              Loading topics…
            </div>
            <div className="identity-list" aria-hidden="true" />
          </div>
          <aside className="node-sidebar global-map-sidebar topic-sidebar" />
        </div>
        <div className="graph-footer">
          <span>
            Topics are derived from tags, names and access, not policy
            boundaries
          </span>
          <span>Revision …</span>
        </div>
      </>
    );
  const summary = map.summary;
  const privilege = summary.privilege;
  const evidence = privilege?.evidence;
  const measured = !!evidence && evidence.status !== "none";
  const focus = selected ? (byId.get(selected) ?? null) : null;
  const shown = hovered ?? focus;
  const notice = map.view.notice || TOPICS_NOTICE_FALLBACK;
  const statusSpans = (
    <>
      <span>
        {count(map.view.shown_topics)} / {count(map.view.total_topics)} topics ·{" "}
        {count(summary.resources as number)} data assets ·{" "}
        {count(summary.cross_topic_grants as number)} cross-topic grants ·{" "}
        {count(summary.hub_roles as number)} hub roles ·{" "}
        {count(map.view.shown_links)} / {count(map.view.links)} topic links
        {map.view.truncated ? " · Partial map" : " · Complete map"}
      </span>
      <span className="global-map-notice">
        {measured
          ? `Granted vs needed · ${EVIDENCE_LABELS[evidence.status].toLowerCase()}`
          : "Granted (structural) access, not usage"}
      </span>
    </>
  );
  return (
    <>
      <div
        className={`exploration-status global-map-status${statusSizer ? " stacked" : ""}`}
        role="status"
      >
        {statusSizer ? (
          <>
            <div className="status-layer">{statusSpans}</div>
            <div className="status-layer sizer" aria-hidden="true">
              {statusSizer}
            </div>
          </>
        ) : (
          statusSpans
        )}
      </div>
      <div className="graph-body">
        <div className="graph-main">
          <div className="global-map-canvas" data-label-scope>
            <ClusterCanvas
              clusters={circles}
              links={links}
              selected={selected}
              onOpen={(c) => openTopic(c.id)}
              onHover={(c) => setHovered(c ? (byId.get(c.id) ?? null) : null)}
              colorOf={(c) =>
                byId.has(c.id) ? topicColor(byId.get(c.id)!) : FALLBACK_COLOR
              }
              captionOf={(c) => captions.get(c.id) ?? c.label}
              label="Topics map"
              unit="topics"
              legend={[
                { text: "Circle area: sensitivity weight" },
                ...SHARE_COLORS.map((s) => ({
                  text: `Outside the topic: ${s.text}`,
                  color: s.color,
                })),
                { text: "Unassigned", color: FALLBACK_COLOR },
                { text: "Line width: cross-topic grants" },
              ]}
            />
          </div>
          <div className="identity-list" aria-label="Open a topic">
            {map.topics.map((t) => (
              <button
                key={t.id}
                disabled={stale}
                aria-pressed={selected === t.id}
                onClick={() => openTopic(t.id)}
              >
                {t.label} · {count(t.resources)}
              </button>
            ))}
          </div>
        </div>
        <aside
          className="node-sidebar global-map-sidebar topic-sidebar"
          aria-label="Topic details"
        >
          {member && focus ? (
            <MemberPanel
              member={member}
              topics={byId}
              stale={stale}
              onBack={() => setMember(null)}
              onOpen={() => onOpenNeighborhood(member.id, map.revision)}
            />
          ) : hovered && hovered.id !== selected ? (
            <TopicFacts topic={hovered} measured={measured} hint />
          ) : focus ? (
            <>
              <TopicFacts topic={focus} measured={measured} />
              <span className="section-label">Most over-privileged roles</span>
              {detail && detail.topic.id === focus.id ? (
                detail.top_roles.length ? (
                  <div className="topic-member-list">
                    {detail.top_roles.map((r) => (
                      <button
                        key={`top:${r.id}`}
                        type="button"
                        onClick={() => setMember(r)}
                      >
                        <span>{r.name}</span>
                        <small>
                          {r.flags.map((f) => FLAG_LABELS[f]).join(", ")}
                        </small>
                      </button>
                    ))}
                  </div>
                ) : (
                  <small>No flagged roles in this topic.</small>
                )
              ) : (
                <small>Loading…</small>
              )}
              <div
                className="topic-tabs"
                role="group"
                aria-label="Topic members"
              >
                {(Object.keys(KIND_LABELS) as TopicMemberKind[]).map((k) => (
                  <button
                    key={k}
                    type="button"
                    aria-pressed={kind === k}
                    onClick={() => showKind(k)}
                  >
                    {KIND_LABELS[k]}
                  </button>
                ))}
              </div>
              <small className="topic-page-status">
                {detail && detail.topic.id === focus.id
                  ? `${count(members.length)} of ${count(detail.view.total)} ${KIND_LABELS[kind].toLowerCase()} shown`
                  : "Loading…"}
              </small>
              <div className="topic-member-list" aria-busy={busy}>
                {members.map((m) => (
                  <button key={m.id} type="button" onClick={() => setMember(m)}>
                    <span>{m.name}</span>
                    <small>
                      {m.kind === "resource"
                        ? `${m.sensitivity} · ${SEED_LABELS[m.seed] ?? m.seed}`
                        : (m.flags.length
                            ? m.flags.map((f) => FLAG_LABELS[f]).join(", ")
                            : `${count(m.reach_resources)} data assets granted`) +
                          (m.epi != null
                            ? ` · EPI ${epiText(m.epi)} ${m.basis}`
                            : "")}
                    </small>
                  </button>
                ))}
              </div>
              {detail &&
                detail.topic.id === focus.id &&
                detail.view.next_offset !== null && (
                  <Button
                    variant="outline"
                    disabled={busy || stale}
                    onClick={() =>
                      void loadPage(focus.id, kind, detail.view.next_offset!)
                    }
                  >
                    Show {count(TOPIC_PAGE)} more
                  </Button>
                )}
              <small>{notice}</small>
            </>
          ) : (
            <>
              <span className="section-label">Topics</span>
              <p>
                Each circle is a topic: data assets that belong together by
                their tags, names and shared access, with the roles and
                identities granted on them. Select one to see why it was named,
                its most over-privileged roles and its members.
              </p>
              <div className="sidebar-stat">
                <span>Roles with cross-topic grants</span>
                <b>
                  {count(summary.cross_topic_roles as number)} /{" "}
                  {count(summary.roles as number)}
                </b>
              </div>
              <div className="sidebar-stat">
                <span>Hub roles</span>
                <b>{count(summary.hub_roles as number)}</b>
              </div>
              {privilege && (
                <>
                  <span className="section-label">Excess privilege</span>
                  {measured ? (
                    <>
                      <div className="sidebar-stat">
                        <span>Identities (without hubs)</span>
                        <b>
                          {epiText(privilege.identities.epi)} (
                          {epiText(privilege.identities.epi_excl_hubs)})
                        </b>
                      </div>
                      <div className="sidebar-stat">
                        <span>Roles (without hubs)</span>
                        <b>
                          {epiText(privilege.roles.epi)} (
                          {epiText(privilege.roles.epi_excl_hubs)})
                        </b>
                      </div>
                      <div className="sidebar-stat">
                        <span>Unused grants (restricted)</span>
                        <b>
                          {count(privilege.unused_grants)} (
                          {count(privilege.unused_restricted_grants)})
                        </b>
                      </div>
                      <div className="sidebar-stat">
                        <span>Dormant identities</span>
                        <b>{count(privilege.dormant_identities)}</b>
                      </div>
                      <small>
                        {EVIDENCE_LABELS[evidence.status]} ·{" "}
                        {windowText(evidence)} · sufficient for{" "}
                        {evidence.sufficient_services?.join(", ") || "none"} ·
                        sources {evidence.sources?.join(", ")}; RoleLastUsed and
                        Access Advisor are hints only.
                      </small>
                    </>
                  ) : (
                    <small>
                      No usage evidence yet: only granted access is shown.
                      Upload a CloudTrail export in Data sources to compare it
                      with observed use.
                    </small>
                  )}
                </>
              )}
              <small>{notice}</small>
            </>
          )}
        </aside>
      </div>
      <div className="graph-footer">
        <span>
          Topics are derived from tags, names and access, not policy boundaries
        </span>
        <span>Revision {map.revision.slice(0, 8)}</span>
      </div>
    </>
  );
}

function TopicFacts({
  topic,
  hint,
  measured,
}: {
  topic: TopicSummary;
  hint?: boolean;
  measured?: boolean;
}) {
  const privilege = topic.privilege;
  return (
    <>
      <span className="section-label">{hint ? "Topic" : "Open topic"}</span>
      <h3 title={topic.label}>{topic.label}</h3>
      <span className="node-type">
        {topic.kind === "anchored" ? "Named topic" : "Unassigned group"}
      </span>
      <p className="topic-reason">{topic.reason}</p>
      <dl>
        <dt>Data assets</dt>
        <dd>{count(topic.resources)}</dd>
        <dt>Sensitivity weight</dt>
        <dd>{count(topic.resource_weight)}</dd>
        <dt>Roles</dt>
        <dd>{count(topic.roles)}</dd>
        <dt>Identities</dt>
        <dd>{count(topic.identities)}</dd>
        <dt>Roles flagged</dt>
        <dd>
          {count(topic.overprivileged_roles)} (
          {percent(topic.overprivileged_share)})
        </dd>
        <dt>Weight outside topic</dt>
        <dd>{percent(topic.cross_weight_share)}</dd>
        <dt>Cross-topic grants out</dt>
        <dd>{count(topic.cross_grants_out)}</dd>
        <dt>Cross-topic grants in</dt>
        <dd>{count(topic.cross_grants_in)}</dd>
        <dt>Hub role grants in</dt>
        <dd>{count(topic.hub_grants_in)}</dd>
      </dl>
      {measured && privilege && !hint && (
        <>
          <span className="section-label">Excess privilege</span>
          <dl>
            <PrivilegeRows label="Roles" aggregate={privilege.roles} />
            <PrivilegeRows
              label="Identities"
              aggregate={privilege.identities}
            />
            <dt>Unused grants</dt>
            <dd>
              {count(privilege.unused_grants)} (
              {count(privilege.unused_restricted_grants)} restricted)
            </dd>
            <dt>Dormant identities</dt>
            <dd>{count(privilege.dormant_identities)}</dd>
          </dl>
        </>
      )}
      {measured && privilege && hint && (
        <dl>
          <dt>Identity EPI</dt>
          <dd>
            {epiText(privilege.identities.epi)} (
            {epiText(privilege.identities.epi_excl_hubs)} without hubs)
          </dd>
        </dl>
      )}
      {hint && <small>Select the circle to open this topic.</small>}
    </>
  );
}

function MemberPanel({
  member,
  topics,
  stale,
  onBack,
  onOpen,
}: {
  member: TopicMember;
  topics: Map<string, TopicSummary>;
  stale: boolean;
  onBack: () => void;
  onOpen: () => void;
}) {
  return (
    <>
      <span className="section-label">
        {member.kind === "resource"
          ? "Data asset"
          : member.kind === "role"
            ? "Role"
            : "Identity"}
      </span>
      <h3 title={member.name}>{member.name}</h3>
      <span className="node-type">{member.type}</span>
      {member.flags.length > 0 && (
        <ul className="topic-flags" aria-label="Flags">
          {member.flags.map((f) => (
            <li key={f}>{FLAG_LABELS[f] ?? f}</li>
          ))}
        </ul>
      )}
      <dl>
        {member.kind === "resource" ? (
          <>
            <dt>Sensitivity</dt>
            <dd>{member.sensitivity}</dd>
            <dt>Topic from</dt>
            <dd>{SEED_LABELS[member.seed] ?? member.seed}</dd>
          </>
        ) : (
          <>
            <dt>Direct grants</dt>
            <dd>{count(member.direct_grants)}</dd>
            <dt>Data assets reached</dt>
            <dd>{count(member.reach_resources)}</dd>
            <dt>Granted weight</dt>
            <dd>{count(member.reach_weight)}</dd>
            <dt>Without hub roles</dt>
            <dd>{count(member.reach_weight_excl_hubs)}</dd>
            {member.kind === "role" && (
              <>
                <dt>Cross-topic grants</dt>
                <dd>{count(member.cross_topic_grants)}</dd>
              </>
            )}
            <dt>Restricted outside</dt>
            <dd>{count(member.restricted_outside)}</dd>
            {member.basis && member.basis !== "none" && (
              <>
                <dt>Needed weight</dt>
                <dd>
                  {count(member.needed_weight)} (
                  {count(member.needed_weight_excl_hubs)} without hubs)
                </dd>
                <dt>EPI</dt>
                <dd>
                  {epiText(member.epi)} ({epiText(member.epi_excl_hubs)} without
                  hubs)
                </dd>
                <dt>Needed from</dt>
                <dd>{BASIS_LABELS[member.basis]}</dd>
                <dt>Data assets used</dt>
                <dd>{count(member.used_resources)}</dd>
                <dt>Unused own grants</dt>
                <dd>
                  {count(member.unused_grants)} (
                  {count(member.unused_restricted)} restricted)
                </dd>
              </>
            )}
          </>
        )}
      </dl>
      {member.kind === "resource" ? (
        <p className="topic-reason">{member.reason}</p>
      ) : (
        member.profile.length > 0 && (
          <>
            <span className="section-label">Granted weight by topic</span>
            <dl>
              {member.profile.map((p) => (
                <ProfileRow
                  key={p.topic_id}
                  name={topics.get(p.topic_id)?.label ?? "Topic not on map"}
                  share={p.share}
                />
              ))}
            </dl>
          </>
        )
      )}
      <Button variant="outline" disabled={stale} onClick={onOpen}>
        Open neighborhood
      </Button>
      <Button variant="ghost" onClick={onBack}>
        Back to topic
      </Button>
      <small className="node-id" title={member.id}>
        {member.id}
      </small>
    </>
  );
}

function ProfileRow({ name, share }: { name: string; share: number }) {
  return (
    <>
      <dt className="facet-name" title={name}>
        {name}
      </dt>
      <dd>{percent(share)}</dd>
    </>
  );
}
