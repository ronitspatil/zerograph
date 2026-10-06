"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { ChevronRight, LoaderCircle, Network } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import { kindNote, MAX_VISIBLE_MEMBERS, topFacets } from "@/lib/cluster-layout";
import type { MapExpansion } from "@/components/cluster-canvas";
import type {
  ClusterDetail,
  ClusterMap,
  ClusterMembers,
  ClusterSummary,
  GraphData,
  GraphNode,
} from "@/lib/types";
import { Button } from "@/components/ui/button";

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
const GraphCanvas = dynamic(
  () => import("@/components/graph-canvas").then((m) => m.GraphCanvas),
  { ssr: false, loading },
);

const count = formatCount;
const typeNames: Record<string, string> = {
  AIAgent: "AI agents",
  MCPServer: "MCP servers",
  CloudRole: "Cloud roles",
  ServiceAccount: "Service accounts",
  HumanUser: "Human users",
  Database: "Databases",
  VectorStore: "Vector stores",
  S3Bucket: "S3 buckets",
  DataCategory: "Data categories",
};
const noRisk = new Set<string>();
/** Members listed for keyboard selection (the map itself shows up to 5,000). */
export const LISTED_MEMBERS = 300;
/** A revision without clusters is backfilled by the worker; check again this often. */
export const UNAVAILABLE_RETRY_MS = 30_000;

/**
 * Obsidian-like global view: precomputed structural clusters as sized
 * super-nodes. A cluster that fits the on-screen budget (5,000 members across
 * all expanded clusters) expands in place into its members; a larger one opens
 * its sub-groups as a new level. Members hand off to the bounded neighborhood
 * explorer.
 */
export function GlobalMap({
  reloadKey,
  stale,
  onError,
  onOpenNeighborhood,
}: {
  reloadKey: number;
  stale: boolean;
  onError: (e: unknown) => void;
  onOpenNeighborhood: (nodeId: string, revision: string) => void;
}) {
  const [map, setMap] = useState<ClusterMap | null>(null);
  const [detail, setDetail] = useState<ClusterDetail | null>(null);
  const [unavailable, setUnavailable] = useState("");
  const [busy, setBusy] = useState(true);
  const [hovered, setHovered] = useState<ClusterSummary | null>(null);
  const [member, setMember] = useState<GraphNode | null>(null);
  const [expansions, setExpansions] = useState<MapExpansion[]>([]);
  const [expanding, setExpanding] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const request = useRef<AbortController | null>(null);
  const expandRequest = useRef<AbortController | null>(null);
  const begin = () => {
    request.current?.abort();
    expandRequest.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setHovered(null);
    setMember(null);
    setExpansions([]);
    setExpanding(null);
    setNotice("");
    return controller;
  };
  const loadTop = useCallback(async () => {
    const controller = begin();
    try {
      const result = await api<ClusterMap>(
        "graph/clusters?level=0&edge_limit=1000",
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      setMap(result);
      setDetail(null);
      setUnavailable("");
    } catch (e) {
      if (controller.signal.aborted) return;
      if (e instanceof ApiError && e.status === 404) {
        setMap(null);
        setDetail(null);
        setUnavailable(e.message);
      } else onError(e);
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }, [onError]);
  const openCluster = useCallback(
    async (id: string) => {
      if (!map) return;
      const controller = begin();
      const params = new URLSearchParams({ revision: map.revision });
      try {
        const result = await api<ClusterDetail>(
          `graph/clusters/${encodeURIComponent(id)}?${params}`,
          { signal: controller.signal },
        );
        if (!controller.signal.aborted) setDetail(result);
      } catch (e) {
        if (!controller.signal.aborted) onError(e);
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    },
    [map, onError],
  );
  const visible = expansions.reduce((sum, e) => sum + e.nodes.length, 0);
  const expand = useCallback(
    async (target: ClusterSummary) => {
      if (!map) return;
      expandRequest.current?.abort();
      const controller = new AbortController();
      expandRequest.current = controller;
      setExpanding(target.id);
      setNotice("");
      const params = new URLSearchParams({ revision: map.revision });
      for (const e of expansions) params.append("expanded", e.cluster.id);
      try {
        const result = await api<ClusterMembers>(
          `graph/clusters/${encodeURIComponent(target.id)}/members?${params}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setExpansions((list) => [
          ...list.filter((e) => e.cluster.id !== target.id),
          {
            cluster: result.cluster,
            nodes: result.nodes,
            edges: result.edges,
            degrees: result.degrees,
          },
        ]);
        if (result.view.truncated)
          setNotice(
            `${result.cluster.label}: ${count(result.view.shown_members)} of ${count(result.view.total_members)} members and the first ${count(result.view.shown_edges)} relationships shown.`,
          );
      } catch (e) {
        if (controller.signal.aborted) return;
        if (e instanceof ApiError && e.status === 422) setNotice(e.message);
        else onError(e);
      } finally {
        if (!controller.signal.aborted) setExpanding(null);
      }
    },
    [map, expansions, onError],
  );
  const collapse = (id: string) => {
    setExpansions((list) => list.filter((e) => e.cluster.id !== id));
    setMember((m) =>
      m &&
      expansions.some(
        (e) => e.cluster.id === id && e.degrees[m.id] !== undefined,
      )
        ? null
        : m,
    );
    setNotice("");
  };
  /** Expand in place when the cluster fits the on-screen budget; otherwise open its level. */
  const activate = (target: ClusterSummary) => {
    if (expansions.some((e) => e.cluster.id === target.id)) collapse(target.id);
    else if (fitsInPlace(target)) void expand(target);
    else void openCluster(target.id);
  };
  const fitsInPlace = (target: ClusterSummary) =>
    target.size <= MAX_VISIBLE_MEMBERS - visible;
  useEffect(() => {
    void loadTop();
    return () => {
      request.current?.abort();
      expandRequest.current?.abort();
    };
  }, [loadTop, reloadKey]);
  useEffect(() => {
    if (!unavailable) return;
    const timer = setInterval(() => void loadTop(), UNAVAILABLE_RETRY_MS);
    return () => clearInterval(timer);
  }, [unavailable, loadTop]);
  const members: GraphData | null = useMemo(
    () =>
      detail && detail.view.mode === "members"
        ? {
            revision: detail.revision,
            nodes: detail.nodes,
            edges: detail.node_edges,
            warnings: detail.warnings,
          }
        : null,
    [detail],
  );
  const clusters = detail ? detail.children : (map?.clusters ?? []);
  const links = detail ? detail.edges : (map?.edges ?? []);
  const focus = hovered ?? detail?.cluster ?? null;
  const inPlace = member
    ? expansions.find((e) => e.degrees[member.id] !== undefined)
    : undefined;
  const shownIds = useMemo(
    () => new Set(expansions.flatMap((e) => e.nodes.map((n) => n.id))),
    [expansions],
  );
  const listedMembers = useMemo(
    () =>
      expansions
        .flatMap((e) =>
          e.nodes.map((n) => ({ node: n, degree: e.degrees[n.id] ?? 0 })),
        )
        .sort(
          (a, b) => b.degree - a.degree || a.node.id.localeCompare(b.node.id),
        )
        .slice(0, LISTED_MEMBERS)
        .map((m) => m.node),
    [expansions],
  );
  const shownRelationships = (id: string) => {
    const seen = new Set<string>();
    for (const e of expansions)
      for (const edge of e.edges)
        if (
          (edge.source === id || edge.target === id) &&
          shownIds.has(edge.source) &&
          shownIds.has(edge.target)
        )
          seen.add(edge.id);
    return seen.size;
  };

  if (unavailable)
    return (
      <div className="empty-state">
        <Network size={28} aria-hidden="true" />
        <h3>Global map not available yet</h3>
        <p>{unavailable}. This view checks again every 30 seconds.</p>
      </div>
    );
  if (!map)
    return (
      <div className="canvas-loading" role="status">
        Loading global map…
      </div>
    );
  return (
    <div className="global-map">
      <nav className="global-map-crumbs" aria-label="Map level">
        <button
          type="button"
          disabled={!detail || busy}
          onClick={() => void loadTop()}
        >
          Global map
        </button>
        {detail?.path.map((crumb, i) => (
          <span key={crumb.id}>
            <ChevronRight size={12} aria-hidden="true" />
            {i === detail.path.length - 1 ? (
              <strong title={crumb.label}>{crumb.label}</strong>
            ) : (
              <button
                type="button"
                disabled={busy || stale}
                title={crumb.label}
                onClick={() => void openCluster(crumb.id)}
              >
                {crumb.label}
              </button>
            )}
          </span>
        ))}
      </nav>
      <div className="exploration-status global-map-status" role="status">
        <span>
          {!detail ? (
            <>
              {count(map.view.shown_clusters)} / {count(map.view.clusters)}{" "}
              top-level clusters · {count(map.view.total_nodes)} entities ·{" "}
              {count(map.view.total_edges)} relationships ·{" "}
              {count(map.view.shown_links)} / {count(map.view.links)} cluster
              links
              {map.view.truncated ? " · Partial map" : " · Complete map"}
            </>
          ) : detail.view.mode === "clusters" ? (
            <>
              {count(detail.view.shown_children)} /{" "}
              {count(detail.view.total_children)} child clusters ·{" "}
              {count(detail.cluster.size)} entities ·{" "}
              {count(detail.view.shown_links)} /{" "}
              {count(detail.view.total_links)} links between them
              {detail.view.truncated ? " · Partial level" : " · Complete level"}
            </>
          ) : (
            <>
              {count(detail.view.shown_members)} /{" "}
              {count(detail.view.total_members)} members ·{" "}
              {count(detail.view.shown_member_edges)} /{" "}
              {count(detail.view.total_member_edges)} relationships inside ·{" "}
              {count(detail.cluster.boundary_edges)} leave this cluster
              {detail.view.truncated
                ? " · Partial cluster"
                : " · Complete cluster"}
            </>
          )}
        </span>
        <span className="global-map-notice">{map.view.notice}</span>
      </div>
      <div className="graph-body">
        <div className="graph-main">
          {busy ? (
            <div className="canvas-loading" role="status">
              Loading map level…
            </div>
          ) : members ? (
            <GraphCanvas
              graph={{ ...members, view: { mode: "neighborhood" } }}
              selected={member?.id ?? null}
              riskNodes={noRisk}
              simulation={null}
              onSelect={setMember}
            />
          ) : (
            <div className="global-map-canvas">
              <ClusterCanvas
                clusters={clusters}
                links={links}
                expansions={expansions}
                selected={inPlace ? (member?.id ?? null) : null}
                onOpen={activate}
                onHover={setHovered}
                onSelect={setMember}
              />
              {(expansions.length > 0 || expanding || notice) && (
                <div className="global-map-inplace" role="status">
                  {expanding ? (
                    <span>Expanding…</span>
                  ) : (
                    <span>
                      {count(visible)} / {count(MAX_VISIBLE_MEMBERS)} members
                      shown in place
                    </span>
                  )}
                  {notice && <span className="inplace-notice">{notice}</span>}
                  {expansions.length > 0 && (
                    <button
                      type="button"
                      onClick={() => {
                        setExpansions([]);
                        setMember(null);
                        setNotice("");
                      }}
                    >
                      Collapse all
                    </button>
                  )}
                </div>
              )}
            </div>
          )}
          <div
            className="identity-list"
            aria-label={members ? "Select a member" : "Open a cluster"}
          >
            {members
              ? members.nodes.map((n) => (
                  <button
                    key={n.id}
                    className={member?.id === n.id ? "selected" : ""}
                    onClick={() => setMember(n)}
                  >
                    {n.name}
                  </button>
                ))
              : [
                  ...clusters.map((c) => (
                    <button
                      key={c.id}
                      disabled={stale}
                      aria-pressed={expansions.some(
                        (e) => e.cluster.id === c.id,
                      )}
                      onClick={() => activate(c)}
                    >
                      {c.label} · {count(c.size)}
                    </button>
                  )),
                  ...listedMembers.map((n) => (
                    <button
                      key={`m:${n.id}`}
                      className={member?.id === n.id ? "selected" : ""}
                      onClick={() => setMember(n)}
                    >
                      {n.name}
                    </button>
                  )),
                ]}
          </div>
        </div>
        <aside className="node-sidebar global-map-sidebar">
          {member && inPlace ? (
            <>
              <span className="section-label">Member</span>
              <h3 title={member.name}>{member.name}</h3>
              <span className="node-type">{member.type}</span>
              <dl>
                <dt>Account</dt>
                <dd>{member.account_id || "Unspecified"}</dd>
                <dt>Relationships</dt>
                <dd>{count(inPlace.degrees[member.id] ?? 0)}</dd>
                <dt>Shown here</dt>
                <dd>{count(shownRelationships(member.id))}</dd>
                <dt>Cluster</dt>
                <dd title={inPlace.cluster.label}>{inPlace.cluster.label}</dd>
              </dl>
              <Button
                variant="outline"
                disabled={stale || !map}
                onClick={() =>
                  map && onOpenNeighborhood(member.id, map.revision)
                }
              >
                Open neighborhood
              </Button>
              <Button
                variant="ghost"
                onClick={() => collapse(inPlace.cluster.id)}
              >
                Collapse cluster
              </Button>
              <small className="node-id" title={member.id}>
                {member.id}
              </small>
            </>
          ) : member && detail ? (
            <>
              <span className="section-label">Member</span>
              <h3 title={member.name}>{member.name}</h3>
              <span className="node-type">{member.type}</span>
              <dl>
                <dt>Account</dt>
                <dd>{member.account_id || "Unspecified"}</dd>
                <dt>Relationships</dt>
                <dd>
                  {count(
                    detail.node_edges.filter(
                      (e) => e.source === member.id || e.target === member.id,
                    ).length,
                  )}{" "}
                  shown inside
                </dd>
                <dt>Leave cluster</dt>
                <dd>{count(detail.boundary_edges[member.id] ?? 0)}</dd>
              </dl>
              <Button
                variant="outline"
                disabled={stale}
                onClick={() => onOpenNeighborhood(member.id, detail.revision)}
              >
                Open neighborhood
              </Button>
              <small className="node-id" title={member.id}>
                {member.id}
              </small>
            </>
          ) : focus ? (
            <>
              <span className="section-label">
                {hovered ? "Cluster" : "Open cluster"}
              </span>
              <h3 title={focus.label}>{focus.label}</h3>
              <span className="node-type">{kindNote(focus.kind)}</span>
              <dl>
                <dt>Entities</dt>
                <dd>{count(focus.size)}</dd>
                <dt>Relationships inside</dt>
                <dd>{count(focus.internal_edges)}</dd>
                <dt>Leaving the cluster</dt>
                <dd>{count(focus.boundary_edges)}</dd>
                {topFacets(focus.types).map((f) => (
                  <FacetRow
                    key={`t:${f.name}`}
                    name={typeNames[f.name] ?? f.name}
                    count={f.count}
                  />
                ))}
              </dl>
              <span className="section-label">Accounts</span>
              <dl>
                {topFacets(focus.accounts).map((f) => (
                  <FacetRow key={`a:${f.name}`} name={f.name} count={f.count} />
                ))}
              </dl>
              {hovered && (
                <small>
                  {fitsInPlace(hovered)
                    ? `Select the circle to show its ${count(hovered.size)} members here.`
                    : "Select the circle to open this cluster."}
                </small>
              )}
            </>
          ) : (
            <>
              <span className="section-label">Global map</span>
              <p>
                Each circle is a group of densely connected entities, sized by
                how many it holds. Open one to see its sub-groups, then its
                members, then a member's neighborhood.
              </p>
              <div className="sidebar-stat">
                <span>Clusters (all levels)</span>
                <b>{count(map.view.total_clusters)}</b>
              </div>
              <div className="sidebar-stat">
                <span>Entities without relationships</span>
                <b>{count(map.view.isolated_nodes)}</b>
              </div>
              <small>{map.view.notice}</small>
            </>
          )}
        </aside>
      </div>
      <div className="graph-footer">
        <span>Clusters are structural, not permission boundaries</span>
        <span>Revision {map.revision.slice(0, 8)}</span>
      </div>
    </div>
  );
}

function FacetRow({ name, count: value }: { name: string; count: number }) {
  return (
    <>
      <dt className="facet-name" title={name}>
        {name}
      </dt>
      <dd>{count(value)}</dd>
    </>
  );
}
