"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ChevronRight,
  CircleHelp,
  GitPullRequest,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  Network,
  Plus,
  RefreshCw,
  Search,
  Unplug,
  X,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import type {
  Actor,
  AuditEvent,
  Finding,
  GraphData,
  GraphView,
  RoleMap,
  GraphSearch,
  GraphNode,
  Job,
  Overview,
  Remediation,
  Simulation,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Simulator } from "@/components/simulator";
import { RemediationHub } from "@/components/remediation-hub";
import { Sources } from "@/components/sources";
import { ExcessPrivilegePanel } from "@/components/privilege";
import { SensitivityChart } from "@/components/sensitivity-chart";
import { Wordmark } from "@/components/ui/logo";
import { GlobalMap } from "@/components/global-map";
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
type View = "overview" | "graph" | "remediation" | "sources" | "activity";
const titles: Record<View, { title: string; description: string }> = {
  overview: {
    title: "Security overview",
    description:
      "A clear view of your identities, data, and the access between them.",
  },
  graph: {
    title: "Identity & data graph",
    description:
      "Explore effective access. Find the paths that put your data at risk.",
  },
  remediation: {
    title: "Remediation hub",
    description:
      "Turn access findings into reviewable least-privilege changes.",
  },
  sources: {
    title: "Data sources",
    description:
      "Bring your cloud identities, agents, and data into one graph.",
  },
  activity: {
    title: "Audit activity",
    description: "Trace collection, simulations, and remediation decisions.",
  },
};
const nav = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "graph", label: "Knowledge graph", icon: Network },
  { id: "remediation", label: "Remediation", icon: GitPullRequest },
  { id: "sources", label: "Data sources", icon: Unplug },
  { id: "activity", label: "Audit activity", icon: Activity },
] as const;
const typeLabels: Record<string, string> = {
  AIAgent: "AI agent",
  MCPServer: "MCP server",
  CloudRole: "Cloud role",
  ServiceAccount: "Service account",
  HumanUser: "Human user",
};
// Findings arrive page by page for the displayed revision; the graph never waits on them.
const FINDINGS_PAGE = 200;
const emptyGraph: GraphView = {
  revision: "",
  nodes: [],
  edges: [],
  warnings: [],
  view: {
    mode: "sample",
    root_id: null,
    node_limit: 250,
    edge_limit: 1000,
    truncated: false,
    total_nodes: 0,
    total_edges: 0,
  },
};
export function Console({ demo }: { demo: boolean }) {
  const [view, setView] = useState<View>("graph");
  const [graph, setGraph] = useState<GraphView | RoleMap>(emptyGraph);
  const [graphMode, setGraphMode] = useState<"identities" | "roles" | "map">(
    "identities",
  );
  const graphModeRef = useRef<"identities" | "roles" | "map">("identities");
  // Bumped by refresh so the global map reloads its top level with the workspace.
  const [mapReload, setMapReload] = useState(0);
  const [graphBusy, setGraphBusy] = useState(false);
  const roles = graph.view.mode === "roles" ? (graph as RoleMap) : null;
  const [overview, setOverview] = useState<Overview | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsRevision, setFindingsRevision] = useState<string | null>(null);
  const [findingsMore, setFindingsMore] = useState(false);
  const [findingsBusy, setFindingsBusy] = useState(false);
  const findingsRequest = useRef<AbortController | null>(null);
  const workspaceRequest = useRef<AbortController | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [records, setRecords] = useState<Remediation[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [actor, setActor] = useState<Actor | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [simulation, setSimulation] = useState<Simulation | null>(null);
  const [search, setSearch] = useState("");
  const [searchResults, setSearchResults] = useState<GraphSearch | null>(null);
  const [searchBusy, setSearchBusy] = useState(false);
  const [revisionStale, setRevisionStale] = useState(false);
  const graphRequest = useRef<AbortController | null>(null);
  const searchRequest = useRef<AbortController | null>(null);
  const [account, setAccount] = useState("");
  const [type, setType] = useState("");
  const [risk, setRisk] = useState("");
  const [showHelp, setShowHelp] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const simulationKey = `${graph.revision}:${selected?.id ?? ""}:${simulating}`;
  const currentSimulationKey = useRef(simulationKey);
  currentSimulationKey.current = simulationKey;
  const acceptSimulation = useCallback(
    (result: Simulation) => {
      if (currentSimulationKey.current === simulationKey) setSimulation(result);
    },
    [simulationKey],
  );
  const canWrite = !!actor?.roles.some((r) => r === "analyst" || r === "admin");
  const canAdmin = !!actor?.roles.includes("admin");
  const refresh = useCallback(async () => {
    graphRequest.current?.abort();
    searchRequest.current?.abort();
    workspaceRequest.current?.abort();
    const controller = new AbortController();
    graphRequest.current = controller;
    // Overview and workspace records load independently of the bounded graph:
    // whole-revision analysis must never hold the graph view back.
    const workspace = new AbortController();
    workspaceRequest.current = workspace;
    setSearchResults(null);
    setSearch("");
    setError("");
    setMapReload((key) => key + 1);
    const workspaceError = (e: unknown) => {
      if (workspace.signal.aborted) return;
      if (e instanceof ApiError && e.status === 401) {
        window.location.assign("/login");
        return;
      }
      setError(e instanceof Error ? e.message : "Could not load workspace");
    };
    api<Overview>("overview", { signal: workspace.signal }).then((o) => {
      if (!workspace.signal.aborted) setOverview(o);
    }, workspaceError);
    Promise.all([
      api<Job[]>("ingestions", { signal: workspace.signal }),
      api<Remediation[]>("remediations", { signal: workspace.signal }),
      api<Actor>("me", { signal: workspace.signal }),
    ])
      .then(async ([j, r, a]) => {
        if (workspace.signal.aborted) return;
        setJobs(j);
        setRecords(r);
        setActor(a);
        if (a.roles.includes("admin")) {
          const audit = await api<AuditEvent[]>("audit", {
            signal: workspace.signal,
          });
          if (!workspace.signal.aborted) setEvents(audit);
        }
      })
      .catch(workspaceError);
    try {
      const g = await api<GraphView | RoleMap>(
        graphModeRef.current === "roles"
          ? "graph/roles?role_limit=50&edge_limit=1000"
          : "graph/explore?node_limit=250&edge_limit=2000",
        {
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted) return;
      setGraph(g);
      setSelected(
        (previous) => g.nodes.find((n) => n.id === previous?.id) ?? null,
      );
      setSimulation(null);
      setSimulating(false);
      setRevisionStale(false);
      setGraphBusy(false);
    } catch (e) {
      if (controller.signal.aborted) return;
      if (e instanceof ApiError && e.status === 401) {
        window.location.assign("/login");
        return;
      }
      setError(e instanceof Error ? e.message : "Could not load workspace");
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    return () => {
      graphRequest.current?.abort();
      searchRequest.current?.abort();
      workspaceRequest.current?.abort();
      findingsRequest.current?.abort();
    };
  }, [refresh]);
  const explorationError = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) {
      window.location.assign("/login");
      return;
    }
    if (e instanceof ApiError && e.status === 409) {
      setRevisionStale(true);
      setSelected(null);
      setSimulation(null);
      setSimulating(false);
      setSearchResults(null);
      setError(
        "The graph revision changed. Refresh the workspace to reset this view.",
      );
    } else setError(e instanceof Error ? e.message : "Could not explore graph");
  }, []);
  const loadFindings = useCallback(
    async (revision: string, after?: string) => {
      findingsRequest.current?.abort();
      const controller = new AbortController();
      findingsRequest.current = controller;
      setFindingsBusy(true);
      // Pinned to the displayed revision: a publish in between returns 409.
      const params = new URLSearchParams({
        limit: String(FINDINGS_PAGE),
        revision,
      });
      if (after) params.set("cursor", after);
      try {
        const page = await api<Finding[]>(`findings?${params}`, {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setFindings((previous) => (after ? [...previous, ...page] : page));
        setFindingsRevision(revision);
        setFindingsMore(page.length === FINDINGS_PAGE);
      } catch (e) {
        if (!controller.signal.aborted) explorationError(e);
      } finally {
        if (!controller.signal.aborted) setFindingsBusy(false);
      }
    },
    [explorationError],
  );
  useEffect(() => {
    // Findings of a published revision are immutable: load once per revision.
    if (graph.revision === findingsRevision) return;
    if (!graph.revision) {
      findingsRequest.current?.abort();
      setFindings([]);
      setFindingsMore(false);
      setFindingsBusy(false);
      setFindingsRevision("");
      return;
    }
    void loadFindings(graph.revision);
  }, [graph.revision, findingsRevision, loadFindings]);
  const loadMoreFindings = () => {
    const last = findings[findings.length - 1];
    if (findingsRevision && last) void loadFindings(findingsRevision, last.id);
  };
  const findingsTotal =
    overview && overview.revision === findingsRevision
      ? overview.toxic_combinations
      : undefined;
  const loadRoles = useCallback(
    async (cursor?: string) => {
      graphModeRef.current = "roles";
      setGraphMode("roles");
      graphRequest.current?.abort();
      searchRequest.current?.abort();
      const controller = new AbortController();
      graphRequest.current = controller;
      setSearch("");
      setSearchResults(null);
      setAccount("");
      setType("");
      setRisk("");
      setSelected(null);
      setSimulation(null);
      setSimulating(false);
      setError("");
      setGraphBusy(true);
      const params = new URLSearchParams({
        role_limit: "50",
        edge_limit: "1000",
      });
      if (cursor) {
        params.set("cursor", cursor);
        params.set("revision", graph.revision);
      }
      try {
        const result = await api<RoleMap>(`graph/roles?${params}`, {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setGraph(result);
        setRevisionStale(false);
      } catch (e) {
        if (!controller.signal.aborted) explorationError(e);
      } finally {
        if (!controller.signal.aborted) setGraphBusy(false);
      }
    },
    [graph.revision, explorationError],
  );
  const showIdentities = () => {
    graphModeRef.current = "identities";
    setGraphMode("identities");
    setAccount("");
    setType("");
    setRisk("");
    setGraphBusy(false);
    void refresh();
  };
  const showMap = () => {
    graphModeRef.current = "map";
    setGraphMode("map");
    setSelected(null);
    setSimulation(null);
    setSimulating(false);
    setGraphBusy(false);
    setError("");
  };
  const explore = useCallback(
    async (root: string, pinned?: string) => {
      graphModeRef.current = "identities";
      setGraphMode("identities");
      setGraphBusy(true);
      graphRequest.current?.abort();
      searchRequest.current?.abort();
      const controller = new AbortController();
      graphRequest.current = controller;
      setSearchResults(null);
      setSearch("");
      setSimulation(null);
      setSimulating(false);
      const params = new URLSearchParams({
        root_id: root,
        node_limit: "250",
        edge_limit: "1000",
        revision: pinned ?? graph.revision,
      });
      try {
        const result = await api<GraphView>(`graph/explore?${params}`, {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setGraph(result);
        setSelected(result.nodes.find((n) => n.id === root) ?? null);
        setAccount("");
        setType("");
        setRisk("");
        setError("");
      } catch (e) {
        if (!controller.signal.aborted) explorationError(e);
      } finally {
        if (!controller.signal.aborted) setGraphBusy(false);
      }
    },
    [graph.revision, explorationError],
  );
  useEffect(() => {
    searchRequest.current?.abort();
    const controller = new AbortController();
    searchRequest.current = controller;
    setSearchResults(null);
    setSearchBusy(false);
    const q = search.trim();
    if (!q || revisionStale) return;
    setSearchBusy(true);
    const timer = setTimeout(async () => {
      try {
        const params = new URLSearchParams({
          q,
          limit: "25",
          revision: graph.revision,
        });
        const result = await api<GraphSearch>(`graph/search?${params}`, {
          signal: controller.signal,
        });
        if (!controller.signal.aborted) setSearchResults(result);
      } catch (e) {
        if (!controller.signal.aborted) explorationError(e);
      } finally {
        if (!controller.signal.aborted) setSearchBusy(false);
      }
    }, 300);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [search, graph.revision, revisionStale, explorationError]);
  useEffect(() => {
    if (!jobs.some((j) => ["queued", "running", "retrying"].includes(j.status)))
      return;
    const timer = setInterval(() => void refresh(), 3000);
    return () => clearInterval(timer);
  }, [jobs, refresh]);
  const riskNodes = useMemo(
    () => new Set(findings.flatMap((f) => f.path)),
    [findings],
  );
  const filtered = useMemo(() => {
    const nodes = graph.nodes.filter(
      (n) =>
        (!account || n.account_id === account) &&
        (!type || n.type === type) &&
        (!risk || riskNodes.has(n.id)),
    );
    const ids = new Set(nodes.map((n) => n.id));
    return {
      ...graph,
      nodes,
      edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target)),
    };
  }, [graph, account, type, risk, riskNodes]);
  useEffect(() => {
    if (selected && !filtered.nodes.some((n) => n.id === selected.id)) {
      setSelected(null);
      setSimulation(null);
      setSimulating(false);
    }
  }, [filtered, selected]);
  const outsideView =
    simulation?.affected_nodes.filter(
      (id) => !filtered.nodes.some((n) => n.id === id),
    ).length ?? 0;
  const identities = useMemo(
    () =>
      graph.nodes.filter((n) =>
        ["ServiceAccount", "AIAgent", "MCPServer", "CloudRole"].includes(
          n.type,
        ),
      ),
    [graph],
  );
  const selectNode = useCallback((node: GraphNode) => {
    setSelected(node);
    setSimulation(null);
    setSimulating(false);
  }, []);
  const selectFinding = (f: Finding) => {
    setSearch("");
    setAccount("");
    setType("");
    setRisk("");
    setView("graph");
    void explore(f.source);
  };
  async function loadDemo() {
    setActionBusy(true);
    setError("");
    try {
      await api("ingestions", {
        method: "POST",
        body: JSON.stringify({ source: "demo" }),
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Demo ingestion failed");
    } finally {
      setActionBusy(false);
    }
  }
  function exportGraph() {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            ...filtered,
            ...(roles
              ? {
                  role_summaries: roles.role_summaries.filter((s) =>
                    filtered.nodes.some((n) => n.id === s.role_id),
                  ),
                }
              : {}),
            export_scope: roles
              ? "current visible role-map page"
              : "current visible view",
          },
          null,
          2,
        ),
      ],
      {
        type: "application/json",
      },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = roles
      ? "zerograph-visible-role-page.json"
      : "zerograph-visible-view.json";
    a.click();
    URL.revokeObjectURL(url);
  }
  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.assign("/login");
  }
  const metrics = [
    {
      label: "Non-human identities",
      value: overview?.total_nhis,
      caption: "Service accounts, roles and agents",
      accent: "",
    },
    {
      label: "AI agents",
      value: overview?.ai_agents,
      caption: "Connected autonomous identities",
      accent: "",
    },
    {
      label: "Toxic combinations",
      value: overview?.toxic_combinations,
      caption: "Exposed paths to sensitive data",
      accent: "red",
    },
    {
      label: "High blast radius",
      value: overview?.high_blast_radius,
      caption: "Potential exposure score ≥ 70",
      accent: "amber",
    },
  ];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/" aria-label="ZeroGraph home">
          <Wordmark />
        </a>
        <div className="workspace-switch">
          <strong>{demo ? "Demo workspace" : "Organization"}</strong>
          <span title={actor?.tenant_id}>
            {actor?.tenant_id || "Connecting…"}
          </span>
        </div>
        <nav aria-label="Primary">
          {nav.map((n) => (
            <button
              key={n.id}
              className={view === n.id ? "nav-item active" : "nav-item"}
              onClick={() => setView(n.id)}
            >
              <n.icon size={16} aria-hidden="true" />
              <span className="nav-text">{n.label}</span>
              {n.id === "remediation" && records.length > 0 && (
                <span className="nav-count">{formatCount(records.length)}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button className="nav-item" onClick={() => setShowHelp(true)}>
            <CircleHelp size={16} aria-hidden="true" />
            <span className="nav-text">Platform guide</span>
          </button>
          <button className="nav-item" onClick={logout}>
            <LogOut size={16} aria-hidden="true" />
            <span className="nav-text">Sign out</span>
          </button>
          <div className="user">
            <span className="user-avatar">
              {actor?.subject.slice(0, 1).toUpperCase() || "U"}
            </span>
            <div>
              <strong>
                {demo ? "Demo operator" : actor?.subject || "Signed in"}
              </strong>
              <span>
                {canAdmin ? "Administrator" : canWrite ? "Analyst" : "Viewer"}
              </span>
            </div>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace
            <ChevronRight size={12} aria-hidden="true" />
            <span>{titles[view].title}</span>
          </div>
          <div className="topbar-right">
            <span className="connection-status">
              <i
                className={error ? "status-dot warning" : "status-dot"}
                aria-hidden="true"
              />
              {loading
                ? "Connecting"
                : error
                  ? "Connection issue"
                  : "API connected"}
            </span>
            <button
              className="icon-button"
              onClick={() => void refresh()}
              aria-label="Refresh workspace"
            >
              <RefreshCw size={15} className={loading ? "spin" : ""} />
            </button>
          </div>
        </header>
        <main className="main-content">
          <div className="page-heading">
            <div>
              <h1>{titles[view].title}</h1>
              <p>{titles[view].description}</p>
            </div>
            <div className="heading-actions">
              <Button
                variant="outline"
                onClick={exportGraph}
                disabled={!filtered.nodes.length || revisionStale}
              >
                <ArrowDownToLine size={14} aria-hidden="true" />
                {roles ? "Export visible role page" : "Export visible view"}
              </Button>
              <Button onClick={() => setView("sources")}>
                <Plus size={14} aria-hidden="true" />
                Add source
              </Button>
            </div>
          </div>
          {error && (
            <div className="error-banner" role="alert">
              {error}
              <button onClick={() => void refresh()}>Retry</button>
            </div>
          )}
          {loading ? (
            <div className="loading-state">
              <LoaderCircle className="spin" />
              Connecting your workspace…
            </div>
          ) : (
            <>
              {(view === "graph" || view === "overview") && (
                <div className="metric-grid">
                  {metrics.map((m) => (
                    <div
                      className={
                        m.accent && m.value
                          ? `metric-card ${m.accent}`
                          : "metric-card"
                      }
                      key={m.label}
                    >
                      <span>{m.label}</span>
                      <strong>{overview ? formatCount(m.value) : "—"}</strong>
                      <small>{m.caption}</small>
                    </div>
                  ))}
                </div>
              )}
              {view === "graph" && (
                <>
                  <div
                    className="graph-view-switch"
                    role="group"
                    aria-label="Graph view"
                  >
                    <button
                      type="button"
                      aria-pressed={graphMode === "identities"}
                      onClick={showIdentities}
                    >
                      Identity & data
                    </button>
                    <button
                      type="button"
                      aria-pressed={graphMode === "roles"}
                      onClick={() => void loadRoles()}
                    >
                      Role map
                    </button>
                    <button
                      type="button"
                      aria-pressed={graphMode === "map"}
                      onClick={showMap}
                    >
                      Global map
                    </button>
                  </div>
                  {graphMode === "map" && (
                    <section className="panel graph-panel">
                      <div className="panel-heading">
                        <div>
                          <h2>Global map</h2>
                          <span className="muted">
                            The whole revision, grouped by graph structure or by
                            topic. Open a cluster or topic to drill down; open a
                            member to explore its neighborhood.
                          </span>
                        </div>
                        {revisionStale && (
                          <span className="live-label warning">
                            <i
                              className="status-dot warning"
                              aria-hidden="true"
                            />
                            Revision changed — refresh required
                          </span>
                        )}
                      </div>
                      <GlobalMap
                        reloadKey={mapReload}
                        stale={revisionStale}
                        onError={explorationError}
                        onOpenNeighborhood={(id, revision) =>
                          void explore(id, revision)
                        }
                      />
                    </section>
                  )}
                  <section
                    className="panel graph-panel"
                    hidden={graphMode === "map"}
                  >
                    <div className="panel-heading">
                      <div>
                        <h2>
                          {roles
                            ? "Organization-wide role map"
                            : "Access relationships"}
                        </h2>
                        <span className="muted">
                          {roles ? (
                            <>
                              {formatCount(filtered.nodes.length)} /{" "}
                              {formatCount(roles.view.total_roles)} roles ·{" "}
                              {formatCount(filtered.edges.length)} /{" "}
                              {formatCount(roles.view.total_role_edges)} direct
                              role links visible
                              {roles.view.role_map_truncated ||
                              filtered.nodes.length < roles.nodes.length ||
                              filtered.edges.length < roles.edges.length
                                ? " · Partial role map"
                                : " · Complete role map"}
                              . Other identities and data assets excluded.
                              Workspace: {formatCount(roles.view.total_nodes)}{" "}
                              nodes · {formatCount(roles.view.total_edges)}{" "}
                              relationships
                              {roles.view.truncated
                                ? " · Partial workspace"
                                : " · Complete workspace"}
                            </>
                          ) : (
                            <>
                              {formatCount(filtered.nodes.length)} /{" "}
                              {formatCount(graph.view.total_nodes)} nodes ·{" "}
                              {formatCount(filtered.edges.length)} /{" "}
                              {formatCount(graph.view.total_edges)}{" "}
                              relationships visible
                              {graph.view.truncated ||
                              filtered.nodes.length < graph.nodes.length ||
                              filtered.edges.length < graph.edges.length
                                ? " · Partial view"
                                : " · Complete view"}
                            </>
                          )}
                        </span>
                      </div>
                      {revisionStale && (
                        <span className="live-label warning">
                          <i
                            className="status-dot warning"
                            aria-hidden="true"
                          />
                          Revision changed — refresh required
                        </span>
                      )}
                    </div>
                    <div className="exploration-status" role="status">
                      {roles
                        ? "Structural direct role links across the organization (all certainties, not effective permissions). Current-page filters only."
                        : graph.view.mode === "neighborhood"
                          ? "One-hop neighborhood"
                          : "Bounded initial view"}
                      . Filters apply only to visible nodes. Search covers the
                      whole tenant revision.
                      <Button
                        variant="outline"
                        size="small"
                        onClick={() =>
                          roles ? void loadRoles() : void refresh()
                        }
                      >
                        {roles ? "First role page" : "Reset to initial view"}
                      </Button>
                      {roles && (
                        <Button
                          variant="outline"
                          size="small"
                          disabled={
                            graphBusy ||
                            revisionStale ||
                            !roles.view.has_more ||
                            !roles.view.next_cursor
                          }
                          onClick={() =>
                            void loadRoles(roles.view.next_cursor!)
                          }
                        >
                          Next role page
                        </Button>
                      )}
                      {roles && (
                        <span>
                          {roles.view.has_more
                            ? "More role pages available."
                            : "Last role page."}
                        </span>
                      )}
                      {/* Always rendered so a simulation result never re-wraps this bar. */}
                      <span
                        className="simulation-note"
                        data-active={simulation ? "true" : undefined}
                        aria-hidden={simulation ? undefined : true}
                      >
                        Server-side simulation: {simulation ? outsideView : 0}{" "}
                        affected nodes outside the visible view.
                      </span>
                    </div>
                    <div className="graph-toolbar">
                      <div className="search-field">
                        <Search size={14} aria-hidden="true" />
                        <input
                          aria-label="Search identities"
                          maxLength={128}
                          disabled={revisionStale}
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                          placeholder="Search identities or assets…"
                        />
                      </div>
                      <div className="filters">
                        <select
                          aria-label="Filter by account"
                          value={account}
                          onChange={(e) => setAccount(e.target.value)}
                        >
                          <option value="">All accounts</option>
                          {overview?.accounts.map((a) => (
                            <option key={a}>{a}</option>
                          ))}
                        </select>
                        <select
                          aria-label="Filter by identity type"
                          value={type}
                          onChange={(e) => setType(e.target.value)}
                        >
                          <option value="">All identity types</option>
                          {Object.entries(typeLabels).map(([t, label]) => (
                            <option key={t} value={t}>
                              {label}
                            </option>
                          ))}
                        </select>
                        <select
                          aria-label="Filter by risk"
                          value={risk}
                          onChange={(e) => setRisk(e.target.value)}
                        >
                          <option value="">All risk levels</option>
                          <option value="high">High / critical paths</option>
                        </select>
                      </div>
                    </div>
                    {search.trim() && (
                      <div
                        className="graph-search-results"
                        aria-label="Global identity search"
                        aria-live="polite"
                      >
                        {searchBusy
                          ? "Searching tenant revision…"
                          : searchResults && (
                              <>
                                {searchResults.nodes.length === 0 && (
                                  <p>No matching identities.</p>
                                )}
                                {searchResults.nodes.map((n) => (
                                  <button
                                    key={n.id}
                                    onClick={() => void explore(n.id)}
                                  >
                                    <span>{n.name}</span> <small>{n.id}</small>
                                  </button>
                                ))}
                                {searchResults.has_more && (
                                  <p>More matches exist. Refine your search.</p>
                                )}
                              </>
                            )}
                      </div>
                    )}
                    <div className="graph-body">
                      <div className="graph-main">
                        {graphBusy ? (
                          <div className="canvas-loading" role="status">
                            Loading graph view…
                          </div>
                        ) : graph.nodes.length ? (
                          <GraphCanvas
                            graph={filtered}
                            selected={selected?.id || null}
                            riskNodes={riskNodes}
                            simulation={simulation}
                            onSelect={selectNode}
                          />
                        ) : (
                          <div className="empty-state">
                            <Network size={28} aria-hidden="true" />
                            <h3>
                              {roles
                                ? "No roles in this workspace"
                                : "Your access graph starts here"}
                            </h3>
                            <p>
                              {roles
                                ? "This role map excludes identities and data assets. Switch to Identity & data to explore them."
                                : "Connect an AWS account or import your agent inventory to map identity-to-data access."}
                            </p>
                            {roles ? null : demo ? (
                              <Button onClick={loadDemo} disabled={actionBusy}>
                                {actionBusy
                                  ? "Queuing sample…"
                                  : "Load sample environment"}
                              </Button>
                            ) : (
                              <Button onClick={() => setView("sources")}>
                                Connect a data source
                              </Button>
                            )}
                          </div>
                        )}
                        {graph.nodes.length > 0 && (
                          <div
                            className="identity-list"
                            aria-label="Select an identity"
                          >
                            {filtered.nodes.map((n) => (
                              <button
                                key={n.id}
                                onClick={() => selectNode(n)}
                                className={
                                  selected?.id === n.id ? "selected" : ""
                                }
                              >
                                {n.name}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                      {selected ? (
                        <aside className="node-sidebar">
                          <div className="node-sidebar-heading">
                            <span className="section-label">Details</span>
                            <button
                              className="icon-button"
                              onClick={() => {
                                setSelected(null);
                                setSimulation(null);
                                setSimulating(false);
                              }}
                              aria-label="Close node details"
                            >
                              <X size={15} />
                            </button>
                          </div>
                          <h3 title={selected.name}>{selected.name}</h3>
                          <span className="node-type">
                            {typeLabels[selected.type] ?? selected.type}
                          </span>
                          <dl>
                            <dt>Provider</dt>
                            <dd>{selected.provider}</dd>
                            <dt>Account</dt>
                            <dd>{selected.account_id || "Unspecified"}</dd>
                            <dt>Data sensitivity</dt>
                            <dd>{selected.sensitivity}</dd>
                            <dt>Public entry point</dt>
                            <dd>{selected.internet_exposed ? "Yes" : "No"}</dd>
                            <dt>Authentication</dt>
                            <dd>
                              {selected.authenticated ? "Required" : "Absent"}
                            </dd>
                            <dt>Risk path</dt>
                            <dd
                              className={
                                riskNodes.has(selected.id) ? "danger-text" : ""
                              }
                            >
                              {riskNodes.has(selected.id)
                                ? "Detected"
                                : "None detected"}
                            </dd>
                          </dl>
                          {roles &&
                            roles.role_summaries.find(
                              (s) => s.role_id === selected.id,
                            ) && (
                              <div className="role-direct-summary">
                                <strong>
                                  Direct structural links · whole revision
                                </strong>
                                <p>
                                  Both directions, all certainties. Not
                                  effective permissions or transitive exposure.
                                </p>
                                {roles.role_summaries
                                  .filter((s) => s.role_id === selected.id)
                                  .map((s) => (
                                    <dl key={s.role_id}>
                                      <dt>Distinct direct neighbors</dt>
                                      <dd>{formatCount(s.direct_neighbors)}</dd>
                                      <dt>
                                        Linked identities (including roles)
                                      </dt>
                                      <dd>
                                        {formatCount(s.linked_identities)}
                                      </dd>
                                      <dt>Linked data assets</dt>
                                      <dd>
                                        {formatCount(s.linked_data_assets)}
                                      </dd>
                                    </dl>
                                  ))}
                              </div>
                            )}
                          {selected.tags.length > 0 && (
                            <div className="tag-row">
                              <span className="section-label">Tags</span>
                              <p>{selected.tags.join(", ")}</p>
                            </div>
                          )}
                          <Button
                            variant="outline"
                            disabled={revisionStale}
                            onClick={() => void explore(selected.id)}
                          >
                            Explore neighborhood
                          </Button>
                          <Button
                            onClick={() => setSimulating(true)}
                            disabled={!canWrite || revisionStale}
                          >
                            Simulate compromise
                          </Button>
                          <small className="node-id" title={selected.id}>
                            {selected.id}
                          </small>
                        </aside>
                      ) : (
                        <aside className="node-sidebar empty-sidebar">
                          <span className="section-label">Details</span>
                          <p>
                            Select an identity or asset to inspect its
                            properties and simulate downstream exposure.
                          </p>
                          <div className="sidebar-stat">
                            <span>Confirmed edges</span>
                            <b>{formatCount(overview?.confirmed_edges)}</b>
                          </div>
                          <div className="sidebar-stat">
                            <span>Conditional / declared</span>
                            <b>{formatCount(overview?.uncertain_edges)}</b>
                          </div>
                          <small>
                            Dashed edges represent access that still requires
                            verification.
                          </small>
                        </aside>
                      )}
                    </div>
                    <div className="graph-footer">
                      <span>
                        Hover a node to trace its access paths · Simulation
                        depth up to 5 hops
                      </span>
                      <span>
                        {graph.revision
                          ? `Revision ${graph.revision.slice(0, 8)}`
                          : "No snapshot"}
                      </span>
                    </div>
                  </section>
                  {graph.warnings.length > 0 && (
                    <details className="coverage-notice">
                      <summary>
                        Collection coverage & evidence (
                        {formatCount(graph.warnings.length)})
                      </summary>
                      {graph.warnings.map((w, i) => (
                        <p key={i}>{w}</p>
                      ))}
                    </details>
                  )}
                  <Findings
                    findings={findings}
                    graph={graph}
                    onSelect={selectFinding}
                    total={findingsTotal}
                    hasMore={findingsMore}
                    busy={findingsBusy}
                    onLoadMore={loadMoreFindings}
                  />
                </>
              )}
              {view === "overview" && (
                <>
                  <div className="overview-grid">
                    <div className="panel chart-panel">
                      <div className="panel-heading">
                        <h3>Data sensitivity</h3>
                      </div>
                      <p className="muted">
                        Classified data assets across the current snapshot
                      </p>
                      <SensitivityChart sensitivity={overview?.sensitivity} />
                    </div>
                    <div className="panel summary-panel">
                      <h3>Access evidence</h3>
                      <div className="summary-number">
                        <b>{formatCount(overview?.data_assets)}</b>
                        <span>connected data assets</span>
                      </div>
                      <div className="sidebar-stat">
                        <span>Confirmed relationships</span>
                        <b>{formatCount(overview?.confirmed_edges)}</b>
                      </div>
                      <div className="sidebar-stat">
                        <span>Awaiting verification</span>
                        <b>{formatCount(overview?.uncertain_edges)}</b>
                      </div>
                      <p>
                        Scores prioritize review using sensitivity-weighted
                        reachability. They represent potential exposure rather
                        than breach probability.
                      </p>
                      <Button
                        variant="outline"
                        onClick={() => setView("graph")}
                      >
                        Explore access graph
                      </Button>
                    </div>
                    <ExcessPrivilegePanel
                      tile={overview?.excess_privilege}
                      onOpenSources={
                        canAdmin ? () => setView("sources") : undefined
                      }
                    />
                  </div>
                  <Findings
                    findings={findings}
                    graph={graph}
                    onSelect={selectFinding}
                    total={findingsTotal}
                    hasMore={findingsMore}
                    busy={findingsBusy}
                    onLoadMore={loadMoreFindings}
                  />
                </>
              )}
              {view === "remediation" && (
                <RemediationHub
                  identities={identities}
                  records={records}
                  onRefresh={() => void refresh()}
                  demo={demo}
                  canWrite={canWrite}
                  canAdmin={canAdmin}
                />
              )}
              {view === "sources" && (
                <Sources
                  jobs={jobs}
                  onRefresh={() => void refresh()}
                  canAdmin={canAdmin}
                />
              )}
              {view === "activity" && (
                <div className="panel history-panel">
                  <div className="panel-heading">
                    <h3>Workspace audit trail</h3>
                    <span className="muted">
                      Latest {formatCount(events.length)} events
                    </span>
                  </div>
                  {!canAdmin ? (
                    <p className="empty-line">
                      Administrator access is required to view audit events.
                    </p>
                  ) : events.length ? (
                    <table>
                      <thead>
                        <tr>
                          <th>Action</th>
                          <th>Actor</th>
                          <th>Time</th>
                          <th>Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.map((e) => (
                          <tr key={e.id}>
                            <td>{e.action}</td>
                            <td>{e.actor}</td>
                            <td>{new Date(e.created_at).toLocaleString()}</td>
                            <td>
                              <details>
                                <summary>View details</summary>
                                <pre>{JSON.stringify(e.detail, null, 2)}</pre>
                              </details>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="empty-line">No audit events recorded yet.</p>
                  )}
                </div>
              )}
            </>
          )}
        </main>
      </div>
      {simulating && selected && (
        <>
          <button
            className="drawer-backdrop"
            aria-label="Close simulator"
            onClick={() => {
              setSimulating(false);
              setSimulation(null);
            }}
          />
          <Simulator
            node={selected}
            onResult={acceptSimulation}
            onClose={() => {
              setSimulating(false);
              setSimulation(null);
            }}
          />
        </>
      )}
      {showHelp && (
        <div className="modal-backdrop">
          <section
            className="guide-modal"
            role="dialog"
            aria-modal="true"
            aria-label="Platform guide"
          >
            <div className="panel-heading">
              <h2>Understand your access graph</h2>
              <button
                className="icon-button"
                onClick={() => setShowHelp(false)}
                aria-label="Close guide"
              >
                <X size={16} />
              </button>
            </div>
            <p>1. Add a source to collect identities and data relationships.</p>
            <p>
              2. Inspect findings and their evidence. Dashed graph edges are
              conditional or declared access.
            </p>
            <p>
              3. Select an identity and simulate compromise to explore its
              reachable data assets.
            </p>
            <p>
              4. Supply an IAM policy and audit coverage to preview a
              least-privilege change. An administrator can create a draft PR in
              the configured repository.
            </p>
            <p>
              Metadata classifications are hypotheses. Validate them before
              treating assets as confirmed sensitive data.
            </p>
            <Button onClick={() => setShowHelp(false)}>Got it</Button>
          </section>
        </div>
      )}
    </div>
  );
}
function Findings({
  findings,
  graph,
  onSelect,
  total,
  hasMore,
  busy,
  onLoadMore,
}: {
  findings: Finding[];
  graph: GraphData;
  onSelect: (f: Finding) => void;
  total?: number;
  hasMore: boolean;
  busy: boolean;
  onLoadMore: () => void;
}) {
  const count =
    hasMore && total !== undefined
      ? `${formatCount(findings.length)} of ${formatCount(total)}`
      : `${formatCount(findings.length)}${hasMore ? "+" : ""}`;
  const name = (id: string) => graph.nodes.find((n) => n.id === id)?.name || id;
  return (
    <section className="panel findings-panel">
      <div className="panel-heading">
        <div>
          <h2>Toxic access paths</h2>
          <span className="muted">
            Prioritize exposed identities with access to sensitive data
          </span>
        </div>
        <span className="muted count">
          {count} {findings.length === 1 && !hasMore ? "finding" : "findings"}
        </span>
      </div>
      {findings.length ? (
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Access path</th>
              <th>Evidence</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>
                  <span className={`severity ${f.severity}`}>
                    <i aria-hidden="true" />
                    {f.severity}
                  </span>
                </td>
                <td>
                  <strong>{f.title}</strong>
                  <div className="path-preview">
                    {f.path.map((id, i) => (
                      <span key={id}>
                        {i > 0 && <ChevronRight size={11} aria-hidden="true" />}
                        <span>{name(id)}</span>
                      </span>
                    ))}
                  </div>
                </td>
                <td>
                  <span className="muted">
                    {f.conditional ? "Conditional path" : "Confirmed path"}
                  </span>
                  <details>
                    <summary>View evidence</summary>
                    {f.evidence.map((e, i) => (
                      <p key={i}>{e}</p>
                    ))}
                    <p>{f.recommendation}</p>
                  </details>
                </td>
                <td>
                  <button className="text-link" onClick={() => onSelect(f)}>
                    Investigate
                    <ArrowRight size={12} aria-hidden="true" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="empty-line" role={busy ? "status" : undefined}>
          {busy
            ? "Loading findings…"
            : graph.nodes.length
              ? "No exposed sensitive-data paths detected in the current snapshot."
              : "Collect an environment to evaluate toxic access paths."}
        </div>
      )}
      {hasMore && findings.length > 0 && (
        <div className="empty-line">
          <Button
            variant="outline"
            size="small"
            disabled={busy}
            onClick={onLoadMore}
          >
            {busy ? "Loading…" : "Load more findings"}
          </Button>
        </div>
      )}
    </section>
  );
}
