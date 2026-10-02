"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Bot,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Database,
  GitPullRequest,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  Network,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Unplug,
  X,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, ApiError } from "@/lib/api";
import type {
  Actor,
  AuditEvent,
  Finding,
  GraphData,
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
const emptyGraph: GraphData = {
  revision: "",
  nodes: [],
  edges: [],
  warnings: [],
};
export function Console({ demo }: { demo: boolean }) {
  const [view, setView] = useState<View>("graph");
  const [graph, setGraph] = useState<GraphData>(emptyGraph);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
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
  const [account, setAccount] = useState("");
  const [type, setType] = useState("");
  const [risk, setRisk] = useState("");
  const [showHelp, setShowHelp] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const canWrite = !!actor?.roles.some((r) => r === "analyst" || r === "admin");
  const canAdmin = !!actor?.roles.includes("admin");
  const refresh = useCallback(async () => {
    setError("");
    try {
      const [g, o, f, j, r, a] = await Promise.all([
        api<GraphData>("graph"),
        api<Overview>("overview"),
        api<Finding[]>("findings"),
        api<Job[]>("ingestions"),
        api<Remediation[]>("remediations"),
        api<Actor>("me"),
      ]);
      setGraph(g);
      setOverview(o);
      setFindings(f);
      setJobs(j);
      setRecords(r);
      setActor(a);
      if (a.roles.includes("admin"))
        setEvents(await api<AuditEvent[]>("audit"));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        window.location.assign("/login");
        return;
      }
      setError(e instanceof Error ? e.message : "Could not load workspace");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh]);
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
        (!type ||
          n.type === type ||
          ["Database", "S3Bucket", "VectorStore"].includes(n.type)) &&
        (!risk || riskNodes.has(n.id)) &&
        (!search ||
          n.name.toLowerCase().includes(search.toLowerCase()) ||
          n.id.toLowerCase().includes(search.toLowerCase())),
    );
    const ids = new Set(nodes.map((n) => n.id));
    return {
      ...graph,
      nodes,
      edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target)),
    };
  }, [graph, account, type, risk, search, riskNodes]);
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
    const node = graph.nodes.find((n) => n.id === f.source);
    if (node) {
      selectNode(node);
      setView("graph");
    }
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
    const blob = new Blob([JSON.stringify(graph, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "zerograph-snapshot.json";
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
      icon: Shield,
      caption: "Service accounts, roles & agents",
      accent: "blue",
    },
    {
      label: "AI agents",
      value: overview?.ai_agents,
      icon: Bot,
      caption: "Connected autonomous identities",
      accent: "green",
    },
    {
      label: "Toxic combinations",
      value: overview?.toxic_combinations,
      icon: ShieldAlert,
      caption: "Exposed paths to sensitive data",
      accent: "red",
    },
    {
      label: "High blast radius",
      value: overview?.high_blast_radius,
      icon: Activity,
      caption: "Potential exposure score ≥ 70",
      accent: "amber",
    },
  ];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/">
          <div className="brand-mark">
            <Network size={23} />
          </div>
          ZeroGraph
        </a>
        <div className="workspace-switch">
          <div className="workspace-avatar">{demo ? "D" : "W"}</div>
          <div>
            <strong>{demo ? "Demo workspace" : "Organization"}</strong>
            <span>{actor?.tenant_id || "Connecting…"}</span>
          </div>
          <ChevronDown size={14} />
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {nav.map((n) => (
            <button
              key={n.id}
              className={view === n.id ? "nav-item active" : "nav-item"}
              onClick={() => setView(n.id)}
            >
              <n.icon size={17} />
              {n.label}
              {n.id === "remediation" && records.length > 0 && (
                <span className="nav-count">{records.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="posture-card">
            <div>
              <span className="status-dot" />
              IDENTITY × DATA
            </div>
            <p>
              Understand access.
              <br />
              Reduce exposure.
            </p>
            <button onClick={() => setShowHelp(true)}>
              How ZeroGraph works
              <ArrowRight size={13} />
            </button>
          </div>
          <button className="nav-item" onClick={() => setShowHelp(true)}>
            <CircleHelp size={17} />
            Platform guide
          </button>
          <button className="nav-item" onClick={logout}>
            <LogOut size={17} />
            Sign out
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
            <ChevronRight size={13} />
            <span>{titles[view].title}</span>
          </div>
          <div className="topbar-right">
            {demo && <span className="pill">DEMO DATA</span>}
            <span className="connection-status">
              <i className={error ? "status-dot warning" : "status-dot"} />
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
              <RefreshCw size={16} className={loading ? "spin" : ""} />
            </button>
          </div>
        </header>
        <main className="main-content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">ZEROGRAPH / SECURITY POSTURE</span>
              <h1>{titles[view].title}</h1>
              <p>{titles[view].description}</p>
            </div>
            <div className="heading-actions">
              <Button
                variant="outline"
                onClick={exportGraph}
                disabled={!graph.nodes.length}
              >
                <ArrowDownToLine size={15} />
                Export graph
              </Button>
              <Button onClick={() => setView("sources")}>
                <Plus size={15} />
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
                    <div className={`metric-card ${m.accent}`} key={m.label}>
                      <div>
                        <span>{m.label}</span>
                        <m.icon size={17} />
                      </div>
                      <strong>{m.value ?? 0}</strong>
                      <small>{m.caption}</small>
                    </div>
                  ))}
                </div>
              )}
              {view === "graph" && (
                <>
                  <section className="panel graph-panel">
                    <div className="panel-heading">
                      <div>
                        <h2>Access relationships</h2>
                        <span className="muted">
                          {filtered.nodes.length} nodes ·{" "}
                          {filtered.edges.length} relationships
                        </span>
                      </div>
                      <span className="live-label">
                        <i className="status-dot" />
                        {graph.revision
                          ? "Snapshot loaded"
                          : "Awaiting collection"}
                      </span>
                    </div>
                    <div className="graph-toolbar">
                      <div className="search-field">
                        <Search size={15} />
                        <input
                          aria-label="Search identities"
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                          placeholder="Search identities or assets…"
                        />
                      </div>
                      <div className="filters">
                        <SlidersHorizontal size={14} />
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
                          {[
                            "AIAgent",
                            "MCPServer",
                            "CloudRole",
                            "ServiceAccount",
                            "HumanUser",
                          ].map((t) => (
                            <option key={t} value={t}>
                              {t.replace(/([a-z])([A-Z])/g, "$1 $2")}
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
                    <div className="graph-body">
                      <div className="graph-main">
                        {graph.nodes.length ? (
                          <GraphCanvas
                            graph={filtered}
                            selected={selected?.id || null}
                            riskNodes={riskNodes}
                            simulation={simulation}
                            onSelect={selectNode}
                          />
                        ) : (
                          <div className="empty-state">
                            <Network size={42} />
                            <h3>Your access graph starts here</h3>
                            <p>
                              Connect an AWS account or import your agent
                              inventory to map identity-to-data access.
                            </p>
                            {demo ? (
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
                          <div className="panel-heading">
                            <span className="eyebrow">NODE DETAILS</span>
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
                          <div className="node-symbol">
                            <Bot size={25} />
                          </div>
                          <h3>{selected.name}</h3>
                          <span className="pill green">{selected.type}</span>
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
                          {selected.tags.length > 0 && (
                            <div className="tag-row">
                              {selected.tags.map((t) => (
                                <span className="pill" key={t}>
                                  {t}
                                </span>
                              ))}
                            </div>
                          )}
                          <Button
                            onClick={() => setSimulating(true)}
                            disabled={!canWrite}
                          >
                            <Activity size={15} />
                            Simulate compromise
                          </Button>
                          <small className="node-id">{selected.id}</small>
                        </aside>
                      ) : (
                        <aside className="node-sidebar empty-sidebar">
                          <div className="node-symbol">
                            <Network size={25} />
                          </div>
                          <h3>Follow the access</h3>
                          <p>
                            Select any identity or asset to inspect its
                            properties and simulate downstream exposure.
                          </p>
                          <div className="sidebar-stat">
                            <span>Confirmed edges</span>
                            <b>{overview?.confirmed_edges || 0}</b>
                          </div>
                          <div className="sidebar-stat">
                            <span>Conditional / declared</span>
                            <b>{overview?.uncertain_edges || 0}</b>
                          </div>
                          <small>
                            Dashed edges represent access that still requires
                            verification.
                          </small>
                        </aside>
                      )}
                    </div>
                    <div className="graph-footer">
                      <Shield size={13} />
                      <span>
                        Directed access paths · Maximum simulation depth: 5 hops
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
                        Collection coverage & evidence ({graph.warnings.length})
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
                  />
                </>
              )}
              {view === "overview" && (
                <>
                  <div className="overview-grid">
                    <div className="panel chart-panel">
                      <div className="panel-heading">
                        <h3>Data sensitivity</h3>
                        <Database size={16} />
                      </div>
                      <p className="muted">
                        Classified data assets across the current snapshot
                      </p>
                      <div style={{ height: 250 }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            data={Object.entries(
                              overview?.sensitivity || {},
                            ).map(([name, value]) => ({ name, value }))}
                          >
                            <XAxis
                              dataKey="name"
                              tick={{ fill: "#8091a8", fontSize: 11 }}
                              axisLine={false}
                              tickLine={false}
                            />
                            <YAxis
                              allowDecimals={false}
                              tick={{ fill: "#8091a8", fontSize: 11 }}
                              axisLine={false}
                              tickLine={false}
                            />
                            <Tooltip
                              contentStyle={{
                                background: "#152030",
                                border: "1px solid #29394d",
                                borderRadius: 8,
                              }}
                              cursor={{ fill: "#1a293c" }}
                            />
                            <Bar
                              dataKey="value"
                              radius={[5, 5, 0, 0]}
                              maxBarSize={48}
                            >
                              {["#7b9cb4", "#81b9ff", "#f6c578", "#f18b94"].map(
                                (c) => (
                                  <Cell key={c} fill={c} />
                                ),
                              )}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                    <div className="panel summary-panel">
                      <h3>Access evidence</h3>
                      <div className="summary-number">
                        <b>{overview?.data_assets || 0}</b>
                        <span>connected data assets</span>
                      </div>
                      <div className="sidebar-stat">
                        <span>Confirmed relationships</span>
                        <b>{overview?.confirmed_edges || 0}</b>
                      </div>
                      <div className="sidebar-stat">
                        <span>Awaiting verification</span>
                        <b>{overview?.uncertain_edges || 0}</b>
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
                        <ArrowRight size={14} />
                      </Button>
                    </div>
                  </div>
                  <Findings
                    findings={findings}
                    graph={graph}
                    onSelect={selectFinding}
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
                    <span className="muted">Latest {events.length} events</span>
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
        <footer className="app-footer">
          <span>ZeroGraph · Identity × Data Intelligence</span>
          <span>Tenant-scoped · Evidence-backed · Review-first</span>
        </footer>
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
            onResult={setSimulation}
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
                <X size={18} />
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
}: {
  findings: Finding[];
  graph: GraphData;
  onSelect: (f: Finding) => void;
}) {
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
        <span className="pill red">{findings.length} findings</span>
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
                  <span
                    className={`pill ${f.severity === "critical" ? "red" : "amber"}`}
                  >
                    <i />
                    {f.severity}
                  </span>
                </td>
                <td>
                  <strong>{f.title}</strong>
                  <div className="path-preview">
                    {f.path.map((id, i) => (
                      <span key={id}>
                        {i > 0 && <ChevronRight size={10} />}
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
                    <ArrowRight size={13} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="empty-line">
          <Shield size={18} />
          {graph.nodes.length
            ? "No exposed sensitive-data paths detected in the current snapshot."
            : "Collect an environment to evaluate toxic access paths."}
        </div>
      )}
    </section>
  );
}
