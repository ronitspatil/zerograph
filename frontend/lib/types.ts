export type NodeType =
  | "HumanUser"
  | "ServiceAccount"
  | "AIAgent"
  | "MCPServer"
  | "CloudRole"
  | "Database"
  | "VectorStore"
  | "S3Bucket"
  | "DataCategory";
export type Sensitivity = "public" | "internal" | "confidential" | "restricted";
export interface GraphNode {
  id: string;
  type: NodeType;
  name: string;
  account_id: string;
  provider: string;
  sensitivity: Sensitivity;
  tags: string[];
  internet_exposed: boolean;
  authenticated: boolean;
  encrypted: boolean;
  privileged: boolean;
  metadata: Record<string, unknown>;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  actions: string[];
  certainty: "confirmed" | "conditional" | "declared";
  evidence: string[];
}
export interface GraphData {
  revision: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  warnings: string[];
}
export interface GraphView extends GraphData {
  view: {
    mode: "sample" | "neighborhood";
    root_id: string | null;
    node_limit: number;
    edge_limit: number;
    truncated: boolean;
    total_nodes: number;
    total_edges: number;
  };
}
export interface RoleSummary {
  role_id: string;
  direct_neighbors: number;
  linked_identities: number;
  linked_data_assets: number;
}
export interface RoleMap extends GraphData {
  role_summaries: RoleSummary[];
  view: Omit<GraphView["view"], "mode"> & {
    mode: "roles";
    total_roles: number;
    total_role_edges: number;
    role_map_truncated: boolean;
    has_more: boolean;
    next_cursor: string | null;
  };
}
export interface GraphSearch {
  revision: string;
  nodes: GraphNode[];
  has_more: boolean;
}
export interface Overview {
  revision: string;
  total_nhis: number;
  ai_agents: number;
  toxic_combinations: number;
  high_blast_radius: number;
  data_assets: number;
  confirmed_edges: number;
  uncertain_edges: number;
  accounts: string[];
  sensitivity: Record<Sensitivity, number>;
}
export interface Finding {
  id: string;
  title: string;
  severity: string;
  source: string;
  target: string;
  path: string[];
  evidence: string[];
  conditional: boolean;
  recommendation: string;
}
export interface Simulation {
  source: string;
  max_hops: number;
  risk_score: number;
  affected_nodes: string[];
  affected_assets: string[];
  highlighted_edges: string[];
  paths: Record<string, string[]>;
  sensitivity_exposure: number;
  centrality: number;
  includes_uncertain: boolean;
  explanation: string;
}
export interface Job {
  id: string;
  source: string;
  status: string;
  error: string | null;
  node_count: number;
  created_at: string;
  updated_at: string;
}
export interface Remediation {
  id: string;
  identity_id: string;
  status: string;
  pr_url: string | null;
  created_at: string;
  removed_actions: string[];
}
export interface Preview {
  id: string;
  identity_id: string;
  optimization: {
    original: Record<string, unknown>;
    optimized: Record<string, unknown>;
    removed_actions: string[];
    retained_reasons: string[];
    diff: string;
    review_required: boolean;
  };
}
export interface AuditEvent {
  id: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  created_at: string;
}
export interface Actor {
  subject: string;
  tenant_id: string;
  roles: string[];
}
/** A structural cluster of the global map. Structure only, never a permission boundary. */
export interface ClusterSummary {
  id: string;
  parent_id: string | null;
  depth: number;
  kind: "community" | "isolated" | "group" | "part" | "range";
  label: string;
  representative_id: string;
  size: number;
  child_count: number;
  member_count: number;
  internal_edges: number;
  boundary_edges: number;
  dominant_type: NodeType | string;
  types: Record<string, number>;
  accounts: Record<string, number>;
}
export interface ClusterLink {
  source: string;
  target: string;
  weight: number;
}
export interface ClusterMap {
  revision: string;
  clusters: ClusterSummary[];
  edges: ClusterLink[];
  warnings: string[];
  view: {
    level: number;
    total_nodes: number;
    total_edges: number;
    total_clusters: number;
    clusters: number;
    shown_clusters: number;
    links: number;
    shown_links: number;
    edge_limit: number;
    isolated_nodes: number;
    truncated: boolean;
    notice: string;
  };
}
export interface ClusterDetail {
  revision: string;
  cluster: ClusterSummary;
  path: { id: string; label: string; size: number }[];
  children: ClusterSummary[];
  edges: ClusterLink[];
  nodes: GraphNode[];
  node_edges: GraphEdge[];
  boundary_edges: Record<string, number>;
  warnings: string[];
  view: {
    mode: "clusters" | "members";
    total_children: number;
    shown_children: number;
    total_links: number;
    shown_links: number;
    total_members: number;
    shown_members: number;
    member_limit: number;
    total_member_edges: number;
    shown_member_edges: number;
    edge_limit: number;
    truncated: boolean;
    notice: string;
  };
}
/** Every member of one cluster, shown in place on the global map. */
export interface ClusterMembers {
  revision: string;
  cluster: ClusterSummary;
  nodes: GraphNode[];
  /** Relationships among these members and to members already on screen. */
  edges: GraphEdge[];
  /** Each member's relationship count in the whole revision. */
  degrees: Record<string, number>;
  warnings: string[];
  view: {
    total_members: number;
    shown_members: number;
    member_limit: number;
    visible_members: number;
    visible_limit: number;
    shown_edges: number;
    edge_limit: number;
    truncated: boolean;
    notice: string;
  };
}
