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
