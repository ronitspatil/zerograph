import { describe, expect, it } from "vitest";
import { nodeColors } from "@/components/graph-canvas";
import { labelPriority } from "@/lib/graph-layout";
import type { GraphData, GraphNode, NodeType } from "@/lib/types";

const node = (
  id: string,
  type: NodeType,
  sensitivity: GraphNode["sensitivity"] = "internal",
): GraphNode => ({
  id,
  name: id,
  type,
  account_id: "123456789012",
  provider: "aws",
  sensitivity,
  tags: [],
  internet_exposed: false,
  authenticated: true,
  encrypted: true,
  privileged: false,
  metadata: {},
});

describe("data lake node types", () => {
  it("draws Glue tables as data assets and workgroups apart from them", () => {
    expect(nodeColors.DataTable).toBe(nodeColors.S3Bucket);
    expect(nodeColors.QueryWorkgroup).toBeDefined();
    expect(nodeColors.QueryWorkgroup).not.toBe(nodeColors.S3Bucket);
  });

  it("boosts sensitive tables' labels like other data stores, not workgroups", () => {
    const graph: GraphData = {
      revision: "r",
      nodes: [
        node("table", "DataTable", "confidential"),
        node("bucket", "S3Bucket", "confidential"),
        node("workgroup", "QueryWorkgroup", "confidential"),
      ],
      edges: [],
      warnings: [],
    };
    const priority = labelPriority(graph);
    expect(priority.get("table")).toBe(priority.get("bucket"));
    expect(priority.get("workgroup")).toBeLessThan(priority.get("table")!);
  });
});
