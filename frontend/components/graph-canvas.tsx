"use client";
import { useEffect, useRef } from "react";
import cytoscape, { type Core, type StylesheetCSS } from "cytoscape";
import { Maximize2, Minus, Plus } from "lucide-react";
import { circlePositions, layoutInput, startLayout } from "@/lib/graph-layout";
import type { GraphData, GraphNode, Simulation } from "@/lib/types";

export const nodeColors: Record<string, string> = {
  HumanUser: "#94a3b8",
  ServiceAccount: "#82a9ff",
  AIAgent: "#8ee8d0",
  MCPServer: "#be9aff",
  CloudRole: "#f8ca78",
  Database: "#81b9ff",
  VectorStore: "#81b9ff",
  S3Bucket: "#81b9ff",
  DataCategory: "#73849a",
};
export function GraphCanvas({
  graph,
  selected,
  riskNodes,
  simulation,
  onSelect,
}: {
  graph: GraphData;
  selected: string | null;
  riskNodes: Set<string>;
  simulation: Simulation | null;
  onSelect: (node: GraphNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const callback = useRef(onSelect);
  callback.current = onSelect;
  useEffect(() => {
    if (!container.current) return;
    const input = layoutInput(graph);
    if (!input) return;
    const positions = circlePositions(input.nodes);
    const style: StylesheetCSS[] = [
      {
        selector: "node",
        css: {
          "background-color": "data(color)",
          "background-opacity": 0.16,
          "border-color": "data(color)",
          "border-width": 1.5,
          width: 38,
          height: 38,
          label: "data(label)",
          color: "#cbd5e1",
          "font-size": 11,
          "font-family": "Arial",
          "text-valign": "bottom",
          "text-margin-y": 13,
          "text-wrap": "wrap",
          "text-max-width": "130px",
          "overlay-opacity": 0,
        },
      },
      {
        selector: "node[type='AIAgent']",
        css: { shape: "hexagon", width: 48, height: 48 },
      },
      {
        selector: "node[type='CloudRole']",
        css: { shape: "diamond", width: 44, height: 44 },
      },
      {
        selector:
          "node[type='Database'], node[type='VectorStore'], node[type='S3Bucket']",
        css: { shape: "round-rectangle", width: 44, height: 36 },
      },
      {
        selector: "edge",
        css: {
          width: 1.3,
          "line-color": "#34465b",
          "target-arrow-color": "#34465b",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          color: "#62758c",
          "font-size": 7,
          "text-background-color": "#0d1522",
          "text-background-opacity": 1,
          "text-background-padding": "3px",
          "text-rotation": "autorotate",
          "arrow-scale": 0.7,
        },
      },
      {
        selector: "edge[certainty!='confirmed']",
        css: { "line-style": "dashed" },
      },
      {
        selector: ".risk",
        css: { "border-color": "#f28b91", "border-width": 2.5 },
      },
      {
        selector: ".selected",
        css: {
          "border-color": "#f5faff",
          "border-width": 3,
          "background-opacity": 0.4,
        },
      },
      {
        selector: ".affected",
        css: {
          "border-color": "#f9a66c",
          "background-color": "#f9a66c",
          "background-opacity": 0.35,
        },
      },
      {
        selector: "edge.affected",
        css: {
          "line-color": "#f9a66c",
          "target-arrow-color": "#f9a66c",
          width: 2.7,
        },
      },
      { selector: ".dimmed", css: { opacity: 0.22 } },
      { selector: "node.overview", css: { label: "" } },
      { selector: "edge.overview", css: { label: "" } },
    ];
    cy.current = cytoscape({
      container: container.current,
      elements: [
        ...graph.nodes.map((n, i) => ({
          data: {
            id: n.id,
            label: n.name,
            color: nodeColors[n.type],
            type: n.type,
          },
          position: { x: positions[i].x, y: positions[i].y },
        })),
        ...graph.edges.map((e) => ({
          data: { ...e, label: e.type.replaceAll("_", " ").toLowerCase() },
        })),
      ],
      style,
      layout: { name: "preset", fit: true, padding: 55 },
      minZoom: 0.05,
      maxZoom: 2.5,
      wheelSensitivity: 0.2,
    });
    const instance = cy.current;
    let userMoved = false;
    instance.on("pan zoom", () => {
      userMoved = true;
    });
    const stopLayout = startLayout(input, (positions) => {
      if (cy.current !== instance || instance.destroyed()) return;
      instance.batch(() => {
        for (const p of positions)
          instance.getElementById(p.id).position({ x: p.x, y: p.y });
      });
      if (!userMoved) instance.fit(undefined, 55);
    });
    const detail = () => {
      const instance = cy.current;
      if (!instance) return;
      instance.nodes().toggleClass("overview", instance.zoom() < 0.65);
      instance
        .edges()
        .toggleClass(
          "overview",
          instance.zoom() < 1.1 || graph.edges.length > 250,
        );
    };
    cy.current.on("zoom", detail);
    detail();
    cy.current.on("tap", "node", (event) => {
      const node = graph.nodes.find((n) => n.id === event.target.id());
      if (node) callback.current(node);
    });
    const observer = new ResizeObserver(() => cy.current?.resize());
    observer.observe(container.current);
    return () => {
      stopLayout();
      observer.disconnect();
      cy.current?.destroy();
      cy.current = null;
    };
  }, [graph]);
  useEffect(() => {
    const instance = cy.current;
    if (!instance) return;
    instance.elements().removeClass("selected risk affected dimmed");
    instance.nodes().forEach((n) => {
      if (riskNodes.has(n.id())) n.addClass("risk");
      if (n.id() === selected) n.addClass("selected");
    });
    if (simulation) {
      const affected = new Set([
        simulation.source,
        ...simulation.affected_nodes,
      ]);
      instance.nodes().forEach((n) => {
        n.addClass(affected.has(n.id()) ? "affected" : "dimmed");
      });
      const edges = new Set(simulation.highlighted_edges);
      instance.edges().forEach((e) => {
        e.addClass(edges.has(e.id()) ? "affected" : "dimmed");
      });
    }
  }, [selected, riskNodes, simulation, graph]);
  function zoom(factor: number) {
    const c = cy.current;
    if (c)
      c.zoom({
        level: c.zoom() * factor,
        renderedPosition: { x: c.width() / 2, y: c.height() / 2 },
      });
  }
  if (!layoutInput(graph))
    return (
      <div role="alert">
        This view exceeds visualization bounds or contains invalid endpoints.
        Reset to a bounded view.
      </div>
    );
  return (
    <div className="canvas-wrap">
      <div
        ref={container}
        className="graph-canvas"
        role="img"
        aria-label={`Identity and data graph with ${graph.nodes.length} nodes. Use the identity list to select a node with the keyboard.`}
      />
      <div className="canvas-labels">
        <span>CONNECTED VIEW · ZOOM IN FOR LABELS</span>
      </div>
      <div className="graph-controls">
        <button aria-label="Zoom in" onClick={() => zoom(1.2)}>
          <Plus size={15} />
        </button>
        <button aria-label="Zoom out" onClick={() => zoom(0.8)}>
          <Minus size={15} />
        </button>
        <button
          aria-label="Fit graph"
          onClick={() => cy.current?.fit(undefined, 55)}
        >
          <Maximize2 size={14} />
        </button>
      </div>
      <div className="graph-legend">
        <span>
          <i style={{ background: nodeColors.AIAgent }} />
          AI agent
        </span>
        <span>
          <i style={{ background: nodeColors.MCPServer }} />
          MCP server
        </span>
        <span>
          <i style={{ background: nodeColors.CloudRole }} />
          Cloud role
        </span>
        <span>
          <i style={{ background: nodeColors.Database }} />
          Data asset
        </span>
        <span>
          <i className="risk-dot" />
          Risk path
        </span>
      </div>
    </div>
  );
}
