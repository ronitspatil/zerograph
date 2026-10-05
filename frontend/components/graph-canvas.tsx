"use client";
import { useEffect, useRef } from "react";
import type { Core, StylesheetCSS } from "cytoscape";
import { Maximize2, Minus, Plus } from "lucide-react";
import {
  circlePositions,
  fitViewport,
  labelCandidates,
  labelFontSize,
  layoutInput,
  startLayout,
  overviewAnchors,
  spacedLabels,
} from "@/lib/graph-layout";
import { createGraph, WEBGL_MIN_NODES } from "@/lib/renderer";
import type { GraphData, GraphNode, Simulation } from "@/lib/types";

export const nodeColors: Record<string, string> = {
  HumanUser: "#94a3b8",
  ServiceAccount: "#73b2f8",
  AIAgent: "#8ee8d0",
  MCPServer: "#be9aff",
  CloudRole: "#f8ca78",
  Database: "#e391bb",
  VectorStore: "#e391bb",
  S3Bucket: "#e391bb",
  DataCategory: "#73849a",
};
export function GraphCanvas({
  graph,
  selected,
  riskNodes,
  simulation,
  onSelect,
}: {
  graph: GraphData & { view?: { mode: "sample" | "neighborhood" | "roles" } };
  selected: string | null;
  riskNodes: Set<string>;
  simulation: Simulation | null;
  onSelect: (node: GraphNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const applyFocus = useRef<() => void>(() => {});
  const fitView = useRef<() => void>(() => {});
  const callback = useRef(onSelect);
  callback.current = onSelect;
  useEffect(() => {
    if (!container.current) return;
    const input = layoutInput(graph);
    if (!input) return;
    const positions = circlePositions(input.nodes);
    const anchors = overviewAnchors(graph);
    const style: StylesheetCSS[] = [
      {
        selector: "node",
        css: {
          shape: "ellipse",
          width: 8,
          height: 8,
          "background-color": "data(color)",
          "background-opacity": 1,
          "border-width": 0,
          label: "",
          color: "#cbd5e1",
          "font-size": 11,
          "font-family":
            '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
          "text-valign": "bottom",
          "text-events": "yes",
          "text-margin-y": 5,
          "text-wrap": "ellipsis",
          "text-max-width": "140px",
          "overlay-opacity": 0,
        },
      },
      {
        selector: "node[type='CloudRole']",
        css: { width: 10, height: 10 },
      },
      { selector: "node.label-on", css: { label: "data(label)" } },
      {
        selector: "edge",
        css: {
          width: 0.55,
          opacity: 0.25,
          "line-color": "#637b91",
          "target-arrow-shape": "none",
          "curve-style": "straight",
          label: "",
        },
      },
      {
        selector: "edge[certainty!='confirmed']",
        css: { "line-style": "dashed" },
      },
      { selector: ".focus-muted", css: { opacity: 0.13 } },
      {
        selector: "node.focus-neighbor",
        css: {
          opacity: 1,
          "text-background-color": "#0d1522",
          "text-background-opacity": 0.85,
          "text-background-padding": "3px",
        },
      },
      {
        selector: "node.focus-root",
        css: {
          opacity: 1,
          color: "#f5faff",
          "border-width": 2,
          "border-color": "#f5faff",
          "text-background-color": "#0d1522",
          "text-background-opacity": 0.85,
          "text-background-padding": "3px",
        },
      },
      {
        selector: "edge.focus-neighbor",
        css: {
          width: 1.1,
          opacity: 0.9,
          "line-color": "#b7c7d8",
          "target-arrow-color": "#b7c7d8",
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.6,
          label: "",
          color: "#cbd5e1",
          "font-size": 9,
          "text-rotation": "autorotate",
          "text-background-color": "#0d1522",
          "text-background-opacity": 0.95,
          "text-background-padding": "3px",
        },
      },
      {
        selector: "edge.edge-detail",
        css: {
          label: "data(label)",
          opacity: 1,
          width: 1.4,
          "target-arrow-shape": "triangle",
          "target-arrow-color": "#cbd5e1",
          color: "#cbd5e1",
          "font-size": 10,
          "text-background-color": "#0d1522",
          "text-background-opacity": 1,
          "text-background-padding": "3px",
        },
      },
      {
        selector: ".risk",
        css: { "border-color": "#f28b91", "border-width": 2 },
      },
      {
        selector: ".selected",
        css: { "border-color": "#f5faff", "border-width": 2 },
      },
      {
        selector: ".affected",
        css: {
          "border-color": "#f9a66c",
          "border-width": 2,
          "background-color": "#f9a66c",
          opacity: 1,
        },
      },
      {
        selector: "edge.affected",
        css: {
          "line-color": "#f9a66c",
          "target-arrow-color": "#f9a66c",
          "target-arrow-shape": "triangle",
          opacity: 1,
          width: 1.4,
        },
      },
      { selector: ".dimmed", css: { opacity: 0.16 } },
    ];
    // Detail views (at most 500 nodes) keep the canvas renderer for the sharpest labels.
    cy.current = createGraph(
      {
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
        layout: { name: "preset", fit: false },
        minZoom: 0.05,
        maxZoom: 2.5,
        wheelSensitivity: 0.2,
      },
      graph.nodes.length > WEBGL_MIN_NODES,
    ).cy;
    const instance = cy.current;
    let programmatic = false;
    function fitGraph() {
      const view = fitViewport(
        instance.nodes().boundingBox({ includeLabels: false }),
        instance.width(),
        instance.height(),
        instance.minZoom(),
      );
      programmatic = true;
      instance.viewport(view);
      programmatic = false;
    }
    fitView.current = fitGraph;
    fitGraph();
    let userMoved = false;
    instance.on("pan zoom", () => {
      if (!programmatic) userMoved = true;
    });
    const stopLayout = startLayout(input, (positions) => {
      if (cy.current !== instance || instance.destroyed()) return;
      instance.batch(() => {
        for (const p of positions)
          instance.getElementById(p.id).position({ x: p.x, y: p.y });
      });
      if (!userMoved) fitGraph();
      labelSizing();
    });
    let hovered: string | null = null;
    function labelSizing() {
      if (instance.destroyed()) return;
      const zoom = instance.zoom();
      const narrow = instance.width() < 700;
      const root = hovered || selectedRef.current;
      const rootNode = root ? instance.getElementById(root) : null;
      const focused = rootNode && rootNode.nonempty() ? root : null;
      const { order, required } = labelCandidates(graph, anchors, {
        zoom,
        focus: focused,
        neighbors: focused
          ? rootNode!.neighborhood("node").map((n) => n.id())
          : [],
      });
      instance.batch(() => {
        // Labels keep one screen size at every zoom, in step with the UI type scale.
        instance.nodes().style({
          "font-size": labelFontSize(11, zoom),
          "text-max-width": `${(narrow ? 130 : 140) / zoom}px`,
          "text-margin-y": 5 / zoom,
          "text-background-padding": "0px",
        });
        // Only focused labels draw a backdrop, so only they need padding.
        instance
          .nodes(".focus-root, .focus-neighbor")
          .style({ "text-background-padding": `${3 / zoom}px` });
        instance.nodes(".focus-root").style({
          "font-size": labelFontSize(12, zoom),
          "text-max-width": `${(narrow ? 150 : 180) / zoom}px`,
        });
        instance
          .edges(".edge-detail")
          .style({ "font-size": labelFontSize(10, zoom) });
        instance.nodes().removeClass("label-on");
        for (const id of order)
          instance.getElementById(id).addClass("label-on");
      });
      if (!order.length) return;
      const labels = order.map((id) => ({
        id,
        ...instance.getElementById(id).renderedBoundingBox({
          includeNodes: false,
          includeEdges: false,
          includeLabels: true,
        }),
      }));
      // A label may graze a dot's rim but must not cover its core.
      const obstacles = instance.nodes().map((n) => {
        const { x, y } = n.renderedPosition();
        const r = n.renderedWidth() / 4;
        return { id: n.id(), x1: x - r, y1: y - r, x2: x + r, y2: y + r };
      });
      const visible = spacedLabels(
        labels,
        instance.width(),
        instance.height(),
        { required, obstacles },
      );
      instance.batch(() => {
        for (const id of order)
          if (!visible.has(id))
            instance.getElementById(id).removeClass("label-on");
      });
    }
    let frame = 0;
    const scheduleLabels = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        if (cy.current === instance) labelSizing();
      });
    };
    const focus = () => {
      instance.elements().removeClass("focus-root focus-neighbor focus-muted");
      const id = hovered || selectedRef.current;
      if (!id) {
        labelSizing();
        return;
      }
      const root = instance.getElementById(id);
      if (root.empty()) return;
      const neighborhood = root.closedNeighborhood();
      instance.elements().difference(neighborhood).addClass("focus-muted");
      neighborhood.addClass("focus-neighbor");
      root.removeClass("focus-neighbor").addClass("focus-root");
      labelSizing();
    };
    applyFocus.current = focus;
    instance.on("mouseover", "edge", (event) => {
      event.target.addClass("edge-detail");
      instance
        .edges(".edge-detail")
        .style({ "font-size": labelFontSize(10, instance.zoom()) });
    });
    instance.on("mouseout", "edge", (event) =>
      event.target.removeClass("edge-detail"),
    );
    instance.on("mouseover", "node", (event) => {
      hovered = event.target.id();
      focus();
    });
    instance.on("mouseout", "node", () => {
      hovered = null;
      focus();
    });
    cy.current.on("pan zoom", scheduleLabels);
    focus();
    cy.current.on("tap", "node", (event) => {
      const node = graph.nodes.find((n) => n.id === event.target.id());
      if (node) callback.current(node);
    });
    const observer = new ResizeObserver(() => {
      if (cy.current !== instance || instance.destroyed()) return;
      instance.resize();
      scheduleLabels();
    });
    observer.observe(container.current);
    return () => {
      cancelAnimationFrame(frame);
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
    applyFocus.current();
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
      <div role="alert" className="empty-line">
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
      <div className="graph-controls">
        <button aria-label="Zoom in" onClick={() => zoom(1.2)}>
          <Plus size={14} />
        </button>
        <button aria-label="Zoom out" onClick={() => zoom(0.8)}>
          <Minus size={14} />
        </button>
        <button aria-label="Fit graph" onClick={() => fitView.current()}>
          <Maximize2 size={13} />
        </button>
      </div>
      <div className="graph-legend" aria-label="Legend">
        <span>
          <i className="legend-service-account" />
          Service account
        </span>
        <span>
          <i className="legend-ai-agent" />
          AI agent
        </span>
        <span>
          <i className="legend-mcp-server" />
          MCP server
        </span>
        <span>
          <i className="legend-cloud-role" />
          Cloud role
        </span>
        <span>
          <i className="legend-data-asset" />
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
