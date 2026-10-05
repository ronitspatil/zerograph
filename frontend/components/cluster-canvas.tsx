"use client";
import { useEffect, useRef } from "react";
import cytoscape, { type Core, type StylesheetCSS } from "cytoscape";
import { Maximize2, Minus, Plus } from "lucide-react";
import {
  clusterDiameter,
  clusterLabelBox,
  clusterLayoutInput,
  labelBudget,
  clusterPositions,
  linkWidth,
} from "@/lib/cluster-layout";
import { fitViewport, labelFontSize, spacedLabels } from "@/lib/graph-layout";
import { nodeColors } from "@/components/graph-canvas";
import type { ClusterLink, ClusterSummary } from "@/lib/types";

const FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

/** Sized super-nodes (one per cluster) with weighted links; tap opens a cluster. */
export function ClusterCanvas({
  clusters,
  links,
  selected,
  onOpen,
  onHover,
}: {
  clusters: ClusterSummary[];
  links: ClusterLink[];
  selected: string | null;
  onOpen: (cluster: ClusterSummary) => void;
  onHover?: (cluster: ClusterSummary | null) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const fitView = useRef<() => void>(() => {});
  const open = useRef(onOpen);
  open.current = onOpen;
  const hover = useRef(onHover);
  hover.current = onHover;
  const input = clusterLayoutInput(clusters, links);
  useEffect(() => {
    if (!container.current || !input) return;
    const largest = Math.max(1, ...input.clusters.map((c) => c.size));
    const heaviest = Math.max(1, ...input.links.map((l) => l.weight));
    const positions = clusterPositions(input.clusters, input.links);
    const style: StylesheetCSS[] = [
      {
        selector: "node",
        css: {
          shape: "ellipse",
          width: "data(diameter)",
          height: "data(diameter)",
          "background-color": "data(color)",
          "background-opacity": 0.82,
          "border-width": 1,
          "border-color": "#0a101b",
          label: "",
          color: "#cbd5e1",
          "font-family": FONT,
          "text-valign": "bottom",
          "text-wrap": "ellipsis",
          "overlay-opacity": 0,
        },
      },
      {
        // Largest clusters claim label space first; labels may cross circles
        // (on a backdrop) but never each other.
        selector: "node.label-on",
        css: {
          label: "data(label)",
          "text-background-color": "#0d1522",
          "text-background-opacity": 0.92,
          "text-background-shape": "roundrectangle",
        },
      },
      {
        selector: "node.selected, node.hovered",
        css: {
          "border-width": 2,
          "border-color": "#f5faff",
          "background-opacity": 1,
        },
      },
      {
        selector: "edge",
        css: {
          width: "data(width)",
          opacity: 0.32,
          "line-color": "#637b91",
          "curve-style": "straight",
          "target-arrow-shape": "none",
        },
      },
      {
        selector: "edge.hovered",
        css: { opacity: 0.85, "line-color": "#b7c7d8" },
      },
    ];
    const instance = cytoscape({
      container: container.current,
      elements: [
        ...input.clusters.map((c, i) => ({
          data: {
            id: c.id,
            label: `${c.label} · ${c.size.toLocaleString("en-US")}`,
            color: nodeColors[c.dominant_type] ?? "#73849a",
            diameter: clusterDiameter(c.size, largest),
            size: c.size,
          },
          position: { x: positions[i].x, y: positions[i].y },
        })),
        ...input.links.map((l) => ({
          data: {
            id: `${l.source}~${l.target}`,
            source: l.source,
            target: l.target,
            width: linkWidth(l.weight, heaviest),
          },
        })),
      ],
      style,
      layout: { name: "preset", fit: false },
      minZoom: 0.05,
      maxZoom: 3,
      wheelSensitivity: 0.2,
    });
    cy.current = instance;
    const fit = () => {
      instance.viewport(
        fitViewport(
          instance.nodes().boundingBox({ includeLabels: false }),
          instance.width(),
          instance.height(),
          instance.minZoom(),
        ),
      );
    };
    fitView.current = fit;
    let fitted = 1;
    // Largest clusters claim label space first.
    const order = [...input.clusters]
      .sort((a, b) => b.size - a.size || a.id.localeCompare(b.id))
      .map((c) => c.id);
    let hovered: string | null = null;
    const labels = () => {
      if (instance.destroyed()) return;
      const zoom = instance.zoom();
      instance.batch(() => {
        instance.nodes().style({
          "font-size": labelFontSize(12, zoom),
          "text-max-width": `${170 / zoom}px`,
          "text-margin-y": 5 / zoom,
          "text-background-padding": `${2 / zoom}px`,
        });
        instance.nodes().addClass("label-on");
      });
      const required = new Set(
        [hovered, selected].filter((id): id is string => !!id),
      );
      // Estimated label boxes (12px text under the circle, ellipsis at 170px):
      // independent of when the renderer measures newly styled labels.
      const boxes = order.slice(0, labelBudget(zoom / fitted)).map((id) => {
        const node = instance.getElementById(id);
        const { x, y } = node.renderedPosition();
        return clusterLabelBox(
          id,
          node.data("label"),
          x,
          y,
          node.renderedWidth(),
        );
      });
      for (const id of required)
        if (!boxes.some((box) => box.id === id)) {
          const node = instance.getElementById(id);
          const { x, y } = node.renderedPosition();
          boxes.push(
            clusterLabelBox(id, node.data("label"), x, y, node.renderedWidth()),
          );
        }
      const visible = spacedLabels(boxes, instance.width(), instance.height(), {
        required,
      });
      instance.batch(() => {
        for (const id of order)
          if (!visible.has(id) && !required.has(id))
            instance.getElementById(id).removeClass("label-on");
      });
    };
    let frame = 0;
    const schedule = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        labels();
      });
    };
    fit();
    fitted = instance.zoom();
    labels();
    instance.on("pan zoom", schedule);
    instance.on("mouseover", "node", (event) => {
      hovered = event.target.id();
      event.target.addClass("hovered");
      event.target.connectedEdges().addClass("hovered");
      hover.current?.(clusters.find((c) => c.id === hovered) ?? null);
      labels();
    });
    instance.on("mouseout", "node", (event) => {
      hovered = null;
      event.target.removeClass("hovered");
      event.target.connectedEdges().removeClass("hovered");
      hover.current?.(null);
      labels();
    });
    instance.on("tap", "node", (event) => {
      const cluster = clusters.find((c) => c.id === event.target.id());
      if (cluster) open.current(cluster);
    });
    instance.getElementById(selected ?? "").addClass("selected");
    const observer = new ResizeObserver(() => {
      if (instance.destroyed()) return;
      instance.resize();
      schedule();
    });
    observer.observe(container.current);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      instance.destroy();
      cy.current = null;
    };
    // The element set is rebuilt only when the clusters or links change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusters, links]);
  useEffect(() => {
    const instance = cy.current;
    if (!instance) return;
    instance.nodes().removeClass("selected");
    if (selected) instance.getElementById(selected).addClass("selected");
  }, [selected]);
  function zoom(factor: number) {
    const c = cy.current;
    if (c)
      c.zoom({
        level: c.zoom() * factor,
        renderedPosition: { x: c.width() / 2, y: c.height() / 2 },
      });
  }
  if (!input)
    return (
      <div role="alert" className="empty-line">
        This map level exceeds visualization bounds. Reload the global map.
      </div>
    );
  return (
    <div className="canvas-wrap">
      <div
        ref={container}
        className="graph-canvas"
        role="img"
        aria-label={`Global map with ${clusters.length} clusters. Use the cluster list to open one with the keyboard.`}
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
        <span>Circle area: entities</span>
        <span>Color: most common type</span>
        <span>Line width: relationships between clusters</span>
      </div>
    </div>
  );
}
