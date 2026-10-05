"use client";
import { useEffect, useRef } from "react";
import cytoscape, { type Core, type StylesheetCSS } from "cytoscape";
import { Maximize2, Minus, Plus } from "lucide-react";
import {
  circleObstacle,
  clusterDiameter,
  clusterLabelBox,
  clusterLayoutInput,
  estimateLabelWidth,
  fitClusters,
  LABEL_FONT_PX,
  LABEL_MAX_WIDTH,
  labelBudget,
  clusterPositions,
  linkWidth,
  maxCircleDiameter,
  placeLabels,
} from "@/lib/cluster-layout";
import { nodeColors } from "@/components/graph-canvas";
import type { ClusterLink, ClusterSummary } from "@/lib/types";

const FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

let measureContext: CanvasRenderingContext2D | null | undefined;
/** Rendered width of a 12px label, measured once per label; estimated without a canvas. */
function labelWidth(label: string): number {
  if (measureContext === undefined) {
    try {
      measureContext = document.createElement("canvas").getContext("2d");
      if (measureContext) measureContext.font = `${LABEL_FONT_PX}px ${FONT}`;
    } catch {
      measureContext = null;
    }
  }
  if (!measureContext) return estimateLabelWidth(label);
  return Math.min(LABEL_MAX_WIDTH, measureContext.measureText(label).width);
}

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
          "z-index": 1,
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
          // Labeled clusters draw above unlabeled dots, so no dot crosses a label.
          "z-index": 2,
        },
      },
      {
        selector: "node.label-above",
        css: { "text-valign": "top" },
      },
      {
        selector: "node.selected, node.hovered",
        css: {
          "border-width": 2,
          "border-color": "#f5faff",
          "background-opacity": 1,
          "z-index": 3,
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
    // Largest clusters claim label space first.
    const order = [...input.clusters]
      .sort((a, b) => b.size - a.size || a.id.localeCompare(b.id))
      .map((c) => c.id);
    const widths = new Map(
      input.clusters.map((c) => [
        c.id,
        labelWidth(instance.getElementById(c.id).data("label")),
      ]),
    );
    const legend = container.current.parentElement?.querySelector(
      ".graph-legend",
    ) as HTMLElement | null;
    const fit = () => {
      const width = instance.width();
      const height = instance.height();
      const largestModel = clusterDiameter(largest, largest);
      // The labels shown at the fitted view (the largest clusters) must not be clipped.
      const reserved = new Set(order.slice(0, labelBudget(1)));
      const narrow = width < 520;
      instance.viewport(
        fitClusters(
          input.clusters.map((c, i) => ({
            x: positions[i].x,
            y: positions[i].y,
            r: clusterDiameter(c.size, largest) / 2,
            label: reserved.has(c.id) ? (widths.get(c.id) ?? 0) + 6 : 0,
          })),
          width,
          height,
          {
            top: 16,
            left: 16,
            // The zoom controls sit on the right; the legend along the bottom.
            right: narrow ? 16 : 56,
            bottom: (legend?.offsetHeight ?? 24) + 24,
          },
          {
            minZoom: instance.minZoom(),
            maxZoom: Math.min(
              instance.maxZoom(),
              maxCircleDiameter(input.clusters.length, width, height) /
                largestModel,
            ),
          },
        ),
      );
    };
    fitView.current = fit;
    let fitted = 1;
    let hovered: string | null = null;
    const labels = () => {
      if (instance.destroyed()) return;
      const zoom = instance.zoom();
      instance.batch(() => {
        // Fixed screen size at every zoom.
        instance.nodes().style({
          "font-size": LABEL_FONT_PX / zoom,
          "text-max-width": `${LABEL_MAX_WIDTH / zoom}px`,
          "text-background-padding": `${2 / zoom}px`,
        });
        instance.nodes().addClass("label-on");
      });
      const required = new Set(
        [hovered, selected].filter((id): id is string => !!id),
      );
      const candidate = (id: string) => {
        const node = instance.getElementById(id);
        const { x, y } = node.renderedPosition();
        const width = widths.get(id) ?? 0;
        const diameter = node.renderedWidth();
        return {
          id,
          below: clusterLabelBox(id, width, x, y, diameter, "below"),
          above: clusterLabelBox(id, width, x, y, diameter, "above"),
        };
      };
      const candidates = order
        .slice(0, labelBudget(zoom / fitted))
        .map(candidate);
      for (const id of required)
        if (!candidates.some((c) => c.id === id))
          candidates.push(candidate(id));
      // A label never covers another sizeable circle; small dots draw beneath it.
      const obstacles = order.flatMap((id) => {
        const node = instance.getElementById(id);
        const { x, y } = node.renderedPosition();
        const obstacle = circleObstacle(id, x, y, node.renderedWidth());
        return obstacle ? [obstacle] : [];
      });
      const placed = placeLabels(
        candidates,
        instance.width(),
        instance.height(),
        { required, obstacles },
      );
      instance.batch(() => {
        for (const id of order) {
          const node = instance.getElementById(id);
          const side = placed.get(id);
          if (!side) node.removeClass("label-on label-above");
          else {
            node.toggleClass("label-above", side === "above");
            node.style("text-margin-y", (side === "above" ? -5 : 5) / zoom);
          }
        }
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
