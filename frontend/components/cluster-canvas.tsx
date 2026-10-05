"use client";
import { useEffect, useRef, useState } from "react";
import type { Core, ElementDefinition, StylesheetCSS } from "cytoscape";
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
  makeRoom,
  maxCircleDiameter,
  MEMBER_DOT,
  MEMBER_SPACING,
  placeInDisc,
  placeLabels,
} from "@/lib/cluster-layout";
import { packedPositions } from "@/lib/graph-layout-engine";
import {
  MEMBER_LIMITS,
  startLayout,
  type LayoutInput,
  type Position,
} from "@/lib/graph-layout";
import {
  createGraph,
  prefersReducedMotion,
  type RendererKind,
} from "@/lib/renderer";
import { nodeColors } from "@/components/graph-canvas";
import type {
  ClusterLink,
  ClusterSummary,
  GraphEdge,
  GraphNode,
} from "@/lib/types";

const FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

let measureContext: CanvasRenderingContext2D | null | undefined;
const measured = new Map<string, number>();
/** Rendered width of a 12px label, measured once per label; estimated without a canvas. */
function labelWidth(label: string): number {
  const known = measured.get(label);
  if (known !== undefined) return known;
  if (measureContext === undefined) {
    try {
      measureContext = document.createElement("canvas").getContext("2d");
      if (measureContext) measureContext.font = `${LABEL_FONT_PX}px ${FONT}`;
    } catch {
      measureContext = null;
    }
  }
  const width = measureContext
    ? Math.min(LABEL_MAX_WIDTH, measureContext.measureText(label).width)
    : estimateLabelWidth(label);
  if (measured.size > 20000) measured.clear();
  measured.set(label, width);
  return width;
}

/**
 * Label font sizes follow the zoom in steps of 1/16 octave (about 4%), so the
 * WebGL label textures are reused while zooming instead of redrawn every frame.
 */
function labelZoom(zoom: number): number {
  return 2 ** (Math.round(Math.log2(zoom) * 16) / 16);
}

/** On-screen spacing (px) between packed members above which their labels are offered. */
const MEMBER_LABEL_SPACING = 9;
/** Member labels offered per frame (highest degree on screen first). */
const MEMBER_LABEL_CANDIDATES = 80;

/** One cluster shown as its members, in place of its circle. */
export interface MapExpansion {
  cluster: ClusterSummary;
  nodes: GraphNode[];
  /** Relationships among these members and to members expanded before them. */
  edges: GraphEdge[];
  degrees: Record<string, number>;
}

interface Shown {
  members: Set<string>;
  radius: number;
  cancel: () => void;
}

/**
 * The global map: sized super-nodes (one per cluster) with weighted links, and
 * clusters expanded in place into their members (up to 5,000 on screen). Uses
 * Cytoscape's WebGL renderer when the browser supports it and falls back to the
 * canvas renderer. Tapping a circle calls `onOpen`; tapping a member, `onSelect`.
 */
export function ClusterCanvas({
  clusters,
  links,
  expansions = [],
  selected,
  onOpen,
  onHover,
  onSelect,
}: {
  clusters: ClusterSummary[];
  links: ClusterLink[];
  expansions?: MapExpansion[];
  selected: string | null;
  onOpen: (cluster: ClusterSummary) => void;
  onHover?: (cluster: ClusterSummary | null) => void;
  onSelect?: (member: GraphNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const fitView = useRef<() => void>(() => {});
  const sync = useRef<(list: MapExpansion[]) => void>(() => {});
  const relabel = useRef<() => void>(() => {});
  const open = useRef(onOpen);
  open.current = onOpen;
  const hover = useRef(onHover);
  hover.current = onHover;
  const pick = useRef(onSelect);
  pick.current = onSelect;
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const expansionsRef = useRef(expansions);
  expansionsRef.current = expansions;
  const [renderer, setRenderer] = useState<RendererKind | null>(null);
  const [shownMembers, setShownMembers] = useState(0);
  const input = clusterLayoutInput(clusters, links);
  useEffect(() => {
    if (!container.current || !input) return;
    const largest = Math.max(1, ...input.clusters.map((c) => c.size));
    const heaviest = Math.max(1, ...input.links.map((l) => l.weight));
    const positions = clusterPositions(input.clusters, input.links);
    const byId = new Map(input.clusters.map((c) => [c.id, c]));
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
        // An expanded cluster becomes a faint disc behind its members.
        selector: "node.expanded",
        css: {
          "background-opacity": 0.07,
          "border-width": 1.2,
          "border-color": "data(color)",
          "border-opacity": 0.5,
          events: "no",
          "z-index": 0,
        },
      },
      {
        selector: "node.member",
        css: {
          width: MEMBER_DOT,
          height: MEMBER_DOT,
          "background-opacity": 1,
          "border-width": 0,
          "z-index": 2,
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
        selector: "node.label-above",
        css: { "text-valign": "top" },
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
        // The disc behind expanded members never lights up (WebGL picking ignores `events`).
        selector: "node.expanded.hovered, node.expanded.selected",
        css: { "background-opacity": 0.07, "border-width": 1.2 },
      },
      {
        selector: "node.member.selected, node.member.hovered",
        css: { "border-width": 0.8 },
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
        selector: "edge.member-edge",
        css: { width: 0.35, opacity: 0.22 },
      },
      {
        selector: "edge.hovered",
        css: { opacity: 0.85, "line-color": "#b7c7d8" },
      },
    ];
    const { cy: instance, renderer: kind } = createGraph(
      {
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
        // Members need closer zoom; WebGL draws up to zoom 8.
        maxZoom: 7,
        wheelSensitivity: 0.2,
      },
      true,
    );
    cy.current = instance;
    setRenderer(kind);
    container.current.dataset.renderer = kind;
    // Largest clusters claim label space first.
    const order = [...input.clusters]
      .sort((a, b) => b.size - a.size || a.id.localeCompare(b.id))
      .map((c) => c.id);
    const rank = new Map(order.map((id, i) => [id, i]));
    const shown = new Map<string, Shown>();
    const degrees = new Map<string, number>();
    const memberNodes = new Map<string, GraphNode>();
    const legend = container.current.parentElement?.querySelector(
      ".graph-legend",
    ) as HTMLElement | null;
    const radiusOf = (id: string) =>
      shown.get(id)?.radius ?? clusterDiameter(byId.get(id)!.size, largest) / 2;
    const fit = () => {
      const width = instance.width();
      const height = instance.height();
      const largestModel = clusterDiameter(largest, largest);
      // The labels shown at the fitted view (the largest clusters) must not be clipped.
      const reserved = new Set(order.slice(0, labelBudget(1)));
      const narrow = width < 520;
      const expandedArea = [...shown.values()].some((s) => s.members.size);
      instance.viewport(
        fitClusters(
          order.map((id) => {
            const { x, y } = instance.getElementById(id).position();
            return {
              x,
              y,
              r: radiusOf(id),
              label: reserved.has(id)
                ? labelWidth(instance.getElementById(id).data("label")) + 6
                : 0,
            };
          }),
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
            maxZoom: expandedArea
              ? instance.maxZoom()
              : Math.min(
                  instance.maxZoom(),
                  maxCircleDiameter(input.clusters.length, width, height) /
                    largestModel,
                ),
          },
        ),
      );
      fitted = instance.zoom();
    };
    fitView.current = fit;
    let fitted = 1;
    let hovered: string | null = null;
    let labeled = new Set<string>();
    const labels = () => {
      if (instance.destroyed()) return;
      const zoom = instance.zoom();
      const width = instance.width();
      const height = instance.height();
      const required = new Set(
        [hovered, selectedRef.current].filter(
          (id): id is string => !!id && instance.getElementById(id).nonempty(),
        ),
      );
      const candidate = (id: string) => {
        const node = instance.getElementById(id);
        const { x, y } = node.renderedPosition();
        const text = labelWidth(node.data("label"));
        const diameter = node.renderedWidth();
        return {
          id,
          below: clusterLabelBox(id, text, x, y, diameter, "below"),
          above: clusterLabelBox(id, text, x, y, diameter, "above"),
        };
      };
      const candidates = order
        .slice(0, labelBudget(zoom / fitted))
        .map(candidate);
      // Members on screen, highest degree first, once they are far enough apart to read.
      if (
        memberNodes.size &&
        zoom * MEMBER_SPACING * 1.77 >= MEMBER_LABEL_SPACING
      ) {
        const onScreen: [string, number][] = [];
        instance.nodes(".member").forEach((node) => {
          const { x, y } = node.renderedPosition();
          if (x >= 0 && y >= 0 && x <= width && y <= height)
            onScreen.push([node.id(), degrees.get(node.id()) ?? 0]);
        });
        onScreen.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
        for (const [id] of onScreen.slice(0, MEMBER_LABEL_CANDIDATES))
          candidates.push(candidate(id));
      }
      for (const id of required)
        if (!candidates.some((c) => c.id === id))
          candidates.push(candidate(id));
      // A label never covers a larger cluster's circle; small dots draw beneath it.
      // Expanded clusters are discs behind their members, not obstacles.
      const obstacles = order.flatMap((id) => {
        if (shown.has(id)) return [];
        const node = instance.getElementById(id);
        const { x, y } = node.renderedPosition();
        const obstacle = circleObstacle(id, x, y, node.renderedWidth());
        return obstacle ? [obstacle] : [];
      });
      const placed = placeLabels(candidates, width, height, {
        required,
        obstacles,
        rank,
      });
      const size = labelZoom(zoom);
      instance.batch(() => {
        for (const id of labeled)
          if (!placed.has(id))
            instance.getElementById(id).removeClass("label-on label-above");
        for (const [id, side] of placed) {
          const node = instance.getElementById(id);
          // Fixed screen size at every zoom.
          node.style({
            "font-size": LABEL_FONT_PX / size,
            "text-max-width": `${LABEL_MAX_WIDTH / size}px`,
            "text-background-padding": `${2 / size}px`,
            "text-margin-y": (side === "above" ? -5 : 5) / size,
          });
          node.addClass("label-on");
          node.toggleClass("label-above", side === "above");
        }
        // Labeled clusters draw above unlabeled ones, larger above smaller and
        // the hovered or selected one on top, so no circle crosses a label.
        for (const id of order) {
          if (shown.has(id)) continue;
          const z = required.has(id)
            ? order.length * 2
            : placed.has(id)
              ? order.length * 2 - 1 - rank.get(id)!
              : 1;
          instance.getElementById(id).style("z-index", z);
        }
        for (const id of placed.keys())
          if (memberNodes.has(id))
            instance
              .getElementById(id)
              .style(
                "z-index",
                required.has(id) ? order.length * 2 + 2 : order.length * 2 + 1,
              );
        for (const id of labeled)
          if (memberNodes.has(id) && !placed.has(id))
            instance.getElementById(id).style("z-index", 2);
      });
      labeled = new Set(placed.keys());
    };
    relabel.current = labels;
    let frame = 0;
    const schedule = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        labels();
      });
    };
    fit();
    labels();
    instance.on("pan zoom", schedule);
    instance.on("mouseover", "node", (event) => {
      if (shown.has(event.target.id())) return;
      hovered = event.target.id();
      event.target.addClass("hovered");
      event.target.connectedEdges().addClass("hovered");
      if (!memberNodes.has(hovered!))
        hover.current?.(byId.get(hovered!) ?? null);
      labels();
    });
    instance.on("mouseout", "node", (event) => {
      if (shown.has(event.target.id())) return;
      const member = memberNodes.has(event.target.id());
      hovered = null;
      event.target.removeClass("hovered");
      event.target.connectedEdges().removeClass("hovered");
      if (!member) hover.current?.(null);
      labels();
    });
    instance.on("tap", "node", (event) => {
      const id = event.target.id();
      const member = memberNodes.get(id);
      if (member) {
        pick.current?.(member);
        return;
      }
      const cluster = byId.get(id);
      if (cluster && !shown.has(id)) open.current(cluster);
    });

    // In-place expansion: members are laid out on the worker inside the
    // cluster's position; only overlapping circles move aside.
    const reduced = prefersReducedMotion();
    const addEdges = (list: MapExpansion[]) => {
      const add: ElementDefinition[] = [];
      for (const expansion of list)
        for (const edge of expansion.edges)
          if (
            memberNodes.has(edge.source) &&
            memberNodes.has(edge.target) &&
            instance.getElementById(`m:${edge.id}`).empty()
          )
            add.push({
              group: "edges",
              classes: "member-edge",
              data: {
                id: `m:${edge.id}`,
                source: edge.source,
                target: edge.target,
                width: 0.35,
              },
            });
      if (add.length) instance.add(add);
    };
    const place = (expansion: MapExpansion, layout: Position[]) => {
      const id = expansion.cluster.id;
      const entry = shown.get(id);
      if (!entry || instance.destroyed()) return;
      const node = instance.getElementById(id);
      const center = node.position();
      const { positions: spots, radius } = placeInDisc(
        layout,
        center.x,
        center.y,
        clusterDiameter(expansion.cluster.size, largest) / 2,
      );
      entry.radius = radius;
      if (hovered === id) {
        hovered = null;
        hover.current?.(null);
      }
      const fresh = expansion.nodes.filter((n) => !memberNodes.has(n.id));
      const where = new Map(spots.map((p) => [p.id, p]));
      // Neighbours that the disc now overlaps move aside; nothing else moves.
      const moved = makeRoom(
        order.map((cid) => {
          const p = instance.getElementById(cid).position();
          return {
            id: cid,
            x: p.x,
            y: p.y,
            r: radiusOf(cid),
            pinned: shown.has(cid),
          };
        }),
      );
      instance.batch(() => {
        node.data("diameter", radius * 2).addClass("expanded");
        node.removeClass("label-on label-above hovered");
        node.connectedEdges().removeClass("hovered");
        for (const target of moved) {
          const other = instance.getElementById(target.id);
          const now = other.position();
          if (Math.hypot(now.x - target.x, now.y - target.y) < 0.01) continue;
          if (reduced) other.position({ x: target.x, y: target.y });
          else
            other.animate({
              position: { x: target.x, y: target.y },
              duration: 280,
              easing: "ease-out",
            });
        }
        for (const member of fresh) memberNodes.set(member.id, member);
        for (const [mid, degree] of Object.entries(expansion.degrees))
          degrees.set(mid, degree);
        instance.add(
          fresh.map((member) => ({
            group: "nodes" as const,
            classes: "member",
            data: {
              id: member.id,
              label: member.name,
              color: nodeColors[member.type] ?? "#73849a",
              diameter: MEMBER_DOT,
              parentCluster: id,
            },
            position: where.get(member.id) ?? { x: center.x, y: center.y },
          })),
        );
        for (const member of fresh) entry.members.add(member.id);
        addEdges(expansionsRef.current);
      });
      setShownMembers(memberNodes.size);
      // Bring a small disc into view; under reduced motion, without animation.
      const rendered = radius * 2 * instance.zoom();
      const side = Math.min(instance.width(), instance.height());
      if (rendered < side * 0.45) {
        const zoom = Math.min(
          instance.maxZoom(),
          instance.zoom() * 3,
          (side * 0.45) / (radius * 2),
        );
        const viewport = {
          zoom,
          pan: {
            x: instance.width() / 2 - center.x * zoom,
            y: instance.height() / 2 - center.y * zoom,
          },
        };
        if (reduced) instance.viewport(viewport);
        else instance.animate(viewport, { duration: 320, easing: "ease-out" });
      }
      schedule();
    };
    const collapse = (id: string) => {
      const entry = shown.get(id);
      if (!entry) return;
      entry.cancel();
      shown.delete(id);
      instance.batch(() => {
        const members = instance.collection();
        for (const mid of entry.members) {
          members.merge(instance.getElementById(mid));
          memberNodes.delete(mid);
          degrees.delete(mid);
        }
        instance.remove(members);
        const node = instance.getElementById(id);
        node
          .removeClass("expanded")
          .data("diameter", clusterDiameter(byId.get(id)!.size, largest));
      });
      setShownMembers(memberNodes.size);
      schedule();
    };
    sync.current = (list) => {
      if (instance.destroyed()) return;
      const wanted = new Map(
        list
          .filter((e) => byId.has(e.cluster.id))
          .map((e) => [e.cluster.id, e]),
      );
      for (const id of [...shown.keys()]) if (!wanted.has(id)) collapse(id);
      for (const [id, expansion] of wanted) {
        if (shown.has(id)) continue;
        const ids = new Set(expansion.nodes.map((n) => n.id));
        const layoutData: LayoutInput = {
          mode: "packed",
          nodes: [...ids].slice(0, MEMBER_LIMITS.nodes),
          edges: expansion.edges
            .filter((e) => ids.has(e.source) && ids.has(e.target))
            .slice(0, MEMBER_LIMITS.edges)
            .map((e) => ({ id: e.id, source: e.source, target: e.target })),
          attributes: Object.fromEntries(
            expansion.nodes.map((n) => [
              n.id,
              { type: n.type, account: n.account_id },
            ]),
          ),
        };
        const entry: Shown = {
          members: new Set(),
          radius: clusterDiameter(expansion.cluster.size, largest) / 2,
          cancel: () => {},
        };
        shown.set(id, entry);
        let done = false;
        entry.cancel = startLayout(
          layoutData,
          (layout) => {
            done = true;
            place(expansion, layout);
          },
          undefined,
          // No worker (or it failed): the same layout on this thread.
          () => {
            if (!done && shown.get(id) === entry)
              place(expansion, packedPositions(layoutData));
          },
        );
      }
      // Edges to members of a re-expanded cluster come back too.
      addEdges(list);
    };
    sync.current(expansionsRef.current);
    const observer = new ResizeObserver(() => {
      if (instance.destroyed()) return;
      instance.resize();
      schedule();
    });
    observer.observe(container.current);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      for (const entry of shown.values()) entry.cancel();
      instance.destroy();
      cy.current = null;
      sync.current = () => {};
    };
    // The element set is rebuilt only when the clusters or links change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusters, links]);
  useEffect(() => {
    sync.current(expansions);
  }, [expansions]);
  useEffect(() => {
    const instance = cy.current;
    if (!instance) return;
    instance.nodes().removeClass("selected");
    if (selected) instance.getElementById(selected).addClass("selected");
    relabel.current();
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
        data-renderer={renderer ?? undefined}
        data-members={shownMembers}
        aria-label={`Global map with ${clusters.length} clusters${shownMembers ? ` and ${shownMembers.toLocaleString("en-US")} members shown in place` : ""}. Use the cluster list to open one with the keyboard.`}
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
