import type { LabelBounds } from "./graph-layout";

/**
 * Elements drawn over a graph canvas that labels must stay clear of: the zoom
 * controls, each legend entry and the children of any `[data-label-obstacle]`
 * (the global map's "members shown in place" chip and its Collapse all button).
 */
export const OVERLAY_SELECTOR =
  ".graph-controls, .graph-legend > *, [data-label-obstacle] > *";
/** Clearance kept between a label and an overlay, in screen pixels. */
export const OVERLAY_GAP = 4;

interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

/**
 * Overlay rectangles (viewport coordinates) as label obstacles in the canvas's
 * own screen space, padded by `gap`. Empty (hidden) rectangles are dropped.
 */
export function overlayBoxes(
  canvas: Pick<Rect, "left" | "top">,
  rects: Rect[],
  gap = OVERLAY_GAP,
): LabelBounds[] {
  return rects
    .filter((r) => r.right - r.left > 0 && r.bottom - r.top > 0)
    .map((r, i) => ({
      id: `overlay:${i}`,
      x1: r.left - canvas.left - gap,
      y1: r.top - canvas.top - gap,
      x2: r.right - canvas.left + gap,
      y2: r.bottom - canvas.top + gap,
    }));
}

/**
 * The overlay scope of a canvas: the nearest `[data-label-scope]` ancestor (the
 * global map wraps the canvas and its status chip), else the canvas wrapper.
 */
export function overlayScope(container: HTMLElement): Element | null {
  return container.closest("[data-label-scope]") ?? container.parentElement;
}

/** Current on-screen overlays of a canvas, as label obstacles in its screen space. */
export function overlayObstacles(container: HTMLElement): LabelBounds[] {
  const scope = overlayScope(container);
  if (!scope) return [];
  return overlayBoxes(
    container.getBoundingClientRect(),
    [...scope.querySelectorAll(OVERLAY_SELECTOR)].map((e) =>
      e.getBoundingClientRect(),
    ),
  );
}
