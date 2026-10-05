import cytoscape, { type Core, type CytoscapeOptions } from "cytoscape";

/**
 * Cytoscape renderer selection. The canvas renderer draws the sharpest labels
 * and is used for small detail views; its WebGL mode (Cytoscape 3.31+, no extra
 * dependency) keeps 60 fps at 5,000 nodes / 20,000 edges, so large visible
 * slices and the global map use it whenever the browser offers WebGL 2.
 */

/** Views with more nodes than this use WebGL when available. */
export const WEBGL_MIN_NODES = 500;

let supported: boolean | undefined;

/** WebGL 2 is available (checked once with a throwaway context, then released). */
export function webglSupported(): boolean {
  if (supported !== undefined) return supported;
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl2");
    supported = !!gl;
    gl?.getExtension("WEBGL_lose_context")?.loseContext();
  } catch {
    supported = false;
  }
  return supported;
}

/** Test hook: forget the detected support. */
export function resetWebglSupport(value?: boolean): void {
  supported = value;
}

export type RendererKind = "webgl" | "canvas";

/**
 * Create a Cytoscape instance, in WebGL mode when asked for and supported. If
 * WebGL initialisation fails anyway (a lost or blocked context), the same
 * options build a canvas instance instead, so the view always renders.
 */
export function createGraph(
  options: CytoscapeOptions,
  wantWebgl: boolean,
): { cy: Core; renderer: RendererKind } {
  const container = options.container as HTMLElement | undefined;
  if (wantWebgl && webglSupported()) {
    try {
      // WebGL blends arrow heads against this colour; use the canvas's own background.
      if (container && !container.style.backgroundColor) {
        let element: HTMLElement | null = container;
        while (element) {
          const background = getComputedStyle(element).backgroundColor;
          if (background && background !== "rgba(0, 0, 0, 0)") {
            container.style.backgroundColor = background;
            break;
          }
          element = element.parentElement;
        }
      }
      const cy = cytoscape({
        ...options,
        // Not in @types/cytoscape yet: the canvas renderer's WebGL mode.
        renderer: { name: "canvas", webgl: true },
      } as CytoscapeOptions);
      return { cy, renderer: "webgl" };
    } catch {
      supported = false;
      // A half-built renderer may have left canvases behind.
      if (container) container.replaceChildren();
    }
  }
  return {
    cy: cytoscape({
      ...options,
      // Large views on the canvas renderer pan and zoom a cached texture.
      ...(wantWebgl ? { textureOnViewport: true } : {}),
    }),
    renderer: "canvas",
  };
}

export function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}
