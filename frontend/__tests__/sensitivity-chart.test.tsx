import { render } from "@testing-library/react";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  SENSITIVITY_CHART_HEIGHT,
  SensitivityChart,
} from "@/components/sensitivity-chart";

// jsdom has no layout: give ResponsiveContainer a real size so the chart draws.
const realRect = HTMLElement.prototype.getBoundingClientRect;
const realObserver = globalThis.ResizeObserver;
beforeAll(() => {
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      right: 600,
      bottom: 250,
      width: 600,
      height: 250,
      toJSON() {},
    }) as DOMRect;
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
});
afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = realRect;
  globalThis.ResizeObserver = realObserver;
});

const bars = (container: HTMLElement) =>
  [...container.querySelectorAll("path.recharts-rectangle")].map((p) => ({
    name: p.getAttribute("name"),
    fill: p.getAttribute("fill"),
    height: Number(p.getAttribute("height")),
  }));

describe("SensitivityChart", () => {
  it("draws every non-empty bar at full height on the first render", () => {
    const { container } = render(
      <SensitivityChart
        sensitivity={{ public: 1, internal: 0, confidential: 1, restricted: 2 }}
      />,
    );
    // No animation frames have run: bars must already be in their final state,
    // not growing in from zero height (which left fresh paints without bars).
    const drawn = bars(container);
    expect(drawn.map((b) => b.name)).toEqual([
      "public",
      "confidential",
      "restricted",
    ]);
    expect(drawn.every((b) => b.height > 0)).toBe(true);
    const restricted = drawn.find((b) => b.name === "restricted")!;
    const publicBar = drawn.find((b) => b.name === "public")!;
    expect(restricted.height).toBeCloseTo(publicBar.height * 2, 0);
  });

  it("colors bars by sensitivity level, not by position", () => {
    const { container } = render(
      <SensitivityChart sensitivity={{ restricted: 3, public: 1 }} />,
    );
    expect(bars(container)).toEqual([
      expect.objectContaining({ name: "public", fill: "#5d6b7e" }),
      expect.objectContaining({ name: "restricted", fill: "#e0707c" }),
    ]);
  });

  it("draws bars when the overview arrives after the chart mounted", () => {
    const { container, rerender, getByTestId } = render(
      <SensitivityChart sensitivity={undefined} />,
    );
    expect(bars(container)).toHaveLength(0);
    // Height is reserved while loading so the panel does not resize.
    expect(getByTestId("sensitivity-chart").style.height).toBe(
      `${SENSITIVITY_CHART_HEIGHT}px`,
    );
    rerender(
      <SensitivityChart
        sensitivity={{ public: 2, internal: 1, confidential: 0, restricted: 4 }}
      />,
    );
    expect(bars(container).map((b) => b.name)).toEqual([
      "public",
      "internal",
      "restricted",
    ]);
    expect(getByTestId("sensitivity-chart").style.height).toBe(
      `${SENSITIVITY_CHART_HEIGHT}px`,
    );
  });
});
