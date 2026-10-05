"use client";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Sensitivity } from "@/lib/types";

const LEVELS: Sensitivity[] = [
  "public",
  "internal",
  "confidential",
  "restricted",
];
const LEVEL_COLORS: Record<Sensitivity, string> = {
  public: "#5d6b7e",
  internal: "#7f9bbd",
  confidential: "#d9a85b",
  restricted: "#e0707c",
};
const AXIS_TICK = { fill: "#8a96a8", fontSize: 11 };

export const SENSITIVITY_CHART_HEIGHT = 250;

/**
 * Overview "Data sensitivity" bar chart.
 *
 * The bars are drawn at their final size on the first render
 * (`isAnimationActive={false}`). Recharts' grow-in animation rewrites every bar
 * path on each animation frame; Chrome then keeps stale SVG geometry for the
 * bar layer, and any fresh paint of the page (full-page capture, print) drew
 * the axes without a single bar until something forced a relayout. A static
 * chart is also correct from the first frame when the overview data arrives
 * after the chart has mounted.
 *
 * The wrapper height is fixed, so the panel keeps its size while the overview
 * is still loading and when the data arrives.
 */
export function SensitivityChart({
  sensitivity,
}: {
  sensitivity: Partial<Record<Sensitivity, number>> | undefined;
}) {
  const data = sensitivity
    ? LEVELS.filter((level) => level in sensitivity).map((level) => ({
        name: level,
        value: sensitivity[level] ?? 0,
      }))
    : [];
  return (
    <div
      style={{ height: SENSITIVITY_CHART_HEIGHT }}
      data-testid="sensitivity-chart"
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <XAxis
            dataKey="name"
            tick={AXIS_TICK}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={AXIS_TICK}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              background: "#131b27",
              border: "1px solid #263142",
              borderRadius: 6,
              fontSize: 12,
            }}
            cursor={{ fill: "#182230" }}
          />
          <Bar
            dataKey="value"
            radius={[3, 3, 0, 0]}
            maxBarSize={40}
            isAnimationActive={false}
          >
            {data.map((d) => (
              <Cell key={d.name} fill={LEVEL_COLORS[d.name]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
