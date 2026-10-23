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
import { formatCount } from "@/lib/format";
import type { Sensitivity } from "@/lib/types";

const LEVELS: Sensitivity[] = [
  "public",
  "internal",
  "confidential",
  "restricted",
];
/* A calm-to-hot ramp on the console palette: muted green-grey, accent green,
   then the warning and danger hues (SVG fill attributes cannot read CSS vars). */
const LEVEL_COLORS: Record<Sensitivity, string> = {
  public: "#3d5048",
  internal: "#4fae86",
  confidential: "#e1b268",
  restricted: "#ef7f8a",
};
const AXIS_TICK = { fill: "#84958c", fontSize: 11 };

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
            tickFormatter={(value: number) => formatCount(value)}
            tick={AXIS_TICK}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            formatter={(value) => formatCount(Number(value))}
            contentStyle={{
              background: "#111a18",
              border: "1px solid #26342e",
              borderRadius: 6,
              fontSize: 12,
              color: "#e2ebe6",
            }}
            labelStyle={{ color: "#b1c0b8" }}
            itemStyle={{ color: "#e2ebe6" }}
            cursor={{ fill: "#142019" }}
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
