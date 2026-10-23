"use client";
import { useId } from "react";
import { formatCount } from "@/lib/format";

/*
 * Small hand-rolled SVG/HTML charts for the overview: a ring gauge, a donut, a
 * (stacked) bar list and an area chart. No chart dependency, fixed dimensions
 * (loading and empty states keep the same box), animate in once with CSS (off
 * under prefers-reduced-motion) and always carry a text equivalent.
 */

export interface Segment {
  key: string;
  label: string;
  value: number;
  color: string;
}

const RING_R = 42;
const RING_C = 2 * Math.PI * RING_R;

/** A single-value ring gauge (share 0..1), with a centred value and caption. */
export function RingGauge({
  value,
  label,
  center,
  caption,
  color = "var(--accent)",
  size = 120,
}: {
  value: number | null | undefined;
  label: string;
  center: string;
  caption?: string;
  color?: string;
  size?: number;
}) {
  const share =
    value === null || value === undefined || Number.isNaN(value)
      ? null
      : Math.max(0, Math.min(1, value));
  const length = share === null ? 0 : share * RING_C;
  return (
    <figure
      className="gauge-ring"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`${label}: ${center}${caption ? ` ${caption}` : ""}`}
    >
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <circle className="ring-track" cx="50" cy="50" r={RING_R} />
        {share !== null && share > 0 && (
          <circle
            className="ring-value"
            cx="50"
            cy="50"
            r={RING_R}
            stroke={color}
            strokeDasharray={`${length} ${RING_C}`}
            style={{ ["--ring-c" as string]: RING_C }}
          />
        )}
      </svg>
      <figcaption aria-hidden="true">
        <b>{center}</b>
        {caption && <small>{caption}</small>}
      </figcaption>
    </figure>
  );
}

/** A donut of parts of a whole, with the total in the centre. */
export function Donut({
  segments,
  label,
  center,
  caption,
  size = 120,
}: {
  segments: Segment[];
  label: string;
  center: string;
  caption?: string;
  size?: number;
}) {
  const total = segments.reduce((sum, s) => sum + Math.max(0, s.value), 0);
  // A hairline gap between segments, only when there is more than one.
  const shown = segments.filter((s) => s.value > 0);
  const gap = shown.length > 1 ? 1.2 : 0;
  let offset = 0;
  return (
    <figure
      className="gauge-ring"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`${label}: ${center}${caption ? ` ${caption}` : ""}. ${segments
        .map((s) => `${s.label} ${formatCount(s.value)}`)
        .join(", ")}`}
    >
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <circle className="ring-track" cx="50" cy="50" r={RING_R} />
        {total > 0 &&
          shown.map((s) => {
            const length = (s.value / total) * RING_C;
            const visible = Math.max(0.6, length - gap);
            const dash = (
              <circle
                key={s.key}
                className="ring-value"
                cx="50"
                cy="50"
                r={RING_R}
                stroke={s.color}
                strokeDasharray={`${visible} ${RING_C}`}
                strokeDashoffset={-offset}
                style={{ ["--ring-c" as string]: RING_C }}
              />
            );
            offset += length;
            return dash;
          })}
      </svg>
      <figcaption aria-hidden="true">
        <b>{center}</b>
        {caption && <small>{caption}</small>}
      </figcaption>
    </figure>
  );
}

/** Legend rows for a donut or stacked bars: swatch, label, value. */
export function Legend({
  segments,
  format = formatCount,
}: {
  segments: Segment[];
  format?: (value: number) => string;
}) {
  return (
    <ul className="chart-legend">
      {segments.map((s) => (
        <li key={s.key}>
          <i style={{ background: s.color }} aria-hidden="true" />
          <span>{s.label}</span>
          <b>{format(s.value)}</b>
        </li>
      ))}
    </ul>
  );
}

export interface BarItem {
  key: string;
  label: string;
  /** Stacked parts, drawn left to right; their sum is the bar's length. */
  parts: Segment[];
  /** Text at the end of the row (defaults to the total). */
  display?: string;
  title?: string;
}

/**
 * Horizontal bars, one row per item, scaled to the largest total. A fixed number
 * of rows (placeholders while loading) so the panel never changes height.
 */
export function BarList({
  items,
  rows,
  label,
  loading = false,
  empty = "No data",
}: {
  items: BarItem[];
  rows: number;
  label: string;
  loading?: boolean;
  empty?: string;
}) {
  const totals = items.map((i) => i.parts.reduce((s, p) => s + p.value, 0));
  const max = Math.max(1, ...totals);
  const blanks = Math.max(0, rows - items.length);
  return (
    <div className="bar-list" role="list" aria-label={label}>
      {items.slice(0, rows).map((item, n) => (
        <div
          className="bar-row"
          role="listitem"
          key={item.key}
          title={item.title ?? item.label}
          aria-label={`${item.label}: ${item.display ?? formatCount(totals[n])}${
            item.parts.length > 1
              ? ` (${item.parts.map((p) => `${p.label} ${formatCount(p.value)}`).join(", ")})`
              : ""
          }`}
        >
          <span className="bar-label">{item.label}</span>
          <span className="bar-track" aria-hidden="true">
            <span
              className="bar-fill"
              style={{
                width: `${(totals[n] / max) * 100}%`,
                ["--bar-delay" as string]: `${n * 40}ms`,
              }}
            >
              {item.parts.map((p) => (
                <span
                  key={p.key}
                  style={{
                    flexGrow: p.value,
                    background: p.color,
                  }}
                />
              ))}
            </span>
          </span>
          <span className="bar-value">
            {item.display ?? formatCount(totals[n])}
          </span>
        </div>
      ))}
      {Array.from({ length: blanks }, (_, n) => (
        <div
          className={loading ? "bar-row skeleton-row" : "bar-row blank-row"}
          aria-hidden="true"
          key={`blank-${n}`}
        >
          <span className="bar-label">
            {!loading && n === 0 && !items.length ? empty : ""}
          </span>
          <span className="bar-track" />
          <span className="bar-value" />
        </div>
      ))}
    </div>
  );
}

export interface SeriesPoint {
  label: string;
  value: number;
}

/**
 * Area chart of one series over evenly spaced points, with a faint second series
 * drawn as a line. Fixed height; the SVG stretches to the panel's width.
 */
export function AreaChart({
  series,
  secondary,
  label,
  height = 120,
}: {
  series: SeriesPoint[];
  secondary?: SeriesPoint[];
  label: string;
  height?: number;
}) {
  const gradient = `area-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const W = 300;
  const H = 100;
  const max = Math.max(
    1,
    ...series.map((p) => p.value),
    ...(secondary ?? []).map((p) => p.value),
  );
  const xy = (points: SeriesPoint[]) =>
    points.map((p, i) => [
      points.length > 1 ? (i / (points.length - 1)) * W : W / 2,
      H - (p.value / max) * (H - 6) - 2,
    ]);
  const line = (points: number[][]) =>
    points
      .map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`)
      .join(" ");
  const main = xy(series);
  const area = main.length ? `${line(main)} L${W},${H} L0,${H} Z` : "";
  const peak = series.reduce(
    (best, p) => (p.value > best.value ? p : best),
    series[0] ?? { label: "", value: 0 },
  );
  return (
    <figure
      className="area-chart"
      style={{ height }}
      role="img"
      aria-label={
        series.length
          ? `${label}: ${series.length} points from ${series[0].label} to ${series[series.length - 1].label}, peak ${formatCount(peak.value)} (${peak.label})`
          : `${label}: no data`
      }
    >
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id={gradient} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0.32" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((f) => (
          <line
            key={f}
            className="area-grid"
            x1="0"
            x2={W}
            y1={H * f}
            y2={H * f}
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {area && (
          <path className="area-fill" d={area} fill={`url(#${gradient})`} />
        )}
        {main.length > 0 && (
          <path
            className="area-line"
            d={line(main)}
            vectorEffect="non-scaling-stroke"
          />
        )}
        {secondary && secondary.length > 0 && (
          <path
            className="area-line secondary"
            d={line(xy(secondary))}
            vectorEffect="non-scaling-stroke"
          />
        )}
      </svg>
    </figure>
  );
}
