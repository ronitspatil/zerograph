/**
 * The one formatter for user-facing counts: en-US thousands separators
 * ("47,845"), fixed locale so server and client render the same text and tests
 * are deterministic. Only for display; values sent to or read from the API stay
 * numbers, and IDs or revision hashes are never formatted.
 */
const counts = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });

/** "47,845" for 47845; "0" for a missing or non-finite value. */
export function formatCount(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "0";
  return counts.format(value);
}

const percents = new Intl.NumberFormat("en-US", {
  minimumFractionDigits: 1,
  maximumFractionDigits: 1,
});

/**
 * The one percent style: a 0..1 share with one decimal ("63.8%"). "—" for a
 * missing or non-finite value, so placeholders and values line up.
 */
export function formatPercent(share: number | null | undefined): string {
  return typeof share === "number" && Number.isFinite(share)
    ? `${percents.format(share * 100)}%`
    : "—";
}

/**
 * The change between two 0..1 shares in percentage points ("−14.4 pp",
 * "+0.2 pp", "0.0 pp"); empty when either side is missing.
 */
export function formatPp(
  before: number | null | undefined,
  after: number | null | undefined,
): string {
  if (
    typeof before !== "number" ||
    typeof after !== "number" ||
    !Number.isFinite(before) ||
    !Number.isFinite(after)
  )
    return "";
  const delta = Math.round((after - before) * 1000) / 10;
  if (delta === 0) return "0.0 pp";
  return `${delta > 0 ? "+" : "−"}${percents.format(Math.abs(delta))} pp`;
}

/**
 * Timestamps in tables: "2026-10-15 20:28" in the viewer's time zone, the same
 * year-month-day order the evidence windows use.
 */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
