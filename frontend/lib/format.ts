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
