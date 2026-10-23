import type { OverviewActivity } from "@/lib/types";

export interface WeekBucket {
  /** First day of the week (YYYY-MM-DD). */
  start: string;
  identities: number;
  pairs: number;
}

const DAY = 86_400_000;
const iso = (t: number) => new Date(t).toISOString().slice(0, 10);

/**
 * Roll the daily activity series into consecutive 7-day buckets from its first
 * day; days with no rows count as zero, so the x axis is linear in time.
 */
export function weekly(days: OverviewActivity["days"]): WeekBucket[] {
  if (!days.length) return [];
  const first = Date.parse(`${days[0].day}T00:00:00Z`);
  const last = Date.parse(`${days[days.length - 1].day}T00:00:00Z`);
  const weeks = Math.floor((last - first) / DAY / 7) + 1;
  const buckets: WeekBucket[] = Array.from({ length: weeks }, (_, n) => ({
    start: iso(first + n * 7 * DAY),
    identities: 0,
    pairs: 0,
  }));
  for (const d of days) {
    const n = Math.floor((Date.parse(`${d.day}T00:00:00Z`) - first) / DAY / 7);
    const bucket = buckets[n];
    if (!bucket) continue;
    bucket.identities += d.identities_last_used;
    bucket.pairs += d.pairs_first_seen;
  }
  return buckets;
}
