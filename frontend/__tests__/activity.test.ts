import { describe, expect, it } from "vitest";
import { weekly } from "@/lib/activity";

describe("weekly", () => {
  it("rolls days into consecutive 7-day buckets, zero-filling gaps", () => {
    expect(weekly([])).toEqual([]);
    expect(
      weekly([
        { day: "2026-09-01", identities_last_used: 2, pairs_first_seen: 5 },
        { day: "2026-09-07", identities_last_used: 1, pairs_first_seen: 0 },
        { day: "2026-09-22", identities_last_used: 4, pairs_first_seen: 1 },
      ]),
    ).toEqual([
      { start: "2026-09-01", identities: 3, pairs: 5 },
      { start: "2026-09-08", identities: 0, pairs: 0 },
      { start: "2026-09-15", identities: 0, pairs: 0 },
      { start: "2026-09-22", identities: 4, pairs: 1 },
    ]);
  });
});
