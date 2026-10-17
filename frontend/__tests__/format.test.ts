import { describe, expect, it } from "vitest";
import {
  formatCount,
  formatDateTime,
  formatPercent,
  formatPp,
} from "@/lib/format";

describe("formatCount", () => {
  it("groups thousands en-US style", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(999)).toBe("999");
    expect(formatCount(5975)).toBe("5,975");
    expect(formatCount(47845)).toBe("47,845");
    expect(formatCount(100000)).toBe("100,000");
    expect(formatCount(1234567)).toBe("1,234,567");
    expect(formatCount(-15304)).toBe("-15,304");
  });
  it("shows a missing or invalid count as zero", () => {
    expect(formatCount(undefined)).toBe("0");
    expect(formatCount(null)).toBe("0");
    expect(formatCount(Number.NaN)).toBe("0");
    expect(formatCount(Number.POSITIVE_INFINITY)).toBe("0");
  });
});

describe("formatPercent", () => {
  it("shows every share with one decimal", () => {
    expect(formatPercent(0)).toBe("0.0%");
    expect(formatPercent(0.6)).toBe("60.0%");
    expect(formatPercent(0.9834)).toBe("98.3%");
    expect(formatPercent(1)).toBe("100.0%");
  });
  it("shows a missing share as a dash", () => {
    expect(formatPercent(undefined)).toBe("—");
    expect(formatPercent(Number.NaN)).toBe("—");
  });
});

describe("formatPp", () => {
  it("states the change in percentage points with its sign", () => {
    expect(formatPp(0.638, 0.494)).toBe("−14.4 pp");
    expect(formatPp(0.2, 0.25)).toBe("+5.0 pp");
    expect(formatPp(0.982, 0.982)).toBe("0.0 pp");
  });
  it("is empty when either side is missing", () => {
    expect(formatPp(undefined, 0.5)).toBe("");
    expect(formatPp(0.5, null)).toBe("");
  });
});

describe("formatDateTime", () => {
  it("uses year-month-day and 24-hour local time", () => {
    const local = new Date(2026, 9, 15, 20, 8).toISOString();
    expect(formatDateTime(local)).toBe("2026-10-15 20:08");
  });
  it("shows a missing or invalid time as a dash", () => {
    expect(formatDateTime(undefined)).toBe("—");
    expect(formatDateTime("not a date")).toBe("—");
  });
});
