import { describe, expect, it } from "vitest";
import { formatCount } from "@/lib/format";

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
