import { expect, it } from "vitest";
import { byteLength, packChunks, snapshotLines } from "@/lib/upload";
it("packs NDJSON lines in order without exceeding the byte limit", () => {
  const lines = [...snapshotLines({
    nodes: [{ id: "é".repeat(10) }, { id: "b" }],
    edges: [{ source: "a", target: "b" }],
    warnings: ["w"],
  })];
  expect(lines.map((line) => Object.keys(JSON.parse(line))[0])).toEqual([
    "node",
    "node",
    "edge",
    "warning",
  ]);
  const chunks = packChunks(lines, 60);
  expect(chunks.every((chunk) => byteLength(chunk) <= 60)).toBe(true);
  expect(chunks.join("").trim().split("\n")).toEqual(lines);
  expect(() => packChunks(["x".repeat(100)], 60)).toThrow();
});
