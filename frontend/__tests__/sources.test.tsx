import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { Sources } from "@/components/sources";
import { api } from "@/lib/api";
vi.mock("@/lib/api", () => ({ api: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
// The usage evidence panel loads its status on mount; ingestion calls are the rest.
const ingestionCalls = () =>
  vi.mocked(api).mock.calls.filter((call) => call[0] !== "usage");
it("queues only a configured AWS connector without client credentials", async () => {
  vi.mocked(api).mockResolvedValue({ id: "job" });
  const refresh = vi.fn();
  render(<Sources jobs={[]} onRefresh={refresh} canAdmin />);
  fireEvent.change(screen.getByLabelText("Source"), {
    target: { value: "aws" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Queue ingestion" }));
  await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
  expect(JSON.parse(ingestionCalls()[0][1]!.body as string)).toEqual({
    source: "aws",
    payload: {},
  });
});
it("restricts ingestion controls to administrators", () => {
  render(<Sources jobs={[]} onRefresh={vi.fn()} canAdmin={false} />);
  fireEvent.change(screen.getByLabelText("Source"), {
    target: { value: "aws" },
  });
  expect(
    screen.getByRole("button", { name: "Queue ingestion" }),
  ).toBeDisabled();
});
it("uploads a large snapshot file in chunks through an upload session", async () => {
  vi.mocked(api).mockImplementation(async (path: string) =>
    path === "ingestions/uploads" ? { id: "upload-1" } : { id: "job" },
  );
  const refresh = vi.fn();
  render(<Sources jobs={[]} onRefresh={refresh} canAdmin />);
  const nodes = Array.from({ length: 12_000 }, (_, i) => ({
    id: `node:${i}`,
    name: "x".repeat(300),
    type: "S3Bucket",
  }));
  const file = new File([JSON.stringify({ nodes, edges: [] })], "graph.json", {
    type: "application/json",
  });
  fireEvent.change(screen.getByLabelText(/^Snapshot file/), {
    target: { files: [file] },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Queue ingestion" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Queue ingestion" }));
  await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
  const paths = ingestionCalls().map((call) => call[0]);
  expect(paths[0]).toBe("ingestions/uploads");
  expect(paths.at(-1)).toBe("ingestions/uploads/upload-1/commit");
  const chunks = vi
    .mocked(api)
    .mock.calls.filter((call) => String(call[0]).includes("/chunks/"));
  expect(chunks.length).toBeGreaterThan(1);
  expect(chunks.map((call) => call[0])).toEqual(
    chunks.map((_, i) => `ingestions/uploads/upload-1/chunks/${i}`),
  );
  const lines = chunks.flatMap((call) =>
    String(call[1]!.body).trim().split("\n"),
  );
  expect(lines).toHaveLength(12_000);
  expect(JSON.parse(lines[0])).toEqual({ node: nodes[0] });
  expect(paths).not.toContain("ingestions");
});
