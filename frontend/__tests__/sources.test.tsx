import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { Sources } from "@/components/sources";
import { api } from "@/lib/api";
vi.mock("@/lib/api", () => ({ api: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
it("queues only a configured AWS connector without client credentials", async () => {
  vi.mocked(api).mockResolvedValue({ id: "job" });
  const refresh = vi.fn();
  render(<Sources jobs={[]} onRefresh={refresh} canAdmin />);
  fireEvent.change(screen.getByLabelText("Source"), {
    target: { value: "aws" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Queue ingestion" }));
  await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
  expect(JSON.parse(vi.mocked(api).mock.calls[0][1]!.body as string)).toEqual({
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
