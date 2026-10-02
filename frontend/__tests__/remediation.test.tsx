import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RemediationHub } from "@/components/remediation-hub";
import { api } from "@/lib/api";
import type { GraphNode } from "@/lib/types";
vi.mock("@/lib/api", () => ({ api: vi.fn() }));
const identity: GraphNode = {
  id: "role:test",
  name: "Data Role",
  type: "CloudRole",
  account_id: "prod",
  provider: "aws",
  sensitivity: "internal",
  tags: [],
  internet_exposed: false,
  authenticated: true,
  encrypted: true,
  privileged: false,
  metadata: {},
};
const preview = {
  id: "proposal-1",
  identity_id: identity.id,
  optimization: {
    original: {},
    optimized: {},
    removed_actions: ["s3:DeleteObject"],
    retained_reasons: ["Deny preserved"],
    diff: "- s3:DeleteObject\n+ s3:GetObject\n",
    review_required: true,
  },
};
beforeEach(() => vi.clearAllMocks());
function mount(canAdmin = true) {
  return render(
    <RemediationHub
      identities={[identity]}
      records={[]}
      onRefresh={vi.fn()}
      demo
      canWrite
      canAdmin={canAdmin}
    />,
  );
}
describe("Remediation hub", () => {
  it("requires explicit coverage attestation and sends original evidence", async () => {
    vi.mocked(api).mockResolvedValue(preview);
    mount();
    expect(
      screen.getByLabelText(
        "I verified complete coverage, including data events",
      ),
    ).not.toBeChecked();
    fireEvent.click(
      screen.getByLabelText(
        "I verified complete coverage, including data events",
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Generate least-privilege preview" }),
    );
    await waitFor(() => expect(api).toHaveBeenCalled());
    const body = JSON.parse(vi.mocked(api).mock.calls[0][1]!.body as string);
    expect(body.usage.complete).toBe(true);
    expect(body.identity_id).toBe(identity.id);
    expect(await screen.findByText("1 actions removed")).toBeInTheDocument();
  });
  it("creates a PR only after an explicit click", async () => {
    vi.mocked(api).mockResolvedValueOnce(preview).mockResolvedValueOnce({
      url: "https://github.com/acme/policies/pull/1",
    });
    mount();
    fireEvent.click(
      screen.getByRole("button", { name: "Generate least-privilege preview" }),
    );
    const button = await screen.findByRole("button", {
      name: "Generate least-privilege PR",
    });
    expect(api).toHaveBeenCalledTimes(1);
    fireEvent.click(button);
    expect(
      await screen.findByRole("link", { name: "Review pull request" }),
    ).toHaveAttribute("href", "https://github.com/acme/policies/pull/1");
  });
  it("prevents a non-administrator from creating PRs", async () => {
    vi.mocked(api).mockResolvedValue(preview);
    mount(false);
    fireEvent.click(
      screen.getByRole("button", { name: "Generate least-privilege preview" }),
    );
    expect(
      await screen.findByRole("button", {
        name: "Generate least-privilege PR",
      }),
    ).toBeDisabled();
  });
  it("invalidates a preview when the input policy changes", async () => {
    vi.mocked(api).mockResolvedValue(preview);
    mount();
    fireEvent.click(
      screen.getByRole("button", { name: "Generate least-privilege preview" }),
    );
    await screen.findByText("1 actions removed");
    fireEvent.change(screen.getByLabelText("Original IAM policy"), {
      target: { value: "{}" },
    });
    expect(
      screen.queryByRole("button", { name: "Generate least-privilege PR" }),
    ).not.toBeInTheDocument();
  });
  it("displays invalid JSON errors", async () => {
    mount();
    fireEvent.change(screen.getByLabelText("Original IAM policy"), {
      target: { value: "invalid" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Generate least-privilege preview" }),
    );
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(api).not.toHaveBeenCalled();
  });
});
