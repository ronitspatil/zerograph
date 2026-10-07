import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { UsageUpload } from "@/components/usage-upload";
import { ExcessPrivilegePanel } from "@/components/privilege";
import { api } from "@/lib/api";
import { MAX_FILE_BYTES, windowBounds } from "@/lib/usage";
import type { ExcessPrivilegeTile } from "@/lib/types";
vi.mock("@/lib/api", () => ({ api: vi.fn() }));
beforeEach(() => vi.clearAllMocks());

const NOW = Date.UTC(2026, 9, 6);
const committed = {
  id: "u1",
  status: "committed",
  revision: "r1",
  stats: {
    files: 2,
    records: 1200,
    matched: 1100,
    pairs: 800,
    unmapped: 3,
    denied: 4,
    outside_window: 0,
    malformed: 0,
    unresolved_principal: 0,
    unresolved_resource: 0,
    coverage: [
      {
        service: "ec2",
        attested: false,
        events: 3,
        unmapped: 3,
        complete: false,
      },
      {
        service: "s3",
        attested: true,
        events: 900,
        unmapped: 0,
        complete: true,
      },
    ],
  },
  evidence: { status: "attested", sufficient_services: ["s3"] },
  notice: "Observed use is evidence of need only where coverage is attested.",
};

it("uploads export files for the declared window and shows coverage", async () => {
  vi.mocked(api).mockImplementation(async (path: string) =>
    path === "usage"
      ? { evidence: { status: "none" }, uploads: [], services: [], notice: "" }
      : path === "usage/uploads"
        ? { id: "u1" }
        : path.endsWith("/commit")
          ? committed
          : { progress: {} },
  );
  render(<UsageUpload canAdmin now={NOW} />);
  expect(screen.getByLabelText("First day")).toHaveValue("2026-07-07");
  expect(screen.getByLabelText("Last day")).toHaveValue("2026-10-05");
  fireEvent.click(screen.getByLabelText("glue"));
  fireEvent.click(screen.getByLabelText("sts"));
  const files = [
    new File(['{"Records": []}'], "a.json", { type: "application/json" }),
    new File([new Uint8Array([0x1f, 0x8b, 1])], "b.json.gz"),
  ];
  fireEvent.change(screen.getByLabelText(/^CloudTrail export files/), {
    target: { files },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Upload usage evidence" }),
  );
  await screen.findByText("Upload committed");
  const calls = vi.mocked(api).mock.calls.filter((c) => c[0] !== "usage");
  expect(calls.map((c) => c[0])).toEqual([
    "usage/uploads",
    "usage/uploads/u1/files/0",
    "usage/uploads/u1/files/1",
    "usage/uploads/u1/commit",
  ]);
  expect(JSON.parse(calls[0][1]!.body as string)).toEqual({
    window_start: "2026-07-07T00:00:00.000Z",
    window_end: "2026-10-05T23:59:59.000Z",
    attested_services: ["glue", "s3"],
  });
  expect(calls[1][1]!.body).toBeInstanceOf(ArrayBuffer);
  expect(screen.getByText(/1,200 records/)).toBeInTheDocument();
  expect(screen.getByText("Incomplete")).toBeInTheDocument();
  expect(screen.getByText("Complete")).toBeInTheDocument();
});

it("refuses oversized files and keeps the control admin-only", async () => {
  vi.mocked(api).mockResolvedValue({
    evidence: { status: "none" },
    uploads: [],
    services: [],
    notice: "",
  });
  const { unmount } = render(<UsageUpload canAdmin={false} now={NOW} />);
  expect(
    screen.getByRole("button", { name: "Upload usage evidence" }),
  ).toBeDisabled();
  unmount();
  render(<UsageUpload canAdmin now={NOW} />);
  const big = new File(["x"], "big.json");
  Object.defineProperty(big, "size", { value: MAX_FILE_BYTES + 1 });
  fireEvent.change(screen.getByLabelText(/^CloudTrail export files/), {
    target: { files: [big] },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Upload usage evidence" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "big.json is larger than 3.9 MB",
  );
  expect(vi.mocked(api).mock.calls.every((c) => c[0] === "usage")).toBe(true);
  expect(() =>
    windowBounds({
      windowStart: "2026-10-05",
      windowEnd: "2026-10-01",
      attestedServices: [],
    }),
  ).toThrow("start before it ends");
});

it("shows current evidence on load", async () => {
  vi.mocked(api).mockResolvedValue({
    evidence: {
      status: "partial",
      window_start: "2026-07-01T00:00:00+00:00",
      window_end: "2026-08-01T00:00:00+00:00",
      observed_pairs: 12,
      sufficient_services: [],
    },
    uploads: [],
    services: [],
    notice: "",
  });
  render(<UsageUpload canAdmin now={NOW} />);
  await waitFor(() =>
    expect(screen.getByText(/2026-07-01 to 2026-08-01/)).toBeInTheDocument(),
  );
  expect(
    screen.getByText("Usage evidence, not sufficient"),
  ).toBeInTheDocument();
  expect(screen.getByText(/sufficient for no service yet/)).toBeInTheDocument();
});

const aggregate = (epi: number | null, core: number | null) => ({
  granted_weight: 100,
  needed_weight: 30,
  granted_weight_excl_hubs: 40,
  needed_weight_excl_hubs: 30,
  epi,
  epi_excl_hubs: core,
  basis: { used: 10, inferred: 0, none: 0 },
});

it("overview tile decomposes excess privilege and labels its evidence", () => {
  const tile: ExcessPrivilegeTile = {
    status: "attested",
    window_start: "2026-07-01T00:00:00+00:00",
    window_end: "2026-10-01T00:00:00+00:00",
    sufficient_services: ["s3", "sts"],
    identities: aggregate(0.983, 0.633),
    roles: aggregate(0.479, 0.479),
    unused_grants: 97713,
    unused_restricted_grants: 21000,
    dormant_identities: 6097,
    dormant_roles: 12,
  };
  render(<ExcessPrivilegePanel tile={tile} />);
  expect(screen.getByText("98%")).toBeInTheDocument();
  expect(screen.getByText("63%")).toBeInTheDocument();
  expect(screen.getByText("48% / 48%")).toBeInTheDocument();
  expect(screen.getByText("97,713 (21,000)")).toBeInTheDocument();
  expect(screen.getByText("6,097")).toBeInTheDocument();
  expect(
    screen.getByText(/Attested usage evidence · 2026-07-01 to 2026-10-01/),
  ).toBeInTheDocument();
});

it("overview tile without evidence shows granted only and links to sources", () => {
  const open = vi.fn();
  render(
    <ExcessPrivilegePanel
      tile={{
        status: "none",
        window_start: null,
        window_end: null,
        sufficient_services: [],
        identities: aggregate(null, null),
        roles: aggregate(null, null),
        unused_grants: 0,
        unused_restricted_grants: 0,
        dormant_identities: 0,
        dormant_roles: 0,
      }}
      onOpenSources={open}
    />,
  );
  expect(screen.getAllByText("—").length).toBeGreaterThan(3);
  fireEvent.click(
    screen.getByRole("button", { name: "Upload usage evidence" }),
  );
  expect(open).toHaveBeenCalledOnce();
});
