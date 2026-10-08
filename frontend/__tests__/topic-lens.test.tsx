import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GlobalMap } from "@/components/global-map";
import {
  SHARE_COLORS,
  TOPICS_RETRY_MS,
  topicCircle,
  topicColor,
} from "@/components/topic-lens";
import { api, ApiError } from "@/lib/api";
import type {
  ClusterMap,
  TopicDetail,
  TopicMap,
  TopicMember,
  TopicSummary,
} from "@/lib/types";
// The status bar keeps an invisible copy of the top-level line as its sizer.
const VISIBLE = { ignore: "script, style, [aria-hidden=true] *" };
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  api: vi.fn(),
}));
vi.mock("next/dynamic", () => ({ default: () => () => <div>Canvas</div> }));

const STRUCTURAL =
  "Clusters group entities by graph structure only. They are not permission or trust boundaries; membership in a cluster implies no access.";
const TOPICS =
  "Topics are derived from resource tags, names and access. They are not policy boundaries. Profiles and flags describe granted (structural) access, not what is needed or used.";

const clusters: ClusterMap = {
  revision: "rev-1",
  clusters: [],
  edges: [],
  warnings: [],
  view: {
    level: 0,
    total_nodes: 10,
    total_edges: 5,
    total_clusters: 0,
    clusters: 0,
    shown_clusters: 0,
    links: 0,
    shown_links: 0,
    edge_limit: 1000,
    isolated_nodes: 0,
    truncated: false,
    notice: STRUCTURAL,
  },
};
const topic = (
  id: string,
  label: string,
  extra: Partial<TopicSummary> = {},
): TopicSummary => ({
  id,
  name: label,
  label,
  kind: "anchored",
  reason: `Tagged topic=${label} on 1,200 assets; 300 more by name tokens`,
  resources: 4500,
  resource_weight: 21000,
  roles: 1500,
  identities: 4000,
  cross_grants_out: 2700,
  cross_grants_in: 2600,
  hub_grants_in: 1300,
  overprivileged_roles: 900,
  overprivileged_share: 0.6,
  cross_weight_share: 0.18,
  flags: {
    hub_roles: 1,
    privileged_roles: 30,
    cross_topic_roles: 880,
    restricted_outside_roles: 400,
    via_hub_identities: 500,
    privileged_identities: 700,
    cross_topic_identities: 900,
    restricted_outside_identities: 2500,
  },
  seeds: { tag: 1200, name: 300, coaccess: 50, metadata: 0, fallback: 0 },
  sensitivity: { confidential: 3000 },
  types: { S3Bucket: 2000 },
  ...extra,
});
const map: TopicMap = {
  revision: "rev-1",
  topics: [
    topic("t000000000000001", "data-lake"),
    topic("t000000000000002", "Unassigned S3 buckets", {
      kind: "fallback",
      resources: 300,
    }),
  ],
  edges: [
    { source: "t000000000000001", target: "t000000000000002", weight: 12 },
  ],
  summary: {
    basis: "granted (structural)",
    resources: 45000,
    cross_topic_grants: 27643,
    hub_roles: 3,
    cross_topic_roles: 8928,
    roles: 15000,
  },
  warnings: [],
  view: {
    total_topics: 2,
    shown_topics: 2,
    links: 1,
    shown_links: 1,
    edge_limit: 1000,
    truncated: false,
    basis: "granted (structural)",
    notice: TOPICS,
  },
};
const memberOf = (
  id: string,
  kind: TopicMember["kind"],
  extra: Partial<TopicMember> = {},
): TopicMember => ({
  id,
  name: id,
  type: kind === "role" ? "CloudRole" : "S3Bucket",
  kind,
  sensitivity: kind === "resource" ? "confidential" : "",
  seed: kind === "resource" ? "tag" : "",
  reason: kind === "resource" ? "tag topic=data-lake" : "",
  flags: [],
  direct_grants: 0,
  reach_resources: 0,
  reach_weight: 0,
  reach_weight_excl_hubs: 0,
  cross_topic_grants: 0,
  restricted_outside: 0,
  profile: [],
  ...extra,
});
const hub = memberOf("role:admin", "role", {
  flags: ["hub", "privileged"],
  direct_grants: 4500,
  reach_resources: 4500,
  reach_weight: 20000,
  reach_weight_excl_hubs: 0,
  profile: [{ topic_id: "t000000000000001", share: 0.25, resources: 900 }],
});
const detail = (
  kind: TopicMember["kind"],
  offset: number,
  members: TopicMember[],
  total: number,
): TopicDetail => ({
  revision: "rev-1",
  topic: map.topics[0],
  members,
  top_roles: [hub],
  view: {
    kind,
    total,
    offset,
    limit: 50,
    shown: members.length,
    next_offset:
      offset + members.length < total ? offset + members.length : null,
    truncated: true,
    basis: "granted (structural)",
    notice: TOPICS,
  },
});
let handler: (p: string) => unknown;
beforeEach(() => {
  vi.clearAllMocks();
  handler = (p) => {
    if (p.startsWith("graph/clusters?")) return clusters;
    if (p.startsWith("graph/topics?")) return map;
    const params = new URLSearchParams(p.split("?")[1]);
    const kind = params.get("kind") as TopicMember["kind"];
    const offset = Number(params.get("offset"));
    if (kind === "role")
      return detail("role", 0, [hub, memberOf("role:etl", "role")], 2);
    return detail(
      "resource",
      offset,
      Array.from({ length: offset ? 10 : 50 }, (_, i) =>
        memberOf(`bucket:${offset + i}`, "resource"),
      ),
      60,
    );
  };
  vi.mocked(api).mockImplementation(async (p) => handler(p) as never);
});

function renderMap(open = vi.fn()) {
  render(
    <GlobalMap
      reloadKey={0}
      stale={false}
      onError={vi.fn()}
      onOpenNeighborhood={open}
    />,
  );
  return open;
}

describe("topics lens", () => {
  it("switches lenses, keeps each notice to its own mode and counts with separators", async () => {
    renderMap();
    await screen.findByText(/0 \/ 0 top-level clusters/, VISIBLE);
    expect(screen.getAllByText(STRUCTURAL).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Topics" }));
    const status = await screen.findByText(/2 \/ 2 topics/);
    expect(api).toHaveBeenCalledWith(
      "graph/topics?edge_limit=1000",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(status).toHaveTextContent("45,000 data assets");
    expect(status).toHaveTextContent("27,643 cross-topic grants");
    expect(status).toHaveTextContent("3 hub roles");
    expect(status).toHaveTextContent("Complete map");
    expect(
      screen.getByText("Granted (structural) access, not usage"),
    ).toBeInTheDocument();
    expect(screen.getByText(TOPICS)).toBeInTheDocument();
    // Only the invisible bar sizer holds the structural notice in the Topics lens.
    expect(
      screen.queryByText(STRUCTURAL, {
        ignore: "script, style, [aria-hidden=true] *",
      }),
    ).toBeNull();
    expect(
      screen.getByText(
        "Topics are derived from tags, names and access, not policy boundaries",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("8,928 / 15,000")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Topics" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    fireEvent.click(screen.getByRole("button", { name: "Structure" }));
    await screen.findByText(/0 \/ 0 top-level clusters/, VISIBLE);
    expect(screen.queryByText(TOPICS)).toBeNull();
  });

  it("opens a topic panel with its reason, top roles and paged members, then hands off to explore", async () => {
    const open = renderMap();
    await screen.findAllByText(/top-level clusters/);
    fireEvent.click(screen.getByRole("button", { name: "Topics" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "data-lake · 4,500" }),
    );
    expect(api).toHaveBeenLastCalledWith(
      "graph/topics/t000000000000001?kind=resource&offset=0&limit=50&revision=rev-1",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    const panel = screen.getByRole("complementary", { name: "Topic details" });
    await within(panel).findByText("50 of 60 data assets shown");
    expect(panel).toHaveTextContent(
      "Tagged topic=data-lake on 1,200 assets; 300 more by name tokens",
    );
    expect(
      within(panel).getByText("Roles flagged").nextSibling,
    ).toHaveTextContent("900 (60%)");
    expect(
      within(panel).getByText("Weight outside topic").nextSibling,
    ).toHaveTextContent("18%");
    expect(panel).toHaveTextContent("Hub role, Privileged");
    fireEvent.click(
      within(panel).getByRole("button", { name: "Show 50 more" }),
    );
    await within(panel).findByText("60 of 60 data assets shown");
    expect(api).toHaveBeenLastCalledWith(
      "graph/topics/t000000000000001?kind=resource&offset=50&limit=50&revision=rev-1",
      expect.anything(),
    );
    expect(
      within(panel).queryByRole("button", { name: "Show 50 more" }),
    ).toBeNull();
    fireEvent.click(within(panel).getByRole("button", { name: "Roles" }));
    await within(panel).findByText("2 of 2 roles shown");
    fireEvent.click(
      within(panel).getAllByRole("button", { name: /role:admin/ })[0],
    );
    expect(
      within(panel).getByRole("list", { name: "Flags" }),
    ).toHaveTextContent("Hub rolePrivileged");
    expect(
      within(panel).getByText("Granted weight").nextSibling,
    ).toHaveTextContent("20,000");
    expect(
      within(panel).getByText("Without hub roles").nextSibling,
    ).toHaveTextContent("0");
    expect(within(panel).getByText("data-lake").nextSibling).toHaveTextContent(
      "25%",
    );
    fireEvent.click(
      within(panel).getByRole("button", { name: "Open neighborhood" }),
    );
    expect(open).toHaveBeenCalledWith("role:admin", "rev-1");
    fireEvent.click(
      within(panel).getByRole("button", { name: "Back to topic" }),
    );
    await within(panel).findByText("2 of 2 roles shown");
  });

  it("explains a revision without topics and retries", async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      handler = (p) => {
        if (p.startsWith("graph/clusters?")) return clusters;
        calls += 1;
        throw new ApiError(
          "Topics are not computed for this revision yet; the worker builds them within a few minutes",
          404,
        );
      };
      renderMap();
      await act(async () => {});
      fireEvent.click(screen.getByRole("button", { name: "Topics" }));
      await act(async () => {});
      expect(screen.getByText("Topics not available yet")).toBeInTheDocument();
      expect(calls).toBe(1);
      await act(async () => {
        vi.advanceTimersByTime(TOPICS_RETRY_MS);
      });
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("colors topics by weight outside them and sizes circles by sensitivity weight", () => {
    const low = topic("t1", "a", { cross_weight_share: 0.05 });
    const high = topic("t2", "b", { cross_weight_share: 0.5 });
    expect(topicColor(low)).toBe(SHARE_COLORS[0].color);
    expect(topicColor(high)).toBe(SHARE_COLORS[3].color);
    expect(topicColor(topic("t3", "c", { kind: "fallback" }))).toBe("#73849a");
    expect(topicCircle(low)).toMatchObject({
      id: "t1",
      size: 21000,
      member_count: 4500,
      boundary_edges: 5300,
    });
  });

  it("shows excess privilege, its basis and evidence when usage evidence exists", async () => {
    const aggregate = (epi: number, core: number, used = 10, inferred = 0) => ({
      granted_weight: 1000,
      needed_weight: Math.round(1000 * (1 - epi)),
      granted_weight_excl_hubs: 400,
      needed_weight_excl_hubs: Math.round(400 * (1 - core)),
      epi,
      epi_excl_hubs: core,
      basis: { used, inferred, none: 0 },
    });
    const privilege = {
      roles: aggregate(0.48, 0.45),
      identities: aggregate(0.98, 0.63, 30, 10),
      unused_grants: 97713,
      unused_restricted_grants: 21000,
      dormant_identities: 6097,
      dormant_roles: 4,
      dormant_role_hint_conflicts: 0,
    };
    const measured: TopicMap = {
      ...map,
      topics: [
        topic("t000000000000001", "data-lake", {
          privilege: { ...privilege, dormant_identities: 120 },
        }),
      ],
      summary: {
        ...map.summary,
        privilege: {
          ...privilege,
          evidence: {
            status: "attested",
            window_start: "2026-07-01T00:00:00+00:00",
            window_end: "2026-10-01T00:00:00+00:00",
            sufficient_services: ["s3", "sts"],
            sources: ["cloudtrail-export"],
          },
        },
      },
    };
    const role = memberOf("role:etl", "role", {
      reach_resources: 40,
      reach_weight: 200,
      reach_weight_excl_hubs: 200,
      basis: "used",
      needed_weight: 50,
      needed_weight_excl_hubs: 50,
      epi: 0.75,
      epi_excl_hubs: 0.75,
      used_resources: 9,
      unused_grants: 31,
      unused_restricted: 4,
      flags: ["dormant"],
    });
    handler = (p) => {
      if (p.startsWith("graph/clusters?")) return clusters;
      if (p.startsWith("graph/topics?")) return measured;
      return { ...detail("role", 0, [role], 1), topic: measured.topics[0] };
    };
    renderMap();
    await screen.findAllByText(/top-level clusters/);
    fireEvent.click(screen.getByRole("button", { name: "Topics" }));
    await screen.findByText(/1 \/ 2 topics|2 \/ 2 topics/);
    expect(
      screen.getByText("Granted vs needed · attested usage evidence"),
    ).toBeInTheDocument();
    const panel = screen.getByRole("complementary", { name: "Topic details" });
    expect(
      within(panel).getByText("Identities (without hubs)").nextSibling,
    ).toHaveTextContent("98% (63%)");
    expect(
      within(panel).getByText("Dormant identities").nextSibling,
    ).toHaveTextContent("6,097");
    expect(panel).toHaveTextContent(
      "RoleLastUsed and Access Advisor are hints only",
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "data-lake · 4,500" }),
    );
    expect(within(panel).getByText("Roles EPI").nextSibling).toHaveTextContent(
      "48%",
    );
    expect(
      within(panel).getByText("Identities EPI").nextSibling,
    ).toHaveTextContent("98%");
    expect(panel).toHaveTextContent("30 used · 10 inferred");
    fireEvent.click(within(panel).getByRole("button", { name: "Roles" }));
    const button = await within(panel).findByRole("button", {
      name: /role:etl/,
    });
    expect(button).toHaveTextContent(
      "Dormant (no observed use) · EPI 75% used",
    );
    fireEvent.click(button);
    expect(within(panel).getByText("EPI").nextSibling).toHaveTextContent(
      "75% (75% without hubs)",
    );
    expect(
      within(panel).getByText("Needed from").nextSibling,
    ).toHaveTextContent("Used (attested evidence)");
    expect(
      within(panel).getByText("Unused own grants").nextSibling,
    ).toHaveTextContent("31 (4 restricted)");
  });
});
