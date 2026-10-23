"use client";
import { type ComponentType, type ReactNode, useEffect, useState } from "react";
import {
  Activity,
  Gauge,
  ListChecks,
  Radar,
  type LucideProps,
} from "lucide-react";
import { api } from "@/lib/api";
import { weekly } from "@/lib/activity";
import { formatCount, formatPercent } from "@/lib/format";
import { TIER_LABELS, TIERS } from "@/lib/proposals";
import {
  AreaChart,
  BarList,
  type BarItem,
  Donut,
  Legend,
  RingGauge,
  type Segment,
} from "@/components/charts";
import type {
  Overview,
  OverviewActivity,
  ProposalSummary,
  ProposalTier,
  TopicMap,
  UsageStatus,
} from "@/lib/types";

/** Tier colours: the same hues as the tier dots in the proposal queue. */
export const TIER_COLORS: Record<ProposalTier, string> = {
  high: "var(--accent)",
  medium: "var(--info)",
  low: "var(--warning)",
  inferred: "var(--violet)",
  manual: "var(--danger)",
};
const TOP_ROWS = 6;
const EVIDENCE_STATUS: Record<UsageStatus["evidence"]["status"], string> = {
  none: "None",
  partial: "Partial",
  attested: "Attested",
};

/** A section title with an icon and a hairline rule, like an instrument panel label. */
export function SectionHeader({
  icon: Icon,
  title,
  meta,
  id,
}: {
  icon: ComponentType<LucideProps>;
  title: string;
  meta?: ReactNode;
  id?: string;
}) {
  return (
    <div className="section-header">
      <h2 id={id}>
        <Icon size={14} aria-hidden="true" />
        {title}
      </h2>
      <span className="section-rule" aria-hidden="true" />
      {meta && <span className="section-meta">{meta}</span>}
    </div>
  );
}

/** undefined while loading, null when unavailable. */
function useResource<T>(path: string, reloadKey: number) {
  const [value, setValue] = useState<T | null | undefined>(undefined);
  useEffect(() => {
    const controller = new AbortController();
    setValue(undefined);
    api<T>(path, { signal: controller.signal }).then(
      (found) => {
        if (!controller.signal.aborted) setValue(found);
      },
      () => {
        if (!controller.signal.aborted) setValue(null);
      },
    );
    return () => controller.abort();
  }, [path, reloadKey]);
  return value;
}

function Kpi({
  label,
  value,
  caption,
  tone,
}: {
  label: string;
  value: string;
  caption: string;
  tone?: "danger" | "warning";
}) {
  return (
    <div className={tone ? `kpi kpi-${tone}` : "kpi"}>
      <span className="kpi-label">{label}</span>
      <strong className="kpi-value">{value}</strong>
      <small className="kpi-caption">{caption}</small>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="band-stat">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

/**
 * The overview dashboard: a band of grouped KPIs (exposure, excess privilege,
 * proposals by tier, usage evidence) and the least-privilege charts (excess
 * privilege and proposals by topic, observed use over the window). Every number
 * comes from the API; nothing is estimated. Each block keeps its size while it
 * loads or when its data is unavailable.
 */
export function Dashboard({
  overview,
  reloadKey,
}: {
  overview: Overview | null;
  reloadKey: number;
}) {
  const summary = useResource<ProposalSummary>("proposals/summary", reloadKey);
  const topics = useResource<TopicMap>("graph/topics?edge_limit=1", reloadKey);
  const activity = useResource<OverviewActivity>(
    "overview/activity",
    reloadKey,
  );
  const usage = useResource<UsageStatus>("usage", reloadKey);
  const dash = "—";
  const n = (value: number | undefined) =>
    overview ? formatCount(value) : dash;

  const tile = overview?.excess_privilege;
  const ready = !!tile && tile.status !== "none";
  const highAfter = summary?.high_tier.graph.identities.after.epi;

  const tierSegments: Segment[] = TIERS.map((tier) => ({
    key: tier,
    label: TIER_LABELS[tier],
    value: summary?.by_tier[tier] ?? 0,
    color: TIER_COLORS[tier],
  }));

  const services = Object.values(usage?.evidence.services ?? {});
  const sufficient = services.filter((s) => s.sufficient).length;
  const windowDays = services.reduce((m, s) => Math.max(m, s.days), 0);

  const labels = new Map(topics?.topics.map((t) => [t.id, t.label]) ?? []);
  const privilegeItems: BarItem[] = (topics?.topics ?? [])
    .filter((t) => (t.privilege?.unused_grants ?? 0) > 0)
    .sort(
      (a, b) =>
        (b.privilege?.unused_grants ?? 0) - (a.privilege?.unused_grants ?? 0),
    )
    .slice(0, TOP_ROWS)
    .map((t) => {
      const unused = t.privilege?.unused_grants ?? 0;
      const restricted = t.privilege?.unused_restricted_grants ?? 0;
      return {
        key: t.id,
        label: t.label,
        title: `${t.label}: ${formatCount(unused)} unused grants, ${formatCount(restricted)} on restricted data · identity EPI ${formatPercent(t.privilege?.identities.epi)}`,
        parts: [
          {
            key: "restricted",
            label: "on restricted data",
            value: restricted,
            color: "var(--danger)",
          },
          {
            key: "other",
            label: "other",
            value: unused - restricted,
            color: "var(--accent)",
          },
        ],
      };
    });
  const proposalItems: BarItem[] = Object.entries(summary?.topics ?? {})
    .sort(([, a], [, b]) => b.total - a.total)
    .slice(0, TOP_ROWS)
    .map(([id, stats]) => ({
      key: id,
      label: labels.get(id) ?? (id ? id : "No topic"),
      parts: TIERS.map((tier) => ({
        key: tier,
        label: TIER_LABELS[tier],
        value: stats.by_tier[tier] ?? 0,
        color: TIER_COLORS[tier],
      })),
    }));

  const weeks = activity ? weekly(activity.days) : [];
  const short = (day: string) => day.slice(5);

  return (
    <>
      <section className="dashboard-band" aria-label="Security posture">
        <div className="band-group band-exposure">
          <h3 className="band-title">
            <Radar size={13} aria-hidden="true" />
            Exposure
          </h3>
          <div className="kpi-grid">
            <Kpi
              label="Non-human identities"
              value={n(overview?.total_nhis)}
              caption="Roles, service accounts, agents"
            />
            <Kpi
              label="AI agents"
              value={n(overview?.ai_agents)}
              caption="Autonomous identities"
            />
            <Kpi
              label="Toxic combinations"
              value={n(overview?.toxic_combinations)}
              caption="Exposed paths to sensitive data"
              tone={overview?.toxic_combinations ? "danger" : undefined}
            />
            <Kpi
              label="High blast radius"
              value={n(overview?.high_blast_radius)}
              caption="Exposure score ≥ 70"
              tone={overview?.high_blast_radius ? "warning" : undefined}
            />
          </div>
        </div>
        <div className="band-group">
          <h3 className="band-title">
            <Gauge size={13} aria-hidden="true" />
            Excess privilege
          </h3>
          <div className="band-visual">
            <RingGauge
              value={ready ? tile.identities.epi : null}
              label="Identity excess privilege index"
              center={ready ? formatPercent(tile.identities.epi) : dash}
              caption="not needed"
              color="var(--warning)"
            />
            <div className="band-stats">
              <Stat
                label="Without hub roles"
                value={
                  ready ? formatPercent(tile.identities.epi_excl_hubs) : dash
                }
              />
              <Stat label="After high tier" value={formatPercent(highAfter)} />
              <Stat
                label="Dormant identities"
                value={ready ? formatCount(tile.dormant_identities) : dash}
              />
            </div>
          </div>
        </div>
        <div className="band-group">
          <h3 className="band-title">
            <ListChecks size={13} aria-hidden="true" />
            Proposals by tier
          </h3>
          <div className="band-visual">
            <Donut
              segments={tierSegments}
              label="Least-privilege proposals by tier"
              center={summary ? formatCount(summary.total) : dash}
              caption="proposals"
            />
            <Legend
              segments={tierSegments}
              format={(v) => (summary ? formatCount(v) : dash)}
            />
          </div>
        </div>
        <div className="band-group">
          <h3 className="band-title">
            <Activity size={13} aria-hidden="true" />
            Usage evidence
          </h3>
          <div className="band-visual">
            <RingGauge
              value={services.length ? sufficient / services.length : null}
              label="Services with sufficient usage evidence"
              center={usage ? `${sufficient}/${services.length}` : dash}
              caption="sufficient"
            />
            <div className="band-stats">
              <Stat
                label="Status"
                value={usage ? EVIDENCE_STATUS[usage.evidence.status] : dash}
              />
              <Stat
                label="Window"
                value={
                  usage && windowDays ? `${formatCount(windowDays)} days` : dash
                }
              />
              <Stat
                label="Observed pairs"
                value={
                  usage ? formatCount(usage.evidence.observed_pairs) : dash
                }
              />
            </div>
          </div>
        </div>
      </section>
      <SectionHeader
        icon={Gauge}
        title="Least privilege"
        meta="What-if analysis · nothing is applied"
      />
      <div className="dashboard-charts">
        <div className="panel chart-card">
          <div className="chart-card-head">
            <h3>Excess privilege by topic</h3>
            <span className="muted">Unused grants</span>
          </div>
          <BarList
            items={privilegeItems}
            rows={TOP_ROWS}
            label="Unused grants by topic"
            loading={topics === undefined}
            empty={topics === null ? "Topics unavailable" : "No unused grants"}
          />
          <div className="chart-card-foot">
            <span className="swatch" style={{ background: "var(--danger)" }} />
            On restricted data
            <span className="swatch" style={{ background: "var(--accent)" }} />
            Other
          </div>
        </div>
        <div className="panel chart-card">
          <div className="chart-card-head">
            <h3>Proposals by topic</h3>
            <span className="muted">By tier</span>
          </div>
          <BarList
            items={proposalItems}
            rows={TOP_ROWS}
            label="Proposals by topic and tier"
            loading={summary === undefined}
            empty={summary === null ? "Proposals unavailable" : "No proposals"}
          />
          <div className="chart-card-foot">
            {TIERS.map((tier) => (
              <span key={tier} className="foot-item">
                <span
                  className="swatch"
                  style={{ background: TIER_COLORS[tier] }}
                />
                {TIER_LABELS[tier]}
              </span>
            ))}
          </div>
        </div>
        <div className="panel chart-card">
          <div className="chart-card-head">
            <h3>Observed use</h3>
            <span className="muted">Per week</span>
          </div>
          <div className="activity-figures">
            <div>
              <b>{activity ? formatCount(activity.identities) : dash}</b>
              <span>
                <i className="swatch" style={{ background: "var(--accent)" }} />
                identities by last use
              </span>
            </div>
            <div>
              <b>{activity ? formatCount(activity.pairs) : dash}</b>
              <span>
                <i className="swatch line" />
                access pairs by first use
              </span>
            </div>
          </div>
          <div
            className={
              activity === undefined
                ? "activity-plot skeleton-block"
                : "activity-plot"
            }
          >
            {weeks.length > 0 ? (
              <AreaChart
                label="Identities by week of last observed use"
                series={weeks.map((w) => ({
                  label: w.start,
                  value: w.identities,
                }))}
                secondary={weeks.map((w) => ({
                  label: w.start,
                  value: w.pairs,
                }))}
                height={112}
              />
            ) : (
              activity !== undefined && (
                <p className="chart-empty">
                  {activity === null
                    ? "Observed use unavailable"
                    : "Upload a CloudTrail export in Data sources to see observed use."}
                </p>
              )
            )}
          </div>
          <div className="chart-axis" aria-hidden="true">
            <span>{weeks.length ? short(weeks[0].start) : ""}</span>
            <span>
              {weeks.length > 2
                ? short(weeks[Math.floor(weeks.length / 2)].start)
                : ""}
            </span>
            <span>
              {weeks.length > 1 ? short(weeks[weeks.length - 1].start) : ""}
            </span>
          </div>
        </div>
      </div>
    </>
  );
}
