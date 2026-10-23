"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { formatCount } from "@/lib/format";
import type { UsageStatus } from "@/lib/types";
import { type UsageCommit, uploadUsage } from "@/lib/usage";
import { Button } from "@/components/ui/button";
import { FilePicker } from "@/components/ui/file-picker";
import { EVIDENCE_LABELS, windowText } from "@/components/privilege";

/** Services a customer can attest complete CloudTrail coverage for. */
export const USAGE_SERVICES = [
  "s3",
  "sts",
  "glue",
  "athena",
  "lakeformation",
  "rds-data",
  "aoss",
];
const DAY = 86_400_000;
const isoDay = (time: number) => new Date(time).toISOString().slice(0, 10);

/**
 * CloudTrail export upload (admins): declare the window and the services whose
 * events the files completely capture, send the files, and show the coverage the
 * upload established. Observed use only counts as needed access where coverage is
 * attested, complete and long enough; everything else stays "inferred".
 */
export function UsageUpload({
  canAdmin,
  now = Date.now(),
}: {
  canAdmin: boolean;
  now?: number;
}) {
  const [status, setStatus] = useState<UsageStatus | null>(null);
  const [windowStart, setWindowStart] = useState(isoDay(now - 91 * DAY));
  const [windowEnd, setWindowEnd] = useState(isoDay(now - DAY));
  const [services, setServices] = useState<string[]>(["s3", "sts"]);
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<UsageCommit | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    api<UsageStatus>("usage", { signal: controller.signal })
      .then((s) => !controller.signal.aborted && setStatus(s))
      .catch(() => {});
    return () => controller.abort();
  }, [result]);

  const toggle = (service: string) =>
    setServices((list) =>
      list.includes(service)
        ? list.filter((s) => s !== service)
        : [...list, service].sort(),
    );

  async function submit() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const committed = await uploadUsage(
        files,
        { windowStart, windowEnd, attestedServices: services },
        (sent, total) =>
          setProgress(
            sent < total
              ? `Uploading file ${formatCount(sent + 1)} of ${formatCount(total)}`
              : "Committing…",
          ),
      );
      setResult(committed);
      setFiles([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Usage upload failed");
    } finally {
      setBusy(false);
      setProgress("");
    }
  }

  const evidence = result?.evidence ?? status?.evidence;
  return (
    <div className="panel form-panel usage-panel">
      <div className="panel-heading">
        <h3>Usage evidence</h3>
        <span className="muted">
          {evidence ? EVIDENCE_LABELS[evidence.status] : "Loading…"}
        </span>
      </div>
      <p className="muted usage-intro">
        CloudTrail export files (JSON or .json.gz, as delivered to S3). Attest
        only services the files capture completely for the whole window.
      </p>
      <div className="two-columns">
        <label>
          First day
          <input
            type="date"
            value={windowStart}
            onChange={(e) => setWindowStart(e.target.value)}
          />
        </label>
        <label>
          Last day
          <input
            type="date"
            value={windowEnd}
            onChange={(e) => setWindowEnd(e.target.value)}
          />
        </label>
      </div>
      <fieldset className="usage-services">
        <legend>Complete coverage attested for</legend>
        {USAGE_SERVICES.map((service) => (
          <label key={service}>
            <input
              type="checkbox"
              checked={services.includes(service)}
              onChange={() => toggle(service)}
            />
            {service}
          </label>
        ))}
      </fieldset>
      <FilePicker
        label="CloudTrail export files"
        multiple
        accept=".json,.gz,application/json,application/gzip"
        hint="Up to 3.9 MB per file. Use counts as evidence with 90 days of attested coverage ending in the last 7 days; otherwise need is inferred from peers."
        onFiles={setFiles}
      />
      {progress && <p className="muted">{progress}</p>}
      {error && (
        <p role="alert" className="error-banner">
          {error}
        </p>
      )}
      <Button
        variant="outline"
        disabled={busy || !canAdmin || !files.length}
        onClick={submit}
      >
        {busy ? "Uploading…" : "Upload usage evidence"}
      </Button>
      {result && (
        <div className="usage-result" role="status">
          <span className="section-label">Upload committed</span>
          <p>
            {formatCount(result.stats.records)} records ·{" "}
            {formatCount(result.stats.matched)} matched ·{" "}
            {formatCount(result.stats.pairs)} observed access pairs ·{" "}
            {formatCount(result.stats.unmapped)} unmapped ·{" "}
            {formatCount(result.stats.denied)} denied
          </p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Attested</th>
                  <th className="num">Events</th>
                  <th className="num">Unmapped</th>
                  <th>Coverage</th>
                </tr>
              </thead>
              <tbody>
                {result.stats.coverage.map((row) => (
                  <tr key={row.service}>
                    <td>{row.service}</td>
                    <td>{row.attested ? "Yes" : "No"}</td>
                    <td className="num">{formatCount(row.events)}</td>
                    <td className="num">{formatCount(row.unmapped)}</td>
                    <td>{row.complete ? "Complete" : "Incomplete"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <small>
            Privilege is recomputed for the current revision within a few
            minutes. {result.notice}
          </small>
        </div>
      )}
      {!result && evidence && evidence.status !== "none" && (
        <div className="usage-result">
          <span className="section-label">Current evidence</span>
          <p>
            {windowText(evidence)} · {formatCount(evidence.observed_pairs ?? 0)}{" "}
            observed access pairs · sufficient for{" "}
            {evidence.sufficient_services?.length
              ? evidence.sufficient_services.join(", ")
              : "no service yet"}
          </p>
        </div>
      )}
    </div>
  );
}
