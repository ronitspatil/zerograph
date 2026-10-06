"use client";
import { useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { api } from "@/lib/api";
import { formatCount } from "@/lib/format";
import type { GraphNode, Preview, Remediation } from "@/lib/types";
import { Button } from "@/components/ui/button";
const examplePolicy = JSON.stringify(
  {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        Resource: "arn:aws:s3:::example-bucket/*",
      },
    ],
  },
  null,
  2,
);
export function RemediationHub({
  identities,
  records,
  onRefresh,
  demo,
  canWrite,
  canAdmin,
}: {
  identities: GraphNode[];
  records: Remediation[];
  onRefresh: () => void;
  demo: boolean;
  canWrite: boolean;
  canAdmin: boolean;
}) {
  const [identity, setIdentity] = useState(identities[0]?.id || "");
  const [policy, setPolicy] = useState(demo ? examplePolicy : "");
  const [usage, setUsage] = useState(demo ? "s3:GetObject" : "");
  const [services, setServices] = useState(demo ? "s3" : "");
  const [start, setStart] = useState(
    new Date(Date.now() - 100 * 86400000).toISOString().slice(0, 10),
  );
  const [end, setEnd] = useState(
    new Date(Date.now() - 86400000).toISOString().slice(0, 10),
  );
  const [complete, setComplete] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pr, setPr] = useState("");
  async function generate() {
    setBusy(true);
    setError("");
    setPreview(null);
    setPr("");
    try {
      const result = await api<Preview>("remediations/preview", {
        method: "POST",
        body: JSON.stringify({
          identity_id: identity,
          policy: JSON.parse(policy),
          usage: {
            window_start: `${start}T00:00:00Z`,
            window_end: `${end}T00:00:00Z`,
            used_actions: usage.split(/[\s,]+/).filter(Boolean),
            covered_services: services.split(/[\s,]+/).filter(Boolean),
            complete,
            source: demo
              ? "synthetic-demo"
              : "operator-supplied-cloudtrail-export",
          },
        }),
      });
      setPreview(result);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Preview failed");
    } finally {
      setBusy(false);
    }
  }
  async function openPR() {
    if (!preview) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<{ url: string }>(
        `remediations/${preview.id}/pr`,
        { method: "POST" },
      );
      setPr(result.url);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "PR creation failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="remediation-page">
      {demo && (
        <div className="notice">
          The sample policy and action history below are synthetic. Connect real
          audit evidence before proposing production changes.
        </div>
      )}
      <div className="remediation-grid">
        <div className="panel form-panel">
          <div className="panel-heading">
            <h3>Policy optimization</h3>
            <span className="muted">Proposals require review</span>
          </div>
          <label>
            Identity
            <select
              value={identity}
              onChange={(e) => {
                setIdentity(e.target.value);
                setPreview(null);
              }}
            >
              {identities.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Original IAM policy
            <textarea
              rows={12}
              value={policy}
              onChange={(e) => {
                setPolicy(e.target.value);
                setPreview(null);
              }}
              placeholder="Paste an IAM JSON policy"
              spellCheck={false}
            />
          </label>
          <div className="two-columns">
            <label>
              Observation start
              <input
                type="date"
                value={start}
                onChange={(e) => {
                  setStart(e.target.value);
                  setPreview(null);
                }}
              />
            </label>
            <label>
              Observation end
              <input
                type="date"
                value={end}
                onChange={(e) => {
                  setEnd(e.target.value);
                  setPreview(null);
                }}
              />
            </label>
          </div>
          <label>
            Observed IAM actions
            <textarea
              rows={2}
              value={usage}
              onChange={(e) => {
                setUsage(e.target.value);
                setPreview(null);
              }}
              placeholder="s3:GetObject, s3:ListBucket"
            />
          </label>
          <label>
            Services with complete event coverage
            <input
              value={services}
              onChange={(e) => {
                setServices(e.target.value);
                setPreview(null);
              }}
              placeholder="s3, dynamodb"
            />
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={complete}
              onChange={(e) => {
                setComplete(e.target.checked);
                setPreview(null);
              }}
            />
            I verified complete coverage, including data events
          </label>
          <small className="muted">
            At least 90 days of recent, complete evidence is required. Wildcard
            actions, conditional grants, and deny statements are preserved.
          </small>
          {error && (
            <p role="alert" className="error-banner">
              {error}
            </p>
          )}
          <Button
            onClick={generate}
            disabled={busy || !identity || !policy || !canWrite}
          >
            {busy ? "Working…" : "Generate least-privilege preview"}
          </Button>
        </div>
        <div className="panel diff-panel">
          <div className="panel-heading">
            <h3>Policy diff</h3>
          </div>
          {preview ? (
            <>
              <div className="diff-summary">
                <strong>
                  {formatCount(preview.optimization.removed_actions.length)}{" "}
                  actions removed
                </strong>
                <span className="muted">Proposal only</span>
              </div>
              <pre className="policy-diff">
                {preview.optimization.diff
                  ? preview.optimization.diff.split("\n").map((line, i) => (
                      <span
                        key={i}
                        className={
                          line.startsWith("+")
                            ? "diff-added"
                            : line.startsWith("-")
                              ? "diff-removed"
                              : ""
                        }
                      >
                        {line}
                        {"\n"}
                      </span>
                    ))
                  : "No safe reduction found with the supplied evidence."}
              </pre>
              <details>
                <summary>Why permissions were retained</summary>
                {preview.optimization.retained_reasons.map((r, i) => (
                  <p key={i}>{r}</p>
                ))}
              </details>
              <div className="diff-actions">
                <Button
                  onClick={openPR}
                  disabled={
                    busy ||
                    !canAdmin ||
                    !preview.optimization.removed_actions.length
                  }
                >
                  Generate least-privilege PR
                </Button>
                <Button variant="outline" asChild>
                  <a
                    href={`/api/zg/remediations/${preview.id}/terraform`}
                    download="zerograph-policy.tf"
                  >
                    Export Terraform
                  </a>
                </Button>
              </div>
              {pr && (
                <a
                  className="text-link"
                  href={pr}
                  target="_blank"
                  rel="noreferrer"
                >
                  Review pull request
                  <ArrowUpRight size={14} />
                </a>
              )}
            </>
          ) : (
            <div className="empty-state">
              <h3>No proposal yet</h3>
              <p>
                Supply a policy and audit observation window to compare the
                original and proposed permissions.
              </p>
            </div>
          )}
        </div>
      </div>
      <div className="panel history-panel">
        <div className="panel-heading">
          <h3>Recent proposals</h3>
          <span className="muted">{formatCount(records.length)} proposals</span>
        </div>
        {records.length ? (
          <table>
            <thead>
              <tr>
                <th>Identity</th>
                <th>Actions removed</th>
                <th>Status</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.id}>
                  <td>
                    {identities.find((n) => n.id === r.identity_id)?.name ||
                      r.identity_id}
                  </td>
                  <td>{formatCount(r.removed_actions.length)}</td>
                  <td>{r.status.replaceAll("_", " ")}</td>
                  <td>
                    {r.pr_url ? (
                      <a
                        className="text-link"
                        href={r.pr_url}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Open PR
                        <ArrowUpRight size={12} aria-hidden="true" />
                      </a>
                    ) : (
                      "Preview"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-line">No remediation proposals yet.</p>
        )}
      </div>
    </section>
  );
}
