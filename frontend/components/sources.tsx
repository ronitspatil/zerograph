"use client";
import { useState } from "react";
import { RefreshCw } from "lucide-react";
import type { Job } from "@/lib/types";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { byteLength, INLINE_LIMIT_BYTES, uploadSnapshot } from "@/lib/upload";
function readText(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}
export function Sources({
  jobs,
  onRefresh,
  canAdmin,
}: {
  jobs: Job[];
  onRefresh: () => void;
  canAdmin: boolean;
}) {
  const [source, setSource] = useState("snapshot");
  const [payload, setPayload] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [fileText, setFileText] = useState<string | null>(null);
  async function submit() {
    setBusy(true);
    setError("");
    try {
      // Large graph snapshots go through a chunked upload session; the
      // single-body endpoint is limited to 4 MB by the proxy and API.
      const text =
        source === "snapshot" && fileText !== null ? fileText : payload;
      if (source === "snapshot" && byteLength(text) > INLINE_LIMIT_BYTES) {
        await uploadSnapshot(JSON.parse(text), (sent, total) =>
          setProgress(
            `Uploading chunk ${Math.min(sent + 1, total)} of ${total}`,
          ),
        );
      } else {
        await api("ingestions", {
          method: "POST",
          body: JSON.stringify({
            source,
            payload: source === "aws" ? {} : JSON.parse(text),
          }),
        });
      }
      setPayload("");
      setFileText(null);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ingestion failed");
    } finally {
      setBusy(false);
      setProgress("");
    }
  }
  async function loadFile(file: File | undefined) {
    setFileText(file ? await readText(file) : null);
  }
  return (
    <section>
      <div className="source-cards">
        <div className="panel">
          <h3>AWS account</h3>
          <p>
            Read-only IAM role and S3 metadata collection through an
            administrator-configured role.
          </p>
        </div>
        <div className="panel">
          <h3>AI agents & MCP</h3>
          <p>
            Import server inventories, agent configurations, and explicit
            tool-to-data bindings.
          </p>
        </div>
        <div className="panel">
          <h3>Graph snapshot</h3>
          <p>
            Import normalized identity and data relationships from your internal
            collectors.
          </p>
        </div>
      </div>
      <div className="panel form-panel">
        <div className="panel-heading">
          <h3>Start ingestion</h3>
          <span className="muted">Runs asynchronously in your tenant</span>
        </div>
        <label>
          Source
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="snapshot">Normalized graph snapshot</option>
            <option value="mcp">MCP / agent inventory</option>
            <option value="aws">Configured AWS connector</option>
          </select>
        </label>
        {source !== "aws" && (
          <label>
            JSON inventory
            <textarea
              rows={10}
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder={
                source === "mcp"
                  ? '{"mcpServers": {}, "agents": [], "bindings": {}}'
                  : '{"nodes": [], "edges": [], "source": "internal"}'
              }
              spellCheck={false}
            />
          </label>
        )}
        {source === "snapshot" && (
          <label>
            Snapshot file
            <input
              type="file"
              accept=".json,application/json"
              onChange={(e) => void loadFile(e.target.files?.[0])}
            />
            <small className="muted">
              Files over 3 MB upload in chunks (up to the configured node and
              edge limits).
            </small>
          </label>
        )}
        {progress && <p className="muted">{progress}</p>}
        {error && (
          <p role="alert" className="error-banner">
            {error}
          </p>
        )}
        <Button
          disabled={
            busy ||
            !canAdmin ||
            (source !== "aws" &&
              !payload &&
              !(source === "snapshot" && fileText))
          }
          onClick={submit}
        >
          {busy ? "Queuing…" : "Queue ingestion"}
        </Button>
      </div>
      <div className="panel history-panel">
        <div className="panel-heading">
          <h3>Collection history</h3>
          <Button variant="ghost" size="small" onClick={onRefresh}>
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
        </div>
        {jobs.length ? (
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th>Nodes</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td>
                    {j.source}
                    {j.error && <small className="job-error">{j.error}</small>}
                  </td>
                  <td>
                    <span
                      className={`status ${j.status === "completed" ? "ok" : j.status === "failed" ? "failed" : "pending"}`}
                    >
                      <i aria-hidden="true" />
                      {j.status}
                    </span>
                  </td>
                  <td>{j.node_count}</td>
                  <td>{new Date(j.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-line">No ingestion jobs yet.</p>
        )}
      </div>
    </section>
  );
}
