"use client";
import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { api } from "@/lib/api";
import type { GraphNode, Simulation } from "@/lib/types";
import { Button } from "@/components/ui/button";
export function Simulator({
  node,
  onResult,
  onClose,
}: {
  node: GraphNode;
  onResult: (r: Simulation) => void;
  onClose: () => void;
}) {
  const [hops, setHops] = useState(3);
  const [uncertain, setUncertain] = useState(false);
  const [result, setResult] = useState<Simulation | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError("");
    const timer = setTimeout(() => {
      api<Simulation>("simulate", {
        method: "POST",
        signal: controller.signal,
        body: JSON.stringify({
          node_id: node.id,
          max_hops: hops,
          include_uncertain: uncertain,
        }),
      })
        .then((r) => {
          setResult(r);
          onResult(r);
        })
        .catch((e) => {
          if (!controller.signal.aborted) setError(e.message);
        })
        .finally(() => {
          if (!controller.signal.aborted) setBusy(false);
        });
    }, 200);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [node.id, hops, uncertain, onResult]);
  return (
    <aside className="simulator-drawer" aria-label="Blast radius simulator">
      <div className="drawer-heading">
        <span>Blast radius simulator</span>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="Close simulator"
        >
          <X size={16} />
        </button>
      </div>
      <span className="section-label">Compromise scenario</span>
      <h2 title={node.name}>{node.name}</h2>
      <p>
        Explore the downstream access available if this identity is compromised.
      </p>
      <div className="slider-label">
        <label htmlFor="hops">Traversal depth</label>
        <b>{hops} hops</b>
      </div>
      <input
        id="hops"
        type="range"
        min="1"
        max="5"
        value={hops}
        onChange={(e) => setHops(Number(e.target.value))}
      />
      <div className="range-labels">
        <span>Direct access</span>
        <span>Transitive access</span>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={uncertain}
          onChange={(e) => setUncertain(e.target.checked)}
        />
        Include conditional and declared access
      </label>
      {error && (
        <p role="alert" className="error-banner">
          {error}
        </p>
      )}
      <div className="simulation-score">
        <span>Blast radius score</span>
        <strong>
          {busy ? "…" : (result?.risk_score ?? "—")}
          <small>/100</small>
        </strong>
        <p>
          {uncertain
            ? "Potential exposure including unverified paths"
            : "Confirmed access paths only"}
        </p>
      </div>
      {result && (
        <>
          <div className="simulation-metrics">
            <div>
              <b>{result.affected_nodes.length}</b>
              <span>Reachable nodes</span>
            </div>
            <div>
              <b>{result.affected_assets.length}</b>
              <span>Data assets</span>
            </div>
          </div>
          <h3>Affected data assets</h3>
          {result.affected_assets.length ? (
            result.affected_assets.map((id) => (
              <div className="affected-asset" key={id}>
                <span title={id}>{id}</span>
              </div>
            ))
          ) : (
            <p>No data assets reachable within this depth.</p>
          )}
          <small className="score-explanation">{result.explanation}</small>
        </>
      )}
      <Button variant="outline" onClick={onClose}>
        Return to graph
      </Button>
    </aside>
  );
}
