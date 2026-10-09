"use client";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { formatCount } from "@/lib/format";
import type { RolloutChange, RolloutList, RolloutState } from "@/lib/types";
import { Button } from "@/components/ui/button";

const STATE_LABELS: Record<RolloutState, string> = {
  draft: "Draft",
  pr_open: "PR open",
  merged: "Canary watch",
  verified: "Verified",
  revert_open: "Revert open",
  rolled_back: "Rolled back",
};

/** Short state text: held drafts wait for their topic's canary; merged changes count down. */
export function rolloutStatus(change: RolloutChange): string {
  if (change.state === "draft" && change.held) return "Waiting for canary";
  if (change.state === "merged") {
    const days = change.watch_remaining_days ?? change.watch_days;
    return `${change.canary ? "Canary watch" : "Watch"} · ${days.toFixed(1)} d left`;
  }
  return STATE_LABELS[change.state];
}

function host(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.pathname.replace(/^\//, "");
  } catch {
    return url;
  }
}

/**
 * Rollout of accepted proposals: one draft pull request per role (or a topic bundle), the
 * topic's canary, its AccessDenied watch and one-click revert pull requests. ZeroGraph never
 * applies or merges anything; merging happens in the customer's repository.
 */
export function Rollout({
  canAdmin,
  refreshKey = 0,
}: {
  canAdmin: boolean;
  refreshKey?: number;
}) {
  const [list, setList] = useState<RolloutList | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    try {
      setList(await api<RolloutList>("rollout"));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rollout failed");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  const act = async (
    change: RolloutChange,
    action: "pr" | "merged" | "revert" | "reverted" | "discard",
  ) => {
    setBusy(`${change.id}:${action}`);
    setError("");
    setMessage("");
    try {
      if (action === "discard") {
        await fetch(`/api/zg/rollout/changes/${change.id}`, {
          method: "DELETE",
          cache: "no-store",
        }).then((response) => {
          if (!response.ok) throw new Error("Discard failed");
        });
        setMessage(`Discarded the draft for ${change.subject_name}.`);
      } else {
        const result = await api<{ warning?: string }>(
          `rollout/changes/${change.id}/${action}`,
          {
            method: "POST",
            body: action === "revert" ? JSON.stringify({}) : undefined,
          },
        );
        const done = {
          pr: `Draft pull request opened for ${change.subject_name}.`,
          merged: `Recorded as merged; the ${change.watch_days}-day AccessDenied watch started.`,
          revert: `Revert pull request opened for ${change.subject_name} (draft; never merged by ZeroGraph).`,
          reverted: `Recorded as rolled back.`,
        }[action];
        setMessage(result?.warning ? `${done} Warning: ${result.warning}` : done);
      }
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(null);
    }
  };

  const changes = list?.changes ?? [];
  return (
    <section className="rollout-panel" aria-label="Rollout">
      <div className="notice rollout-notice">
        <b>Nothing is applied by ZeroGraph.</b> Each change is a draft pull
        request in your policy repository; merging happens there. Per topic, the
        first role is the canary: the others wait until it is merged and{" "}
        {list ? list.watch_days : 7} days pass without AccessDenied events.
      </div>
      {list && !list.gitops_configured && (
        <div className="notice rollout-warning">
          No policy repository is configured for this workspace; pull requests
          cannot be opened.
        </div>
      )}
      <div className="rollout-status" role="status" aria-live="polite">
        {error ? (
          <span className="rollout-error" title={error}>
            {error}
          </span>
        ) : (
          <span title={message || undefined}>
            {message ||
              (list
                ? `${formatCount(changes.length)} change${changes.length === 1 ? "" : "s"}`
                : "Loading")}
          </span>
        )}
      </div>
      <div className="panel rollout-list">
        {list && !changes.length && (
          <p className="empty-line">
            No changes yet. Accept proposals, then use Create PR in a
            proposal&apos;s evidence panel.
          </p>
        )}
        {changes.map((change) => (
          <article key={change.id} className="rollout-row">
            <div className="rollout-main">
              <span
                className={`rollout-state rollout-${change.held ? "held" : change.state}`}
              >
                {rolloutStatus(change)}
              </span>
              <b title={change.subject_id}>
                {change.scope === "topic" ? "Topic bundle · " : ""}
                {change.subject_name}
              </b>
              <small>
                {change.canary ? "Canary · " : ""}
                {formatCount(change.proposal_count)} proposal
                {change.proposal_count === 1 ? "" : "s"} ·{" "}
                {formatCount(change.files.length)} file
                {change.files.length === 1 ? "" : "s"}
                {change.draft_count
                  ? ` · ${formatCount(change.draft_count)} draft only`
                  : ""}
              </small>
              {change.held && (
                <small className="rollout-reason" title={change.held_reason}>
                  {change.held_reason}
                </small>
              )}
              {change.flag && (
                <small className="rollout-flag">
                  AccessDenied after merge: {formatCount(change.flag.events)}{" "}
                  event{change.flag.events === 1 ? "" : "s"}
                </small>
              )}
              {change.revert_error && !change.revert_pr_url && (
                <small className="rollout-flag" title={change.revert_error}>
                  Revert failed: {change.revert_error}
                </small>
              )}
            </div>
            <div className="rollout-links">
              {change.pr_url ? (
                <a href={change.pr_url} target="_blank" rel="noreferrer">
                  {host(change.pr_url)}
                </a>
              ) : (
                <small>No pull request yet</small>
              )}
              {change.revert_pr_url && (
                <a href={change.revert_pr_url} target="_blank" rel="noreferrer">
                  Revert: {host(change.revert_pr_url)}
                </a>
              )}
            </div>
            <div className="rollout-actions">
              {change.state === "draft" && (
                <>
                  <Button
                    size="small"
                    disabled={!canAdmin || change.held || busy !== null}
                    onClick={() => void act(change, "pr")}
                  >
                    Open PR
                  </Button>
                  <Button
                    size="small"
                    variant="outline"
                    disabled={!canAdmin || change.pr_requested || busy !== null}
                    onClick={() => void act(change, "discard")}
                  >
                    Discard
                  </Button>
                </>
              )}
              {change.state === "pr_open" && (
                <Button
                  size="small"
                  variant="outline"
                  disabled={!canAdmin || busy !== null}
                  onClick={() => void act(change, "merged")}
                >
                  Mark merged
                </Button>
              )}
              {(change.state === "merged" ||
                change.state === "verified" ||
                (change.state === "revert_open" && !change.revert_pr_url)) && (
                <Button
                  size="small"
                  variant="outline"
                  disabled={!canAdmin || busy !== null}
                  onClick={() => void act(change, "revert")}
                >
                  Open revert PR
                </Button>
              )}
              {change.state === "revert_open" && change.revert_pr_url && (
                <Button
                  size="small"
                  variant="outline"
                  disabled={!canAdmin || busy !== null}
                  onClick={() => void act(change, "reverted")}
                >
                  Mark reverted
                </Button>
              )}
            </div>
          </article>
        ))}
      </div>
      <small className="proposal-footnote">
        {canAdmin
          ? "Mark merged and Mark reverted record what happened in your repository. A revert restores the original policies byte for byte."
          : "Administrators open pull requests and record merges."}
      </small>
    </section>
  );
}
