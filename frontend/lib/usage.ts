import { api } from "@/lib/api";
import type { UsageEvidence } from "@/lib/types";

/** Each export file is sent as one request body, below the 4 MB proxy and API limit. */
export const MAX_FILE_BYTES = 3_900_000;

export interface UsageUploadWindow {
  windowStart: string; // YYYY-MM-DD (UTC)
  windowEnd: string; // YYYY-MM-DD (UTC), inclusive
  attestedServices: string[];
}

export interface UsageCommit {
  id: string;
  status: string;
  revision: string;
  stats: {
    files: number;
    records: number;
    matched: number;
    pairs: number;
    unmapped: number;
    denied: number;
    outside_window: number;
    malformed: number;
    unresolved_principal: number;
    unresolved_resource: number;
    coverage: {
      service: string;
      attested: boolean;
      events: number;
      unmapped: number;
      complete: boolean;
    }[];
  };
  evidence: UsageEvidence;
  notice: string;
}

/** A file's bytes (FileReader: available wherever File is, unlike Blob.arrayBuffer). */
export function readBytes(file: Blob): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

/** ISO timestamps for a date range: start of the first day to the end of the last (UTC). */
export function windowBounds(window: UsageUploadWindow): [string, string] {
  const start = new Date(`${window.windowStart}T00:00:00Z`);
  const end = new Date(`${window.windowEnd}T23:59:59Z`);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()))
    throw new Error("Choose the first and last day the export covers");
  if (start >= end) throw new Error("The window must start before it ends");
  return [start.toISOString(), end.toISOString()];
}

/**
 * Upload CloudTrail export files (JSON or gzip, one request each) for a declared
 * window, then commit them. The worker recomputes privilege after the commit.
 */
export async function uploadUsage(
  files: File[],
  window: UsageUploadWindow,
  onProgress?: (sent: number, total: number) => void,
): Promise<UsageCommit> {
  if (!files.length)
    throw new Error("Choose at least one CloudTrail export file");
  const large = files.find((file) => file.size > MAX_FILE_BYTES);
  if (large)
    throw new Error(
      `${large.name} is larger than 3.9 MB; split the export into smaller files`,
    );
  const [start, end] = windowBounds(window);
  const upload = await api<{ id: string }>("usage/uploads", {
    method: "POST",
    body: JSON.stringify({
      window_start: start,
      window_end: end,
      attested_services: window.attestedServices,
    }),
  });
  for (const [index, file] of files.entries()) {
    onProgress?.(index, files.length);
    await api(`usage/uploads/${upload.id}/files/${index}`, {
      method: "PUT",
      body: await readBytes(file),
      headers: { "Content-Type": "application/octet-stream" },
    });
  }
  onProgress?.(files.length, files.length);
  return api<UsageCommit>(`usage/uploads/${upload.id}/commit`, {
    method: "POST",
  });
}
