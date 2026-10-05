import { api } from "@/lib/api";
import type { Job } from "@/lib/types";

// Each chunk must stay below the 4 MB proxy and API body limits.
export const CHUNK_BYTES = 3_500_000;
// Snapshots larger than this use a chunked upload session instead of one body.
export const INLINE_LIMIT_BYTES = 3_000_000;

export interface SnapshotDocument {
  nodes?: unknown[];
  edges?: unknown[];
  warnings?: unknown[];
}

interface UploadSession {
  id: string;
}

const encoder = new TextEncoder();

export function byteLength(text: string): number {
  return encoder.encode(text).byteLength;
}

/** NDJSON lines in submission order: nodes, then edges, then warnings. */
export function* snapshotLines(snapshot: SnapshotDocument): Generator<string> {
  for (const node of snapshot.nodes ?? []) yield JSON.stringify({ node });
  for (const edge of snapshot.edges ?? []) yield JSON.stringify({ edge });
  for (const warning of snapshot.warnings ?? [])
    yield JSON.stringify({ warning });
}

/** Pack lines into NDJSON chunks of at most ``maxBytes`` UTF-8 bytes. */
export function packChunks(
  lines: Iterable<string>,
  maxBytes: number = CHUNK_BYTES,
): string[] {
  const chunks: string[] = [];
  let current: string[] = [];
  let size = 0;
  for (const line of lines) {
    const bytes = byteLength(line) + 1;
    if (bytes > maxBytes)
      throw new Error("A single graph entity exceeds the chunk size");
    if (size + bytes > maxBytes && current.length) {
      chunks.push(current.join("\n") + "\n");
      current = [];
      size = 0;
    }
    current.push(line);
    size += bytes;
  }
  if (current.length) chunks.push(current.join("\n") + "\n");
  return chunks;
}

/** Upload a snapshot through a chunked session, then queue its publication. */
export async function uploadSnapshot(
  snapshot: SnapshotDocument,
  onProgress?: (sent: number, total: number) => void,
): Promise<Job> {
  const extra = Object.keys(snapshot).filter(
    (key) => !["nodes", "edges", "warnings", "source"].includes(key),
  );
  if (extra.length) throw new Error("Snapshot contains unsupported fields");
  const chunks = packChunks(snapshotLines(snapshot));
  const session = await api<UploadSession>("ingestions/uploads", {
    method: "POST",
    body: JSON.stringify({ source: "snapshot" }),
  });
  for (const [index, chunk] of chunks.entries()) {
    onProgress?.(index, chunks.length);
    await api(`ingestions/uploads/${session.id}/chunks/${index}`, {
      method: "PUT",
      body: chunk,
      headers: { "Content-Type": "application/x-ndjson" },
    });
  }
  onProgress?.(chunks.length, chunks.length);
  return api<Job>(`ingestions/uploads/${session.id}/commit`, {
    method: "POST",
  });
}
