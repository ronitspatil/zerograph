import type { LayoutInput, Position } from "./graph-layout";

/** Nearest role over real edges; account boundaries and other role seeds stay separate. */
export function partitionCommunities(data: LayoutInput): string[][] {
  const ids = [...data.nodes].sort();
  const present = new Set(ids);
  const adjacent = new Map(ids.map((id) => [id, new Set<string>()]));
  for (const edge of data.edges) {
    if (!present.has(edge.source) || !present.has(edge.target)) continue;
    adjacent.get(edge.source)!.add(edge.target);
    adjacent.get(edge.target)!.add(edge.source);
  }
  const account = (id: string) => data.attributes?.[id]?.account || "";
  const compatible = (a: string, b: string) =>
    !account(a) || !account(b) || account(a) === account(b);
  const owners = new Map<string, string>();
  const roles = ids.filter((id) => data.attributes?.[id]?.type === "CloudRole");
  const queue: string[] = [];
  for (const id of roles) {
    owners.set(id, id);
    queue.push(id);
  }
  // Multi-source BFS: roles sorted once gives deterministic ties, O(nodes + edges).
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const id = queue[cursor],
      anchor = owners.get(id)!;
    for (const neighbor of [...adjacent.get(id)!].sort()) {
      if (owners.has(neighbor) || !compatible(anchor, neighbor)) continue;
      owners.set(neighbor, anchor);
      queue.push(neighbor);
    }
  }
  // Remaining connected components are real topology, never name/ID-derived clusters.
  for (const seed of ids) {
    if (owners.has(seed)) continue;
    const pending = [seed];
    owners.set(seed, seed);
    for (let cursor = 0; cursor < pending.length; cursor++) {
      for (const neighbor of [...adjacent.get(pending[cursor])!].sort()) {
        if (owners.has(neighbor) || !compatible(seed, neighbor)) continue;
        owners.set(neighbor, seed);
        pending.push(neighbor);
      }
    }
  }
  const groups = new Map<string, string[]>();
  for (const id of ids) {
    const anchor = owners.get(id)!;
    if (!groups.has(anchor)) groups.set(anchor, [anchor]);
    if (id !== anchor) groups.get(anchor)!.push(id);
  }
  return [...groups.entries()]
    .sort(
      ([a], [b]) => account(a).localeCompare(account(b)) || a.localeCompare(b),
    )
    .map(([, nodes]) => nodes);
}

function noise(seed: string): number {
  let hash = 2166136261;
  for (const char of seed)
    hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  hash = Math.imul(hash ^ (hash >>> 16), 0x7feb352d);
  hash = Math.imul(hash ^ (hash >>> 15), 0x846ca68b);
  return (((hash ^ (hash >>> 16)) >>> 0) / 0xffffffff) * 2 - 1;
}

/** Spacious role-centered constellations on the worker, not a global permission analysis. */
export function computePositions(data: LayoutInput): Position[] {
  if (data.nodes.length > 500 || data.edges.length > 2000) return [];
  const groups = partitionCommunities(data);
  const order = [
    "AIAgent",
    "MCPServer",
    "HumanUser",
    "ServiceAccount",
    "CloudRole",
    "Database",
    "S3Bucket",
    "VectorStore",
    "DataCategory",
  ];
  const radius = (count: number) =>
    count <= 1 ? 0 : 42 + 26 * Math.floor((count - 2) / 16);
  const cell = Math.max(
    150,
    ...groups.map((group) => radius(group.length) * 2 + 100),
  );
  const columns = Math.max(1, Math.ceil(Math.sqrt(groups.length * 1.45)));
  const positions: Position[] = [];
  groups.forEach(([anchor, ...neighbors], index) => {
    const cx = (index % columns) * cell + noise(`${anchor}:x`) * cell * 0.065,
      cy =
        Math.floor(index / columns) * cell +
        noise(`${anchor}:y`) * cell * 0.065;
    positions.push({ id: anchor, x: cx, y: cy });
    neighbors.sort((a, b) => {
      const rank = (id: string) => {
        const r = order.indexOf(data.attributes?.[id]?.type || "");
        return r < 0 ? order.length : r;
      };
      return rank(a) - rank(b) || a.localeCompare(b);
    });
    neighbors.forEach((id, i) => {
      const ring = Math.floor(i / 16),
        offset = i % 16,
        size = Math.min(16, neighbors.length - ring * 16);
      const angle = -Math.PI / 2 + (offset * 2 * Math.PI) / size + ring * 0.17;
      const r = (42 + ring * 26) * (1 + noise(`${id}:radius`) * 0.07);
      positions.push({
        id,
        x: cx + r * Math.cos(angle),
        y: cy + r * Math.sin(angle),
      });
    });
  });
  // Bound even pathological singleton-heavy views without collapsing either dimension.
  const xs = positions.map((p) => p.x),
    ys = positions.map((p) => p.y);
  const width = Math.max(...xs) - Math.min(...xs),
    height = Math.max(...ys) - Math.min(...ys);
  const scale = Math.min(
    1,
    1200 / Math.max(1, width),
    900 / Math.max(1, height),
  );
  return positions.map((p) => ({ id: p.id, x: p.x * scale, y: p.y * scale }));
}
