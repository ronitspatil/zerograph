import {
  EXPLORE_LIMITS,
  MEMBER_LIMITS,
  type LayoutInput,
  type Position,
} from "./graph-layout";

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

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

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
  if (
    data.nodes.length > EXPLORE_LIMITS.nodes ||
    data.edges.length > EXPLORE_LIMITS.edges
  )
    return [];
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
  const rank = (id: string) => {
    const r = order.indexOf(data.attributes?.[id]?.type || "");
    return r < 0 ? order.length : r;
  };
  const positions: Position[] = [];
  if (!data.edges.length) {
    // No relationships to arrange by: one compact disc, entity types in bands,
    // rather than a sparse grid of singleton communities that reads as broken.
    [...data.nodes]
      .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
      .forEach((id, i) => {
        const r = 28 * Math.sqrt(i + 0.5);
        positions.push({
          id,
          x: r * Math.cos(i * GOLDEN_ANGLE),
          y: r * Math.sin(i * GOLDEN_ANGLE),
        });
      });
    return positions;
  }
  const groups = partitionCommunities(data);
  const radius = (count: number) =>
    count <= 1 ? 0 : 42 + 26 * Math.floor((count - 2) / 16);
  const cell = Math.max(
    150,
    ...groups.map((group) => radius(group.length) * 2 + 100),
  );
  const columns = Math.max(1, Math.ceil(Math.sqrt(groups.length * 1.45)));
  groups.forEach(([anchor, ...neighbors], index) => {
    const cx = (index % columns) * cell + noise(`${anchor}:x`) * cell * 0.065,
      cy =
        Math.floor(index / columns) * cell +
        noise(`${anchor}:y`) * cell * 0.065;
    positions.push({ id: anchor, x: cx, y: cy });
    neighbors.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
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

/**
 * In-place expansion layout for up to 5,000 members: a filled disc of radius
 * about sqrt(n) (one member per pi square units), centred on the origin. Each
 * role community (as in `partitionCommunities`) is a contiguous sunflower patch;
 * patches are placed largest first on a golden-angle spiral by cumulative area,
 * so loose members end up on the rim. O(nodes + edges), deterministic.
 */
export function packedPositions(data: LayoutInput): Position[] {
  if (
    data.nodes.length > MEMBER_LIMITS.nodes ||
    data.edges.length > MEMBER_LIMITS.edges
  )
    return [];
  const groups = partitionCommunities(data).sort(
    (a, b) => b.length - a.length || a[0].localeCompare(b[0]),
  );
  const positions: Position[] = [];
  let area = 0;
  groups.forEach((group, k) => {
    // Centre of this patch: where the spiral has covered half of its area.
    const reach = Math.sqrt(area + group.length / 2);
    const cx = k === 0 ? 0 : reach * Math.cos(k * GOLDEN_ANGLE);
    const cy = k === 0 ? 0 : reach * Math.sin(k * GOLDEN_ANGLE);
    group.forEach((id, i) => {
      const r = Math.sqrt(i + 0.5);
      positions.push({
        id,
        x: cx + r * Math.cos(i * GOLDEN_ANGLE),
        y: cy + r * Math.sin(i * GOLDEN_ANGLE),
      });
    });
    area += group.length;
  });
  return positions;
}
