import {
  EXPLORE_LIMITS,
  MEMBER_LIMITS,
  type LayoutInput,
  type Position,
} from "./graph-layout";

/**
 * Nearest role over real edges. With `strictAccounts` (the default, used by the
 * global map's packed members) account boundaries are hard: a member never joins
 * a role of another account. The explorer passes `strictAccounts: false`: roles
 * first claim their own account's members, then members that would otherwise be
 * left alone join the nearest role across accounts, and the rest group by
 * connected component regardless of account. Account becomes a preference.
 */
export function partitionCommunities(
  data: LayoutInput,
  { strictAccounts = true }: { strictAccounts?: boolean } = {},
): string[][] {
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
  const claim = (strict: boolean) => {
    for (let cursor = 0; cursor < queue.length; cursor++) {
      const id = queue[cursor],
        anchor = owners.get(id)!;
      for (const neighbor of [...adjacent.get(id)!].sort()) {
        if (owners.has(neighbor) || (strict && !compatible(anchor, neighbor)))
          continue;
        owners.set(neighbor, anchor);
        queue.push(neighbor);
      }
    }
  };
  claim(true);
  // Same-account members are claimed first; the rest may then cross accounts.
  if (!strictAccounts) claim(false);
  // Remaining connected components are real topology, never name/ID-derived clusters.
  for (const seed of ids) {
    if (owners.has(seed)) continue;
    const pending = [seed];
    owners.set(seed, seed);
    for (let cursor = 0; cursor < pending.length; cursor++) {
      for (const neighbor of [...adjacent.get(pending[cursor])!].sort()) {
        if (
          owners.has(neighbor) ||
          (strictAccounts && !compatible(seed, neighbor))
        )
          continue;
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

/**
 * Fixed force refinement length. The work is bounded by the input caps
 * (EXPLORE_LIMITS), never by a clock, so machine load cannot change positions.
 * The only time limit is the caller's last-resort worker timeout in
 * `startLayout`, which discards the run and reports failure; it never applies
 * a partial result.
 */
export const REFINE_ITERATIONS = 240;
const SPRING = 46; // Ideal relationship length (layout units).

/**
 * Bounded Fruchterman-Reingold refinement, in place. Repulsion acts within
 * 3 x SPRING through a spatial hash (no all-pairs pass), relationships are
 * springs, members are tethered (reciprocally) to their community's role,
 * community centres repel each other by size so roles stay visible centres,
 * and a light pull toward the centroid keeps components together. Iterates over
 * sorted IDs for exactly REFINE_ITERATIONS steps with a fixed cooling schedule
 * and reads no clock, so the same input always gives the same positions.
 */
function refine(
  positions: Position[],
  edges: LayoutInput["edges"],
  anchorOf: Map<string, string>,
): void {
  const order = [...positions].sort((a, b) => a.id.localeCompare(b.id));
  const count = order.length;
  if (count < 2) return;
  const index = new Map(order.map((p, i) => [p.id, i]));
  const x = Float64Array.from(order, (p) => p.x),
    y = Float64Array.from(order, (p) => p.y);
  const pairs = new Set<string>();
  const links: number[] = [];
  for (const edge of [...edges].sort((a, b) => a.id.localeCompare(b.id))) {
    const a = index.get(edge.source),
      b = index.get(edge.target);
    if (a === undefined || b === undefined || a === b) continue;
    const key = a < b ? `${a}:${b}` : `${b}:${a}`;
    if (pairs.has(key)) continue;
    pairs.add(key);
    links.push(a, b);
  }
  const tether = Int32Array.from(order, (p) => {
    const anchor = anchorOf.get(p.id);
    return anchor === undefined ? -1 : index.get(anchor)!;
  });
  // Community centres (three or more members) repel each other at any range,
  // in proportion to their size, so hubs stand apart with members around them.
  const members = new Int32Array(count);
  for (const anchor of tether) if (anchor >= 0) members[anchor]++;
  const centres: number[] = [];
  for (let i = 0; i < count; i++) if (members[i] >= 3) centres.push(i);
  const dx = new Float64Array(count),
    dy = new Float64Array(count);
  const k = SPRING,
    k2 = k * k,
    cutoff = 3 * k,
    cutoff2 = cutoff * cutoff;
  let temperature = 4 * k;
  for (let iteration = 0; iteration < REFINE_ITERATIONS; iteration++) {
    dx.fill(0);
    dy.fill(0);
    const grid = new Map<string, number[]>();
    for (let i = 0; i < count; i++) {
      const key = `${Math.floor(x[i] / cutoff)}:${Math.floor(y[i] / cutoff)}`;
      const cell = grid.get(key);
      if (cell) cell.push(i);
      else grid.set(key, [i]);
    }
    for (let i = 0; i < count; i++) {
      const gx = Math.floor(x[i] / cutoff),
        gy = Math.floor(y[i] / cutoff);
      for (let ox = -1; ox <= 1; ox++)
        for (let oy = -1; oy <= 1; oy++) {
          const cell = grid.get(`${gx + ox}:${gy + oy}`);
          if (!cell) continue;
          for (const j of cell) {
            if (j <= i) continue;
            let ex = x[i] - x[j],
              ey = y[i] - y[j];
            let d2 = ex * ex + ey * ey;
            if (d2 > cutoff2) continue;
            if (d2 < 0.01) {
              // Coincident: separate along a fixed, index-derived direction.
              ex = Math.cos(i + j);
              ey = Math.sin(i + j);
              d2 = 1;
            }
            const force = k2 / d2;
            dx[i] += ex * force;
            dy[i] += ey * force;
            dx[j] -= ex * force;
            dy[j] -= ey * force;
          }
        }
    }
    for (let c = 0; c < centres.length; c++)
      for (let e = c + 1; e < centres.length; e++) {
        const i = centres[c],
          j = centres[e];
        const ex = x[i] - x[j],
          ey = y[i] - y[j];
        const d2 = Math.max(ex * ex + ey * ey, 1);
        const force = (k2 * Math.sqrt(members[i] * members[j])) / d2;
        dx[i] += ex * force;
        dy[i] += ey * force;
        dx[j] -= ex * force;
        dy[j] -= ey * force;
      }
    for (let l = 0; l < links.length; l += 2) {
      const a = links[l],
        b = links[l + 1];
      const ex = x[a] - x[b],
        ey = y[a] - y[b];
      const d = Math.sqrt(ex * ex + ey * ey) || 1;
      const force = d / k;
      dx[a] -= ex * force;
      dy[a] -= ey * force;
      dx[b] += ex * force;
      dy[b] += ey * force;
    }
    let mx = 0,
      my = 0;
    for (let i = 0; i < count; i++) {
      mx += x[i];
      my += y[i];
    }
    mx /= count;
    my /= count;
    for (let i = 0; i < count; i++) {
      const anchor = tether[i];
      if (anchor >= 0) {
        // Reciprocal, so a community moves as one and never drifts on its own.
        const tx = (x[i] - x[anchor]) * 0.35,
          ty = (y[i] - y[anchor]) * 0.35;
        dx[i] -= tx;
        dy[i] -= ty;
        dx[anchor] += tx;
        dy[anchor] += ty;
      }
    }
    for (let i = 0; i < count; i++) {
      dx[i] -= (x[i] - mx) * 0.02;
      dy[i] -= (y[i] - my) * 0.02;
      const length = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]);
      if (length > 0) {
        const step = Math.min(length, temperature) / length;
        x[i] += dx[i] * step;
        y[i] += dy[i] * step;
      }
    }
    temperature = Math.max(0.5, temperature * 0.975);
  }
  for (const p of positions) {
    const i = index.get(p.id)!;
    p.x = x[i];
    p.y = y[i];
  }
}

/** Role-centred constellations refined into a graph, on the worker; not a permission analysis. */
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
  const groups = partitionCommunities(data, { strictAccounts: false });
  // Seed: communities largest first on a golden-angle spiral, members in rings
  // around their role; then a bounded force refinement pulls linked nodes together.
  groups.sort((a, b) => b.length - a.length || a[0].localeCompare(b[0]));
  const ringRadius = (ring: number) => 42 + ring * 26;
  let area = 0;
  groups.forEach(([anchor, ...neighbors], index) => {
    const span = ringRadius(Math.floor(Math.max(0, neighbors.length - 1) / 16));
    const reach = 1.15 * Math.sqrt(area + (span + 40) ** 2 / 2);
    const cx = index === 0 ? 0 : reach * Math.cos(index * GOLDEN_ANGLE),
      cy = index === 0 ? 0 : reach * Math.sin(index * GOLDEN_ANGLE);
    area += (span + 40) ** 2;
    positions.push({ id: anchor, x: cx, y: cy });
    neighbors.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
    neighbors.forEach((id, i) => {
      const ring = Math.floor(i / 16),
        offset = i % 16,
        size = Math.min(16, neighbors.length - ring * 16);
      const angle = -Math.PI / 2 + (offset * 2 * Math.PI) / size + ring * 0.17;
      const r = ringRadius(ring) * (1 + noise(`${id}:radius`) * 0.07);
      positions.push({
        id,
        x: cx + r * Math.cos(angle),
        y: cy + r * Math.sin(angle),
      });
    });
  });
  const anchorOf = new Map<string, string>();
  for (const [anchor, ...members] of groups)
    for (const id of members) anchorOf.set(id, anchor);
  refine(positions, data.edges, anchorOf);
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
