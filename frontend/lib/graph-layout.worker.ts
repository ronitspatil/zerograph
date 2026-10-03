import { computePositions } from "./graph-layout-engine";
import type { LayoutInput } from "./graph-layout";
const scope = self as unknown as {
  onmessage: (event: MessageEvent<LayoutInput>) => void;
  postMessage: (data: unknown) => void;
};
scope.onmessage = ({ data }) => {
  if (
    !Array.isArray(data.nodes) ||
    !Array.isArray(data.edges) ||
    data.nodes.length > 500 ||
    data.edges.length > 2000
  ) {
    scope.postMessage([]);
    return;
  }
  scope.postMessage(computePositions(data));
};
