import { computePositions, packedPositions } from "./graph-layout-engine";
import { layoutLimits, type LayoutInput } from "./graph-layout";
const scope = self as unknown as {
  onmessage: (event: MessageEvent<LayoutInput>) => void;
  postMessage: (data: unknown) => void;
};
scope.onmessage = ({ data }) => {
  const limits = layoutLimits(data);
  if (
    !Array.isArray(data.nodes) ||
    !Array.isArray(data.edges) ||
    data.nodes.length > limits.nodes ||
    data.edges.length > limits.edges
  ) {
    scope.postMessage([]);
    return;
  }
  scope.postMessage(
    data.mode === "packed" ? packedPositions(data) : computePositions(data),
  );
};
