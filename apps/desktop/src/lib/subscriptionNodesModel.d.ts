import type {
  SubscriptionNode,
  SubscriptionNodeCatalog,
  SubscriptionNodeGroup,
  NodeLatencyBatchResult,
  NodeLatencyResult,
  NodeLatencyViewState,
} from "../types";

export function filterSubscriptionNodes(
  nodes: SubscriptionNode[],
  query: string,
): SubscriptionNode[];

export function replaceSubscriptionNodeGroup(
  catalog: SubscriptionNodeCatalog,
  updatedGroup: SubscriptionNodeGroup,
): SubscriptionNodeCatalog;

export function subscriptionNodeGroupMessage(
  group: SubscriptionNodeGroup | null,
): string | null;

export interface NodePageCapabilities {
  canRefresh: boolean;
  canTest: boolean;
  canSelect: boolean;
  currentNodeLabel: string;
  selectNodeLabel: string;
}

export function nodePageCapabilities(
  catalog: SubscriptionNodeCatalog | null,
  group: SubscriptionNodeGroup | null,
): NodePageCapabilities;

export const NODE_LATENCY_CONCURRENCY: 4;

export function nodeLatencyKey(subscriptionId: string, nodeName: string): string;

export function initialNodeLatencyState(node: SubscriptionNode): NodeLatencyViewState;

export function batchStartingLatencyStates(
  nodes: SubscriptionNode[],
): Record<string, NodeLatencyViewState>;

export function latencyResultToView(result: NodeLatencyResult): NodeLatencyViewState;

export function mergeBatchLatencyResults(
  nodes: SubscriptionNode[],
  result: NodeLatencyBatchResult,
): Record<string, NodeLatencyViewState>;
