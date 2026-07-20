import type {
  SubscriptionNode,
  SubscriptionNodeCatalog,
  SubscriptionNodeGroup,
} from "../types";

export function filterSubscriptionNodes(
  nodes: SubscriptionNode[],
  query: string,
): SubscriptionNode[];

export function replaceSubscriptionNodeGroup(
  catalog: SubscriptionNodeCatalog,
  updatedGroup: SubscriptionNodeGroup,
): SubscriptionNodeCatalog;
