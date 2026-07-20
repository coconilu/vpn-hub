import assert from "node:assert/strict";
import test from "node:test";

import {
  filterSubscriptionNodes,
  replaceSubscriptionNodeGroup,
} from "./subscriptionNodesModel.js";

const nodes = [
  { name: "Synthetic Alpha", proxy_type: "Vless" },
  { name: "Synthetic Beta", proxy_type: "Trojan" },
];

test("filters subscription nodes by name or proxy type", () => {
  assert.deepEqual(filterSubscriptionNodes(nodes, " beta "), [nodes[1]]);
  assert.deepEqual(filterSubscriptionNodes(nodes, "VLESS"), [nodes[0]]);
  assert.equal(filterSubscriptionNodes(nodes, "").length, 2);
});

test("replaces only the selected subscription group", () => {
  const first = { subscription_id: "sub-a", current_node: "Synthetic Alpha" };
  const second = { subscription_id: "sub-b", current_node: "Synthetic Beta" };
  const catalog = { controller_ready: true, subscriptions: [first, second], message: "ready" };
  const updated = { ...first, current_node: "Synthetic Gamma" };

  const result = replaceSubscriptionNodeGroup(catalog, updated);
  assert.equal(result.subscriptions[0], updated);
  assert.equal(result.subscriptions[1], second);
});
