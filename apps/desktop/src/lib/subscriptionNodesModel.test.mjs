import assert from "node:assert/strict";
import test from "node:test";

import {
  NODE_LATENCY_CONCURRENCY,
  batchStartingLatencyStates,
  filterSubscriptionNodes,
  initialNodeLatencyState,
  latencyResultToView,
  mergeBatchLatencyResults,
  nodeLatencyKey,
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

test("uses collision-safe runtime-only keys and marks Controller history stale", () => {
  assert.notEqual(nodeLatencyKey("a:b", "c"), nodeLatencyKey("a", "b:c"));
  assert.equal(initialNodeLatencyState({ latency_ms: 48 }).status, "stale");
  assert.equal(initialNodeLatencyState({ latency_ms: null }).status, "waiting");
});

test("batch start exposes the fixed concurrency window and waiting queue", () => {
  const many = Array.from({ length: NODE_LATENCY_CONCURRENCY + 2 }, (_, index) => ({
    name: `Synthetic ${index}`,
    latency_ms: null,
  }));
  const states = batchStartingLatencyStates(many);
  assert.equal(Object.values(states).filter((state) => state.status === "running").length, 4);
  assert.equal(Object.values(states).filter((state) => state.status === "waiting").length, 2);
});

test("keeps partial successes and maps timeout and cancellation independently", () => {
  const many = [
    { name: "Synthetic Alpha", latency_ms: null },
    { name: "Synthetic Beta", latency_ms: null },
    { name: "Synthetic Gamma", latency_ms: null },
  ];
  const merged = mergeBatchLatencyResults(many, {
    results: [
      { node_name: "Synthetic Alpha", status: "success", latency_ms: 41, tested_at: "2026-07-21T00:00:00Z", error_code: null, message: "ok" },
      { node_name: "Synthetic Beta", status: "failure", latency_ms: null, tested_at: "2026-07-21T00:00:01Z", error_code: "timeout", message: "timeout" },
      { node_name: "Synthetic Gamma", status: "cancelled", latency_ms: null, tested_at: "2026-07-21T00:00:02Z", error_code: "cancelled", message: "cancelled" },
    ],
    error_code: null,
  });
  assert.equal(merged["Synthetic Alpha"].status, "success");
  assert.equal(merged["Synthetic Beta"].error_code, "timeout");
  assert.equal(merged["Synthetic Gamma"].status, "cancelled");
  assert.equal(latencyResultToView({ status: "failure", latency_ms: null, tested_at: "now", error_code: "node_disappeared", message: "gone" }).error_code, "node_disappeared");
});
