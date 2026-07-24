export function filterSubscriptionNodes(nodes, query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return nodes;
  return nodes.filter((node) => (
    node.name.toLowerCase().includes(needle)
      || node.proxy_type.toLowerCase().includes(needle)
  ));
}

export function replaceSubscriptionNodeGroup(catalog, updatedGroup) {
  return {
    ...catalog,
    subscriptions: catalog.subscriptions.map((group) => (
      group.subscription_id === updatedGroup.subscription_id ? updatedGroup : group
    )),
  };
}

export function subscriptionNodeGroupMessage(group) {
  if (!group) return null;
  if (group.state === "core_unavailable") {
    return "无法启动隔离订阅探测。请检查 Mihomo 文件与订阅配置后重试。";
  }
  if (group.state === "controller_error") {
    return "主核心正在运行，但 Mihomo Controller 查询失败。请检查核心状态后刷新。";
  }
  if (group.state === "provider_unavailable") {
    return "订阅 provider 尚未返回可选节点。可以立即重试；配置无需再次保存。";
  }
  if (group.state === "provider_loading") {
    return "配置已生效，provider 正在后台加载；完成后刷新即可加入路由。";
  }
  if (group.state === "provider_failed") {
    return "provider 刷新失败。凭据与配置仍已安全保存，可以重试且无需再次保存。";
  }
  return null;
}

export function nodePageCapabilities(catalog, group) {
  const selectionReady = Boolean(catalog?.selection_ready);
  return {
    canRefresh: true,
    canTest: Boolean(catalog?.controller_ready && group?.state === "available"),
    canSelect: Boolean(selectionReady && group?.state === "available"),
    currentNodeLabel: selectionReady
      ? group?.current_node ?? "尚未选择"
      : "启动主核心后可查看",
    selectNodeLabel: selectionReady ? "选择此节点" : "启动核心后可选",
  };
}

export const NODE_LATENCY_CONCURRENCY = 4;

export function nodeLatencyKey(subscriptionId, nodeName) {
  return JSON.stringify([subscriptionId, nodeName]);
}

export function initialNodeLatencyState(node) {
  if (node.latency_ms !== null) {
    return {
      status: "stale",
      latency_ms: node.latency_ms,
      tested_at: null,
      error_code: null,
      message: "Controller 最近状态，尚未在本次界面主动测速",
    };
  }
  return {
    status: "waiting",
    latency_ms: null,
    tested_at: null,
    error_code: null,
    message: "等待首次测试",
  };
}

export function batchStartingLatencyStates(nodes) {
  return Object.fromEntries(nodes.map((node, index) => [
    node.name,
    {
      status: index < NODE_LATENCY_CONCURRENCY ? "running" : "waiting",
      latency_ms: null,
      tested_at: null,
      error_code: null,
      message: index < NODE_LATENCY_CONCURRENCY ? "正在测试" : "等待并发槽位",
    },
  ]));
}

export function latencyResultToView(result) {
  return {
    status: result.status,
    latency_ms: result.latency_ms,
    tested_at: result.tested_at,
    error_code: result.error_code,
    message: result.message,
  };
}

export function mergeBatchLatencyResults(nodes, result) {
  const byName = new Map(result.results.map((item) => [item.node_name, item]));
  return Object.fromEntries(nodes.map((node) => {
    const item = byName.get(node.name);
    if (item) return [node.name, latencyResultToView(item)];
    if (result.error_code) {
      return [node.name, {
        status: "failure",
        latency_ms: null,
        tested_at: new Date().toISOString(),
        error_code: result.error_code,
        message: result.message,
      }];
    }
    return [node.name, initialNodeLatencyState(node)];
  }));
}
