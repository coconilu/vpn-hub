import { invoke } from "@tauri-apps/api/core";
import { mockSnapshot } from "../data/mock";
import { consumeSettingsPreviewTicket, settingsRequestFingerprint } from "./settingsModel";
import type {
  CoreStatus,
  DashboardSnapshot,
  HistoryExport,
  HistoryFilter,
  HistoryResponse,
  NodeLatencyBatchResult,
  NodeLatencyResult,
  RouteMode,
  SafeSettingsView,
  SettingsTerminalStatus,
  SettingsApplyRequest,
  SettingsApplyResult,
  SettingsDiff,
  SettingsDraft,
  SettingsPreview,
  SettingsPreviewRequest,
  SubscriptionNodeCatalog,
  SubscriptionNodeGroup,
  ValidationIssue,
} from "../types";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export const isTauriRuntime = () => Boolean(window.__TAURI_INTERNALS__);

let browserSnapshot = structuredClone(mockSnapshot);
let browserSettings: SafeSettingsView = {
  draft: {
    entry: { host: "127.0.0.1", port: 3666 },
    route_mode: "priority",
    manual_outlet: null,
    cooldown_seconds: 60,
    minimum_improvement_ms: 150,
    probe_targets: ["https://www.gstatic.com/generate_204", "https://www.baidu.com/"],
    refresh_interval_seconds: 180,
    connect_timeout_ms: 1500,
    request_timeout_ms: 8000,
    failure_threshold: 2,
    recovery_threshold: 3,
    retention_days: 30,
    outlets: [
      {
        kind: "subscription",
        outlet_id: "sub-a",
        label: "合成订阅 A",
        enabled: true,
        provider_update_seconds: 180,
      },
      {
        kind: "local_proxy",
        outlet_id: "local-a",
        label: "合成本地出口",
        enabled: true,
        protocol: "socks5h",
        host: "127.0.0.1",
        port: 45112,
      },
    ],
  },
  credentials: [{ subscription_id: "sub-a", state: "configured" }],
};
let browserSettingsTerminalStatus: SettingsTerminalStatus = { active: false, state: null };
let browserSettingsPreviewTicket: string | null = null;

function browserSettingsDiff(
  draft: SettingsDraft,
  current: SettingsDraft,
  credentialsChanged: boolean,
): SettingsDiff {
  const changes: SettingsDiff["changes"] = [];
  const add = (code: string, summary: string, impact: SettingsDiff["changes"][number]["impact"]) => {
    changes.push({ code, summary, impact });
  };
  if (JSON.stringify(draft.entry) !== JSON.stringify(current.entry)) {
    add("entry_changed", "统一入口只能通过专用安全事务更新", "dedicated_transaction");
  }
  if (draft.route_mode !== current.route_mode || draft.manual_outlet !== current.manual_outlet) {
    add("route_policy_changed", "默认路由模式或手动出口将通过 Controller 在线更新", "live_apply");
  }
  if (draft.cooldown_seconds !== current.cooldown_seconds
    || draft.minimum_improvement_ms !== current.minimum_improvement_ms) {
    add("routing_thresholds_changed", "切换阈值将在线更新", "live_apply");
  }
  if (JSON.stringify(draft.probe_targets) !== JSON.stringify(current.probe_targets)) {
    add("probe_targets_changed", "探测目标影响 Mihomo provider 健康检查，将受控重载核心", "managed_core_reload");
  }
  if (JSON.stringify(draft.outlets) !== JSON.stringify(current.outlets)) {
    add("outlets_changed", "出口定义、provider、启用状态或顺序将受控重载核心", "managed_core_reload");
  }
  if (draft.refresh_interval_seconds !== current.refresh_interval_seconds
    || draft.connect_timeout_ms !== current.connect_timeout_ms
    || draft.request_timeout_ms !== current.request_timeout_ms
    || draft.failure_threshold !== current.failure_threshold
    || draft.recovery_threshold !== current.recovery_threshold) {
    add("monitor_changed", "Guardian 探测周期与阈值将在线更新", "live_apply");
  }
  if (draft.retention_days !== current.retention_days) {
    add("retention_changed", "历史保留期将在线更新并清理过期数据", "live_apply");
  }
  if (credentialsChanged) {
    add("credentials_changed", "订阅凭据状态将更新并受控重载核心；预览不包含凭据内容", "managed_core_reload");
  }
  return { changes };
}
let browserNodeCatalog: SubscriptionNodeCatalog = {
  controller_ready: true,
  subscriptions: [
    {
      subscription_id: "sub-a",
      label: "订阅示例 A",
      state: "available",
      current_node: "示例节点 02",
      nodes: [
        { name: "示例节点 01", proxy_type: "Vless", alive: true, latency_ms: 42 },
        { name: "示例节点 02", proxy_type: "Vless", alive: true, latency_ms: 67 },
        { name: "示例节点 03", proxy_type: "Trojan", alive: false, latency_ms: null },
        { name: "示例节点 04", proxy_type: "Hysteria2", alive: null, latency_ms: null },
        { name: "实验线路 A", proxy_type: "Vmess", alive: true, latency_ms: 118 },
        { name: "实验线路 B", proxy_type: "Vless", alive: true, latency_ms: 91 },
      ],
    },
    {
      subscription_id: "sub-b",
      label: "订阅示例 B",
      state: "available",
      current_node: "备用节点 01",
      nodes: [
        { name: "备用节点 01", proxy_type: "Vless", alive: true, latency_ms: 83 },
        { name: "备用节点 02", proxy_type: "Trojan", alive: true, latency_ms: 105 },
      ],
    },
  ],
  message: "浏览器预览：以下为合成节点数据，不会连接 Mihomo 或修改系统网络。",
};
const browserNodeLatencyActive = new Set<string>();
const browserNodeLatencyCancelled = new Set<string>();

const syntheticLatencyResult = (nodeName: string): NodeLatencyResult => {
  const testedAt = new Date().toISOString();
  if (nodeName.includes("03")) {
    return { node_name: nodeName, status: "failure", latency_ms: null, tested_at: testedAt, error_code: "node_disappeared", message: "节点已从 provider 中消失，请刷新状态", selection_unchanged: true };
  }
  if (nodeName.includes("04")) {
    return { node_name: nodeName, status: "failure", latency_ms: null, tested_at: testedAt, error_code: "timeout", message: "节点测速超时", selection_unchanged: true };
  }
  const latency = 38 + (Array.from(nodeName).reduce((sum, character) => sum + character.codePointAt(0)!, 0) % 92);
  return { node_name: nodeName, status: "success", latency_ms: latency, tested_at: testedAt, error_code: null, message: "本次延迟测试成功；权威当前节点保持不变", selection_unchanged: true };
};

export async function getDashboardSnapshot(): Promise<DashboardSnapshot> {
  if (!isTauriRuntime()) return structuredClone(browserSnapshot);
  return invoke<DashboardSnapshot>("get_dashboard_snapshot");
}

export async function refreshGuardian(): Promise<DashboardSnapshot> {
  if (!isTauriRuntime()) {
    browserSnapshot = { ...browserSnapshot, updated_at: new Date().toISOString() };
    return structuredClone(browserSnapshot);
  }
  return invoke<DashboardSnapshot>("refresh_guardian");
}

export async function startDevelopmentCore(): Promise<CoreStatus> {
  if (!isTauriRuntime()) {
    const status: CoreStatus = {
      state: "running",
      managed: true,
      pid: 32100,
      started_at: new Date().toISOString(),
      message: `浏览器预览：已模拟启动 ${browserSnapshot.entry.host}:${browserSnapshot.entry.port}`,
    };
    browserSnapshot = {
      ...browserSnapshot,
      updated_at: new Date().toISOString(),
      entry: { ...browserSnapshot.entry, reachable: true, owner_pid: status.pid },
      mihomo: status,
    };
    return status;
  }
  return invoke<CoreStatus>("start_development_core");
}

export async function stopDevelopmentCore(): Promise<CoreStatus> {
  if (!isTauriRuntime()) {
    const status: CoreStatus = {
      state: "stopped",
      managed: false,
      pid: null,
      started_at: null,
      message: `浏览器预览：已模拟停止 ${browserSnapshot.entry.host}:${browserSnapshot.entry.port}`,
    };
    browserSnapshot = {
      ...browserSnapshot,
      updated_at: new Date().toISOString(),
      entry: { ...browserSnapshot.entry, reachable: false, owner_pid: null },
      mihomo: status,
    };
    return status;
  }
  return invoke<CoreStatus>("stop_development_core");
}

export async function setRouteMode(mode: RouteMode, manualOutlet: string | null): Promise<DashboardSnapshot> {
  if (!isTauriRuntime()) {
    browserSnapshot = {
      ...browserSnapshot,
      updated_at: new Date().toISOString(),
      routing: { ...browserSnapshot.routing, mode, manual_outlet: manualOutlet },
    };
    return structuredClone(browserSnapshot);
  }
  return invoke<DashboardSnapshot>("set_route_mode", { mode, manualOutlet });
}

export async function revalidateUdpCapabilities(authorizedSubscriptionTargets: string[]): Promise<DashboardSnapshot> {
  if (!isTauriRuntime()) {
    browserSnapshot = { ...browserSnapshot, updated_at: new Date().toISOString() };
    return structuredClone(browserSnapshot);
  }
  return invoke<DashboardSnapshot>("revalidate_udp_capabilities", { authorizedSubscriptionTargets });
}

export async function getHistory(filter: HistoryFilter): Promise<HistoryResponse> {
  if (!isTauriRuntime()) {
    return {
      window_start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      window_end: new Date().toISOString(),
      metrics: [],
      outlets: [],
      records: [],
      total_count: 0,
      page: 0,
      total_pages: 0,
      next_page: null,
      retention_days: 30,
    };
  }
  return invoke<HistoryResponse>("get_history", { filter });
}

export async function exportHistory(filter: HistoryFilter): Promise<HistoryExport> {
  if (!isTauriRuntime()) return { path: "浏览器预览不写入文件", rows: 0 };
  return invoke<HistoryExport>("export_history", { filter });
}

export async function setHistoryRetention(days: number): Promise<number> {
  if (!isTauriRuntime()) return 0;
  return invoke<number>("set_history_retention", { days });
}

export async function getSettings(): Promise<SafeSettingsView> {
  if (!isTauriRuntime()) return structuredClone(browserSettings);
  return invoke<SafeSettingsView>("get_settings");
}

export async function getSettingsTerminalStatus(): Promise<SettingsTerminalStatus> {
  if (!isTauriRuntime()) return structuredClone(browserSettingsTerminalStatus);
  return invoke<SettingsTerminalStatus>("get_settings_terminal_status");
}

export async function recoverSettingsTerminal(): Promise<SettingsTerminalStatus> {
  if (!isTauriRuntime()) {
    browserSettingsTerminalStatus = { active: false, state: null };
    return structuredClone(browserSettingsTerminalStatus);
  }
  return invoke<SettingsTerminalStatus>("recover_settings_terminal");
}

export async function getSubscriptionNodeCatalog(): Promise<SubscriptionNodeCatalog> {
  if (!isTauriRuntime()) return structuredClone(browserNodeCatalog);
  return invoke<SubscriptionNodeCatalog>("get_subscription_node_catalog");
}

export async function selectSubscriptionNode(
  subscriptionId: string,
  nodeName: string,
): Promise<SubscriptionNodeGroup> {
  if (!isTauriRuntime()) {
    const group = browserNodeCatalog.subscriptions.find(
      (item) => item.subscription_id === subscriptionId,
    );
    if (!group || !group.nodes.some((node) => node.name === nodeName)) {
      throw new Error("节点列表已变化，请刷新后重试；原节点选择保持不变");
    }
    const updated = { ...group, current_node: nodeName };
    browserNodeCatalog = {
      ...browserNodeCatalog,
      subscriptions: browserNodeCatalog.subscriptions.map((item) => (
        item.subscription_id === subscriptionId ? updated : item
      )),
    };
    return structuredClone(updated);
  }
  return invoke<SubscriptionNodeGroup>("select_subscription_node", {
    subscriptionId,
    nodeName,
  });
}

export async function testSubscriptionNodeLatency(
  subscriptionId: string,
  nodeName: string,
): Promise<NodeLatencyResult> {
  if (!isTauriRuntime()) {
    const group = browserNodeCatalog.subscriptions.find(
      (item) => item.subscription_id === subscriptionId,
    );
    if (!group) {
      return { node_name: nodeName, status: "failure", latency_ms: null, tested_at: new Date().toISOString(), error_code: "provider_unavailable", message: "订阅 provider 尚未就绪", selection_unchanged: true };
    }
    await new Promise((resolve) => window.setTimeout(resolve, 180));
    return syntheticLatencyResult(nodeName);
  }
  return invoke<NodeLatencyResult>("test_subscription_node_latency", {
    subscriptionId,
    nodeName,
  });
}

export async function testSubscriptionNodeLatencies(
  subscriptionId: string,
  operationId: string,
): Promise<NodeLatencyBatchResult> {
  if (!isTauriRuntime()) {
    const group = browserNodeCatalog.subscriptions.find(
      (item) => item.subscription_id === subscriptionId,
    );
    if (!group) {
      return { subscription_id: subscriptionId, results: [], cancelled: false, selection_unchanged: true, error_code: "provider_unavailable", message: "订阅 provider 尚未就绪" };
    }
    browserNodeLatencyActive.add(operationId);
    const results: NodeLatencyResult[] = [];
    for (let index = 0; index < group.nodes.length; index += 4) {
      await new Promise((resolve) => window.setTimeout(resolve, 260));
      for (const node of group.nodes.slice(index, index + 4)) {
        if (browserNodeLatencyCancelled.has(operationId)) {
          results.push({ node_name: node.name, status: "cancelled", latency_ms: null, tested_at: new Date().toISOString(), error_code: "cancelled", message: "未开始的节点测速已取消", selection_unchanged: true });
        } else {
          results.push(syntheticLatencyResult(node.name));
        }
      }
    }
    const cancelled = browserNodeLatencyCancelled.has(operationId);
    browserNodeLatencyActive.delete(operationId);
    browserNodeLatencyCancelled.delete(operationId);
    return {
      subscription_id: subscriptionId,
      results,
      cancelled,
      selection_unchanged: true,
      error_code: null,
      message: cancelled ? "批量测速已取消；已完成的结果仍保留在当前界面" : "批量测速完成；部分节点失败，其他成功结果已保留",
    };
  }
  return invoke<NodeLatencyBatchResult>("test_subscription_node_latencies", {
    subscriptionId,
    operationId,
  });
}

export async function cancelSubscriptionNodeLatencyBatch(operationId: string): Promise<boolean> {
  if (!isTauriRuntime()) {
    if (!browserNodeLatencyActive.has(operationId)) return false;
    browserNodeLatencyCancelled.add(operationId);
    return true;
  }
  return invoke<boolean>("cancel_subscription_node_latency_batch", { operationId });
}

export async function previewSettings(request: SettingsPreviewRequest): Promise<SettingsPreview> {
  if (!isTauriRuntime()) {
    const fingerprint = settingsRequestFingerprint(
      request.draft,
      request.active_outlet_replacement,
      request.fail_closed_on_removed_active,
      request.credential_intents,
    );
    if (fingerprint !== request.request_fingerprint) {
      throw new Error("设置预览指纹与请求内容不匹配");
    }
    const draft = request.draft;
    const diff = browserSettingsDiff(
      draft,
      browserSettings.draft,
      request.credential_intents.length > 0,
    );
    const issues: ValidationIssue[] = [];
    if (!draft.outlets.some((outlet) => outlet.enabled)) {
      issues.push({ field: "outlets", code: "enabled_outlet_required", message: "至少需要一个启用出口。" });
    }
    for (const outlet of draft.outlets) {
      if (outlet.label.trim().length === 0) {
        issues.push({
          field: `outlets.${outlet.outlet_id}.label`,
          code: "unsafe_outlet_label",
          message: "出口名称不能为空。",
        });
      }
      if (outlet.kind === "subscription" && outlet.provider_update_seconds < 60) {
        issues.push({
          field: `outlets.${outlet.outlet_id}.provider_update_seconds`,
          code: "provider_update_too_short",
          message: "订阅 provider 更新周期不能小于 60 秒。",
        });
      }
      if (outlet.kind === "local_proxy"
        && !["localhost", "127.0.0.1", "::1"].includes(outlet.host.trim().toLowerCase())) {
        issues.push({
          field: `outlets.${outlet.outlet_id}.host`,
          code: "local_proxy_host_not_loopback",
          message: "本地出口地址必须是 loopback IP 或 localhost。",
        });
      }
      if (outlet.kind === "local_proxy" && (outlet.port < 1 || outlet.port > 65_535)) {
        issues.push({
          field: `outlets.${outlet.outlet_id}.port`,
          code: "local_proxy_port_invalid",
          message: "本地出口端口必须在 1 到 65535 之间。",
        });
      }
    }
    if (draft.connect_timeout_ms < 1 || draft.connect_timeout_ms > 120_000) {
      issues.push({
        field: "connect_timeout_ms",
        code: "connect_timeout_out_of_range",
        message: "连接超时必须在 1 毫秒到 120 秒之间。",
      });
    }
    if (draft.recovery_threshold < 1 || draft.recovery_threshold > 100) {
      issues.push({
        field: "recovery_threshold",
        code: "recovery_threshold_out_of_range",
        message: "恢复阈值必须在 1 到 100 之间。",
      });
    }
    if (diff.changes.some((change) => change.impact === "dedicated_transaction")) {
      issues.push({
        field: "entry",
        code: "dedicated_entry_switch_required",
        message: "统一入口只能通过专用安全切换事务修改。",
      });
    }
    const result = {
      diff,
      issues,
      can_apply: issues.length === 0
        && diff.changes.length > 0,
      requires_managed_core_restart: browserSnapshot.mihomo.managed
        && browserSnapshot.mihomo.pid !== null
        && diff.changes.some((change) => change.impact === "managed_core_reload"),
      request_fingerprint: fingerprint,
      tun_plan: {
        requested_enabled: false,
        active: false,
        supported: false,
        consent_required: true,
        reason_code: "windows_verified_application_identity_exclusion_unavailable",
        generation: fingerprint,
        subscription_outlet_ids: draft.outlets
          .filter((outlet) => outlet.enabled && outlet.kind === "subscription")
          .map((outlet) => outlet.outlet_id),
        local_outlet_ids: draft.outlets
          .filter((outlet) => outlet.enabled && outlet.kind === "local_proxy")
          .map((outlet) => outlet.outlet_id),
        missing_executable_identity_outlet_ids: draft.outlets
          .filter((outlet) => outlet.enabled && outlet.kind === "local_proxy")
          .map((outlet) => outlet.outlet_id),
        control_plane_policy: "deny_external_egress_loopback_ipc_only",
        core_policy: "owned_upstream_only",
        local_outlet_policy: "registered_executable_identity_only",
        leak_matrix_disposition: "fail_closed_reject",
      },
    };
    browserSettingsPreviewTicket = result.can_apply ? fingerprint : null;
    return result;
  }
  return invoke<SettingsPreview>("preview_settings", { request });
}

export async function applySettings(request: SettingsApplyRequest): Promise<SettingsApplyResult> {
  if (!isTauriRuntime()) {
    const intents = request.credential_mutations.map(({ subscription_id, action }) => ({
      subscription_id,
      action,
    }));
    const fingerprint = settingsRequestFingerprint(
      request.draft,
      request.active_outlet_replacement,
      request.fail_closed_on_removed_active,
      intents,
    );
    if (fingerprint !== request.preview_fingerprint) {
      throw new Error("设置预览已失效或已被使用，请重新预览");
    }
    browserSettingsPreviewTicket = consumeSettingsPreviewTicket(
      browserSettingsPreviewTicket,
      request.preview_fingerprint,
    );
    const diff = browserSettingsDiff(
      request.draft,
      browserSettings.draft,
      request.credential_mutations.length > 0,
    );
    const previousStates = new Map(browserSettings.credentials.map((item) => [item.subscription_id, item.state]));
    browserSettings = {
      draft: structuredClone(request.draft),
      credentials: request.draft.outlets
        .filter((outlet) => outlet.kind === "subscription")
        .map((outlet) => ({
          subscription_id: outlet.outlet_id,
          state: request.credential_mutations.find(
            (mutation) => mutation.subscription_id === outlet.outlet_id,
          )?.action === "set" ? "configured"
            : request.credential_mutations.find(
              (mutation) => mutation.subscription_id === outlet.outlet_id,
            )?.action === "delete" ? "missing"
              : previousStates.get(outlet.outlet_id) ?? "missing",
        })),
    };
    return {
      settings: structuredClone(browserSettings),
      diff,
      removed_history_rows: 0,
      managed_core_restarted: browserSnapshot.mihomo.managed
        && browserSnapshot.mihomo.pid !== null
        && diff.changes.some((change) => change.impact === "managed_core_reload"),
    };
  }
  return invoke<SettingsApplyResult>("apply_settings", { request });
}
