import { invoke } from "@tauri-apps/api/core";
import { mockSnapshot } from "../data/mock";
import { consumeSettingsPreviewTicket, settingsRequestFingerprint } from "./settingsModel";
import type {
  CoreStatus,
  DashboardSnapshot,
  HistoryExport,
  HistoryFilter,
  HistoryResponse,
  RouteMode,
  SafeSettingsView,
  SettingsApplyRequest,
  SettingsApplyResult,
  SettingsPreview,
  SettingsPreviewRequest,
  SubscriptionNodeCatalog,
  SubscriptionNodeGroup,
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
    outlets: [],
  },
  credentials: [],
};
let browserSettingsPreviewTicket: string | null = null;
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
    const issues = draft.outlets.some((outlet) => outlet.enabled)
      ? []
      : [{ field: "outlets", code: "enabled_outlet_required", message: "至少需要一个启用出口。" }];
    const result = {
      diff: {
        changes: JSON.stringify(draft) === JSON.stringify(browserSettings.draft)
          ? []
          : [{ code: "browser_preview", summary: "浏览器预览：设置将更新" }],
        runtime_changed: true,
        monitor_changed: true,
        retention_changed: draft.retention_days !== browserSettings.draft.retention_days,
      },
      issues,
      can_apply: issues.length === 0
        && (JSON.stringify(draft) !== JSON.stringify(browserSettings.draft)
          || request.credential_intents.length > 0),
      requires_managed_core_restart: false,
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
      diff: {
        changes: [{ code: "browser_apply", summary: "浏览器预览设置已更新" }],
        runtime_changed: true,
        monitor_changed: true,
        retention_changed: true,
      },
      removed_history_rows: 0,
      managed_core_restarted: false,
    };
  }
  return invoke<SettingsApplyResult>("apply_settings", { request });
}
