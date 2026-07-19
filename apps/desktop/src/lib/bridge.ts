import { invoke } from "@tauri-apps/api/core";
import { mockSnapshot } from "../data/mock";
import type { CoreStatus, DashboardSnapshot, HistoryExport, HistoryFilter, HistoryResponse, RouteMode } from "../types";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export const isTauriRuntime = () => Boolean(window.__TAURI_INTERNALS__);

let browserSnapshot = structuredClone(mockSnapshot);

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
      records: [],
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
