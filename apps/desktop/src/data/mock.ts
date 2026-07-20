import type { DashboardSnapshot, HealthStatus, LatencySample } from "../types";

const now = Date.now();
const latencyValues = [182, 194, 178, 216, 228, 205, null, null, 241, 220, 201, 190, 231, 248, 226, 214, null, null, 264, 238, 217, 202, 194, 228];

const samples: LatencySample[] = latencyValues.map((latency, index) => ({
  outlet_id: "local-a",
  observed_at: new Date(now - (latencyValues.length - 1 - index) * 60 * 60 * 1000).toISOString(),
  port_reachable: true,
  status: (latency === null ? "down" : latency > 230 ? "degraded" : "healthy") as HealthStatus,
  latency_ms: latency,
  error_code: latency === null ? "request_timeout" : null,
  successful_targets: latency === null ? 1 : 3,
  total_targets: 3,
}));

export const mockSnapshot: DashboardSnapshot = {
  updated_at: new Date(now).toISOString(),
  entry: { host: "127.0.0.1", port: 3666, reachable: false, owner_pid: null },
  mihomo: {
    state: "stopped",
    managed: false,
    pid: null,
    started_at: null,
    message: "开发核心已停止",
  },
  routing: {
    mode: "priority",
    current_outlet: "local-a",
    manual_outlet: null,
    controller_ready: false,
    outlets: [
      { outlet_id: "sub-a", label: "订阅 A", kind: "subscription", enabled: true, endpoint: null, configured: true },
      { outlet_id: "sub-b", label: "订阅 B", kind: "subscription", enabled: true, endpoint: null, configured: true },
      { outlet_id: "sub-c", label: "订阅 C", kind: "subscription", enabled: false, endpoint: null, configured: false },
      { outlet_id: "local-a", label: "本地客户端 A", kind: "local_proxy", enabled: true, endpoint: "socks5h://127.0.0.1:2666", configured: true },
      { outlet_id: "local-b", label: "本地客户端 B", kind: "local_proxy", enabled: true, endpoint: "http://127.0.0.1:4666", configured: true },
    ],
    message: "开发核心未运行，路由保持 Fail Closed",
  },
  summaries: [
    {
      outlet_id: "local-a",
      label: "本地客户端 A",
      samples: 72,
      successful_samples: 63,
      failed_samples: 9,
      availability_percent: 87.6,
      average_latency_ms: 228,
      last_status: "down",
      last_observed_at: new Date(now - 4 * 60 * 1000).toISOString(),
    },
  ],
  samples,
  events: [
    {
      outlet_id: "local-a",
      occurred_at: new Date(now - 4 * 60 * 1000).toISOString(),
      from_status: "healthy",
      to_status: "down",
      reason: "request_timeout",
    },
    {
      outlet_id: "local-a",
      occurred_at: new Date(now - 9 * 60 * 1000).toISOString(),
      from_status: "down",
      to_status: "healthy",
      reason: "probe_result",
    },
    {
      outlet_id: "local-a",
      occurred_at: new Date(now - 14 * 60 * 1000).toISOString(),
      from_status: "unknown",
      to_status: "healthy",
      reason: "port_reachable",
    },
  ],
  route_switches: [],
};
