export type HealthStatus = "unknown" | "healthy" | "degraded" | "down";
export type UdpCapabilityStatus = "supported" | "tcp_only" | "unknown";
export type HistoryWindow = "1h" | "24h" | "7d" | "30d";
export type HistoryOutletKind = "subscription" | "local_proxy" | "unknown";
export type HistoryEventType = "probe" | "state" | "route_switch";

export interface HistoryFilter {
  window: HistoryWindow;
  outlet_id: string | null;
  kind: HistoryOutletKind | null;
  status: HealthStatus | null;
  event_type: HistoryEventType | null;
  page: number;
  page_size: number;
}

export interface HistoryMetric {
  outlet_id: string;
  label: string;
  kind: HistoryOutletKind;
  deleted: boolean;
  sample_count: number;
  online_samples: number;
  availability_percent: number;
  p50_latency_ms: number | null;
  p95_latency_ms: number | null;
  failure_count: number;
  failure_duration_seconds: number;
  ongoing_failure: boolean;
  confirmed_route_switches: number;
}

export interface HistoryOutletOption {
  outlet_id: string;
  label: string;
  kind: HistoryOutletKind;
  deleted: boolean;
}

export interface HistoryRecord {
  event_type: HistoryEventType;
  occurred_at: string;
  outlet_id: string;
  outlet_label: string;
  outlet_kind: HistoryOutletKind;
  deleted: boolean;
  status: HealthStatus | null;
  from_status: HealthStatus | null;
  to_status: HealthStatus | null;
  latency_ms: number | null;
  from_outlet_id: string | null;
  to_outlet_id: string | null;
  mode: string | null;
  reason: string | null;
  duration_ms: number | null;
}

export interface HistoryResponse {
  window_start: string;
  window_end: string;
  metrics: HistoryMetric[];
  outlets: HistoryOutletOption[];
  records: HistoryRecord[];
  total_count: number;
  page: number;
  total_pages: number;
  next_page: number | null;
  retention_days: number;
}

export interface HistoryExport {
  path: string;
  rows: number;
}

export interface UdpCapabilityEvidence {
  outlet_id: string;
  status: UdpCapabilityStatus;
  observed_at: string;
  evidence_version: number;
  probe_version: string;
  model_version: number;
  configuration_fingerprint: string;
  configuration_generation: number;
  reason_code: string;
}

export interface PortSnapshot {
  host: string;
  port: number;
  reachable: boolean;
  owner_pid: number | null;
}

export interface CoreStatus {
  state: "running" | "stopped" | "external";
  managed: boolean;
  pid: number | null;
  started_at: string | null;
  message: string;
}

export interface OutletSummary {
  outlet_id: string;
  label: string;
  samples: number;
  successful_samples: number;
  failed_samples: number;
  availability_percent: number;
  average_latency_ms: number | null;
  last_status: HealthStatus;
  last_observed_at: string | null;
}

export interface LatencySample {
  outlet_id: string;
  observed_at: string;
  port_reachable: boolean;
  status: HealthStatus;
  latency_ms: number | null;
  error_code: string | null;
  successful_targets: number;
  total_targets: number;
}

export interface StateEvent {
  outlet_id: string;
  occurred_at: string;
  from_status: HealthStatus;
  to_status: HealthStatus;
  reason: string;
}

export interface RouteSwitchEvent {
  occurred_at: string;
  from_outlet: string | null;
  to_outlet: string;
  mode: RouteMode;
  reason: string;
  duration_ms: number;
}

export interface RoutingStatus {
  mode: RouteMode;
  current_outlet: string | null;
  manual_outlet: string | null;
  controller_ready: boolean;
  outlets: RoutingOutlet[];
  message: string;
}

export interface RoutingOutlet {
  outlet_id: string;
  label: string;
  kind: "subscription" | "local_proxy";
  enabled: boolean;
  endpoint: string | null;
  configured: boolean;
}

export interface DashboardSnapshot {
  updated_at: string;
  entry: PortSnapshot;
  mihomo: CoreStatus;
  routing: RoutingStatus;
  summaries: OutletSummary[];
  samples: LatencySample[];
  events: StateEvent[];
  route_switches: RouteSwitchEvent[];
  udp_capabilities: UdpCapabilityEvidence[];
}

export type RouteMode = "priority" | "fastest" | "manual";
