export type HealthStatus = "unknown" | "healthy" | "degraded" | "down";

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
}

export type RouteMode = "priority" | "fastest" | "manual";
