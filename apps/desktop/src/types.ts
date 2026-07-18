export type HealthStatus = "unknown" | "healthy" | "degraded" | "down";

export interface PortSnapshot {
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
}

export interface StateEvent {
  outlet_id: string;
  occurred_at: string;
  from_status: HealthStatus;
  to_status: HealthStatus;
  reason: string;
}

export interface DashboardSnapshot {
  updated_at: string;
  protected_entry: PortSnapshot;
  development_entry: PortSnapshot;
  upstream_entry: PortSnapshot;
  mihomo: CoreStatus;
  summaries: OutletSummary[];
  samples: LatencySample[];
  events: StateEvent[];
}

export type RouteMode = "priority" | "fastest" | "manual";
