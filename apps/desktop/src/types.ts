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

export type SubscriptionNodeGroupState = "available" | "core_unavailable" | "provider_unavailable";

export interface SubscriptionNode {
  name: string;
  proxy_type: string;
  alive: boolean | null;
  latency_ms: number | null;
}

export interface SubscriptionNodeGroup {
  subscription_id: string;
  label: string;
  state: SubscriptionNodeGroupState;
  current_node: string | null;
  nodes: SubscriptionNode[];
}

export interface SubscriptionNodeCatalog {
  controller_ready: boolean;
  subscriptions: SubscriptionNodeGroup[];
  message: string;
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

export type CredentialState = "configured" | "missing" | "unavailable" | "corrupted";
export type LocalProxyProtocol = "http" | "socks5" | "socks5h";

export type SettingsOutlet =
  | {
      kind: "subscription";
      outlet_id: string;
      label: string;
      enabled: boolean;
      provider_update_seconds: number;
    }
  | {
      kind: "local_proxy";
      outlet_id: string;
      label: string;
      enabled: boolean;
      protocol: LocalProxyProtocol;
      host: string;
      port: number;
    };

export interface SettingsDraft {
  entry: { host: string; port: number };
  route_mode: RouteMode;
  manual_outlet: string | null;
  cooldown_seconds: number;
  minimum_improvement_ms: number;
  probe_targets: string[];
  refresh_interval_seconds: number;
  connect_timeout_ms: number;
  request_timeout_ms: number;
  failure_threshold: number;
  recovery_threshold: number;
  retention_days: number;
  outlets: SettingsOutlet[];
}

export interface SafeSettingsView {
  draft: SettingsDraft;
  credentials: Array<{ subscription_id: string; state: CredentialState }>;
}

export interface ValidationIssue {
  field: string;
  code: string;
  message: string;
}

export interface SettingsDiff {
  changes: Array<{ code: string; summary: string }>;
  runtime_changed: boolean;
  monitor_changed: boolean;
  retention_changed: boolean;
}

export interface SettingsPreview {
  diff: SettingsDiff;
  issues: ValidationIssue[];
  can_apply: boolean;
  requires_managed_core_restart: boolean;
  request_fingerprint: string;
  tun_plan: SafeTunPlanPreview;
}

export interface SafeTunPlanPreview {
  requested_enabled: boolean;
  active: boolean;
  supported: boolean;
  consent_required: boolean;
  reason_code: string;
  generation: string;
  subscription_outlet_ids: string[];
  local_outlet_ids: string[];
  missing_executable_identity_outlet_ids: string[];
  control_plane_policy: string;
  core_policy: string;
  local_outlet_policy: string;
  leak_matrix_disposition: string;
}

export interface CredentialMutationIntent {
  subscription_id: string;
  action: "set" | "delete";
}

export interface SettingsPreviewRequest {
  draft: SettingsDraft;
  credential_intents: CredentialMutationIntent[];
  active_outlet_replacement: string | null;
  fail_closed_on_removed_active: boolean;
  request_fingerprint: string;
}

export interface CredentialMutation {
  subscription_id: string;
  action: "set" | "delete";
  credential: string | null;
}

export interface SettingsApplyRequest {
  draft: SettingsDraft;
  credential_mutations: CredentialMutation[];
  active_outlet_replacement: string | null;
  fail_closed_on_removed_active: boolean;
  preview_fingerprint: string;
}

export interface SettingsApplyResult {
  settings: SafeSettingsView;
  diff: SettingsDiff;
  removed_history_rows: number;
  managed_core_restarted: boolean;
}
