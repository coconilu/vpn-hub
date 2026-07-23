import type { DashboardSnapshot, OutletProbePhase, SubscriptionSourcePhase, UdpCapabilityStatus } from "../types";

const formatTime = (value: string | null) => value ? new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
}).format(new Date(value)) : "—";

const statusText: Record<OutletProbePhase, string> = {
  not_configured: "待凭据接入",
  waiting_for_probe_runtime: "等待探测运行时",
  probing: "正在检测",
  healthy: "正常",
  degraded: "部分目标异常",
  down: "不可用",
};

const udpText: Record<UdpCapabilityStatus, string> = {
  supported: "支持 UDP",
  tcp_only: "仅 TCP",
  unknown: "UDP 未知",
};

const sourceText: Record<SubscriptionSourcePhase, string> = {
  not_applicable: "—",
  not_configured: "未配置",
  waiting: "加载中",
  available: "源已就绪",
  unavailable: "源不可用",
};

export function OutletTable({ snapshot }: { snapshot: DashboardSnapshot }) {
  const rows = snapshot.routing.outlets.map((definition) => {
    const summary = snapshot.summaries.find((item) => item.outlet_id === definition.outlet_id);
    const active = definition.enabled && definition.configured;
    const udp = snapshot.udp_capabilities.find((item) => item.outlet_id === definition.outlet_id);
    const probe = snapshot.probe_views.find((item) => item.outlet_id === definition.outlet_id);
    const health: OutletProbePhase | "pending" = active ? probe?.phase ?? "probing" : "pending";
    return {
      ...definition,
      summary,
      probe,
      health,
      access: definition.kind === "subscription" ? "Mihomo provider" : definition.endpoint ?? "—",
      status: !definition.enabled ? "已停用" : statusText[probe?.phase ?? (definition.configured ? "probing" : "not_configured")],
      selected: snapshot.routing.current_outlet === definition.outlet_id,
      udp,
    };
  });

  return (
    <section className="table-section" aria-labelledby="outlets-title">
      <h2 id="outlets-title">出口状态</h2>
      <div className="table-scroll">
        <table>
          <thead><tr><th>出口</th><th>出口健康</th><th>订阅源</th><th>UDP 能力</th><th>接入</th><th>本轮延迟</th><th>历史可用率</th><th>最近检测</th><th>角色</th></tr></thead>
          <tbody>{rows.map((row) => (
            <tr className={row.selected ? "selected" : ""} key={row.outlet_id}>
              <td className="outlet-name">{row.label}</td>
              <td><span className={`status-cell ${row.health}`}><i />{row.status}</span></td>
              <td>
                {sourceText[row.probe?.source_phase ?? (row.kind === "subscription" ? "waiting" : "not_applicable")]}
                {row.probe?.source_phase === "available" ? <><br /><small>不代表出口健康</small></> : null}
              </td>
              <td title={row.udp ? `${row.udp.reason_code} · ${row.udp.probe_version}` : "尚无证据"}>
                {udpText[row.udp?.status ?? "unknown"]}<br /><small>{formatTime(row.udp?.observed_at ?? null)}</small>
              </td>
              <td className="mono">{row.access}</td>
              <td className={row.health === "down" ? "danger-text" : ""}>{row.probe?.latency_ms == null ? "—" : `${Math.round(row.probe.latency_ms)} ms`}</td>
              <td>{row.summary ? `${row.summary.availability_percent.toFixed(1)}%` : "—"}</td>
              <td title={row.probe?.reason_code ?? undefined}>{formatTime(row.probe?.observed_at ?? null)}</td>
              <td>{row.selected ? "当前真实出口" : "候选出口"}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </section>
  );
}
