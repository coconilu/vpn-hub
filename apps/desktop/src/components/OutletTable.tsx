import type { DashboardSnapshot, HealthStatus } from "../types";

const formatTime = (value: string | null) => value ? new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
}).format(new Date(value)) : "—";

const statusText: Record<HealthStatus, string> = {
  unknown: "未知",
  healthy: "正常",
  degraded: "部分目标异常",
  down: "不可用",
};

export function OutletTable({ snapshot }: { snapshot: DashboardSnapshot }) {
  const rows = [
    { id: "subscription-a", name: "订阅 A", port: "provider", configured: snapshot.routing.subscription_configured },
    { id: "chaoshihui", name: "超实惠", port: "16666", configured: true },
  ].map((definition) => {
    const summary = snapshot.summaries.find((item) => item.outlet_id === definition.id);
    const health: HealthStatus | "pending" = definition.configured ? summary?.last_status ?? "unknown" : "pending";
    return {
      ...definition,
      summary,
      health,
      status: definition.configured ? statusText[summary?.last_status ?? "unknown"] : "待本机配置",
      selected: snapshot.routing.current_outlet === definition.id,
    };
  });

  return (
    <section className="table-section" aria-labelledby="outlets-title">
      <h2 id="outlets-title">出口状态</h2>
      <div className="table-scroll">
        <table>
          <thead><tr><th>出口</th><th>状态</th><th>接入</th><th>平均延迟</th><th>历史可用率</th><th>最近检测</th><th>角色</th></tr></thead>
          <tbody>{rows.map((row) => (
            <tr className={row.selected ? "selected" : ""} key={row.id}>
              <td className="outlet-name">{row.name}</td>
              <td><span className={`status-cell ${row.health}`}><i />{row.status}</span></td>
              <td className="mono">{row.port}</td>
              <td className={row.health === "down" ? "danger-text" : ""}>{row.summary?.average_latency_ms == null ? "—" : `${Math.round(row.summary.average_latency_ms)} ms`}</td>
              <td>{row.summary ? `${row.summary.availability_percent.toFixed(1)}%` : "—"}</td>
              <td>{formatTime(row.summary?.last_observed_at ?? null)}</td>
              <td>{row.selected ? "当前真实出口" : "候选出口"}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </section>
  );
}
