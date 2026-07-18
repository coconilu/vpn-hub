import type { DashboardSnapshot, HealthStatus } from "../types";

interface OutletRow {
  id: string;
  name: string;
  status: string;
  health: HealthStatus | "pending";
  port: string;
  latency: string;
  availability: string;
  lastDisconnect: string;
  role: string;
  selected?: boolean;
}

const formatTime = (value: string | null) => {
  if (!value) return "—";
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value));
};

const statusText: Record<HealthStatus, string> = {
  unknown: "未知",
  healthy: "正常",
  degraded: "退化",
  down: "异常/端口可达",
};

export function OutletTable({ snapshot }: { snapshot: DashboardSnapshot }) {
  const live = snapshot.summaries.find((item) => item.outlet_id === "chaoshihui");
  const rows: OutletRow[] = [
    { id: "subscription", name: "订阅 A", status: "待配置", health: "pending", port: "—", latency: "—", availability: "—", lastDisconnect: "—", role: "备用" },
    {
      id: "chaoshihui",
      name: "超实惠",
      status: live ? statusText[live.last_status] : snapshot.upstream_entry.reachable ? "端口可达/待检测" : "端口未就绪",
      health: live?.last_status ?? (snapshot.upstream_entry.reachable ? "unknown" : "down"),
      port: "16666",
      latency: live?.average_latency_ms == null ? "—" : `${Math.round(live.average_latency_ms)} ms`,
      availability: live ? `${live.availability_percent.toFixed(1)}%` : "—",
      lastDisconnect: formatTime(live?.last_observed_at ?? null),
      role: "当前开发出口",
      selected: true,
    },
    { id: "speedcat", name: "SpeedCat", status: "待迁移", health: "pending", port: "26666", latency: "—", availability: "—", lastDisconnect: "—", role: "备用" },
  ];

  return (
    <section className="table-section" aria-labelledby="outlets-title">
      <h2 id="outlets-title">出口状态</h2>
      <div className="table-scroll">
        <table>
          <thead><tr><th>出口</th><th>状态</th><th>端口</th><th>当前延迟</th><th>24h 在线率</th><th>最近检测</th><th>角色</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr className={row.selected ? "selected" : ""} key={row.id}>
                <td className="outlet-name">{row.name}</td>
                <td><span className={`status-cell ${row.health}`}><i />{row.status}</span></td>
                <td className="mono">{row.port}</td>
                <td className={row.health === "down" ? "danger-text" : ""}>{row.latency}</td>
                <td>{row.availability}</td><td>{row.lastDisconnect}</td><td>{row.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
