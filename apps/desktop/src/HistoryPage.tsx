import { Download, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { exportHistory, getHistory, setHistoryRetention } from "./lib/bridge";
import { createLatestRequestGate } from "./lib/requestGeneration.js";
import type {
  HealthStatus,
  HistoryEventType,
  HistoryFilter,
  HistoryOutletKind,
  HistoryResponse,
  HistoryWindow,
} from "./types";

const initialFilter: HistoryFilter = {
  window: "24h",
  outlet_id: null,
  kind: null,
  status: null,
  event_type: null,
  page: 0,
  page_size: 100,
};

const formatDuration = (seconds: number) => {
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟`;
  return `${(seconds / 3600).toFixed(1)} 小时`;
};

const eventDescription = (record: HistoryResponse["records"][number]) => {
  if (record.event_type === "probe") {
    return `${record.status ?? "unknown"} · ${record.latency_ms === null ? "无延迟" : `${record.latency_ms} ms`}`;
  }
  if (record.event_type === "state") {
    return `${record.from_status ?? "unknown"} → ${record.to_status ?? "unknown"} · ${record.reason ?? "state_change"}`;
  }
  return `${record.from_outlet_id ?? "Fail Closed"} → ${record.to_outlet_id ?? record.outlet_id} · ${record.mode ?? "unknown"}`;
};

interface HistoryPageProps {
  onNotice: (message: string) => void;
}

export function HistoryPage({ onNotice }: HistoryPageProps) {
  const [filter, setFilter] = useState(initialFilter);
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retention, setRetention] = useState(30);
  const requestGate = useRef(createLatestRequestGate());

  const load = useCallback(async () => {
    const generation = requestGate.current.begin();
    setLoading(true);
    setError(null);
    try {
      const response = await getHistory(filter);
      if (!requestGate.current.isLatest(generation)) return;
      setHistory(response);
      setRetention(response.retention_days);
      if (response.page !== filter.page) {
        setFilter((current) => ({ ...current, page: response.page }));
      }
    } catch (reason) {
      if (!requestGate.current.isLatest(generation)) return;
      setError(String(reason));
    } finally {
      if (!requestGate.current.isLatest(generation)) return;
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    void load();
    return () => { requestGate.current.begin(); };
  }, [load]);

  const update = <K extends keyof HistoryFilter>(key: K, value: HistoryFilter[K]) => {
    setFilter((current) => ({ ...current, [key]: value, page: 0 }));
  };
  const showsProbeMetrics = filter.event_type === null || filter.event_type === "probe";
  const showsFailureMetrics = (filter.event_type === null || filter.event_type === "state")
    && (filter.status === null || filter.status === "down");
  const showsSwitchMetrics = (filter.event_type === null || filter.event_type === "route_switch")
    && filter.status === null;

  const runExport = async () => {
    setLoading(true);
    try {
      const result = await exportHistory(filter);
      onNotice(`已导出 ${result.rows} 行脱敏 CSV：${result.path}`);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  };

  const saveRetention = async () => {
    setLoading(true);
    try {
      const removed = await setHistoryRetention(retention);
      onNotice(`保留期已更新为 ${retention} 天；清理 ${removed} 条过期记录，进行中故障和当前证据已保留。`);
      await load();
    } catch (reason) {
      setError(String(reason));
      setLoading(false);
    }
  };

  return (
    <main className="history-view">
      <header className="history-header">
        <div><h1>历史</h1><p>只显示脱敏健康证据与 Controller 已确认的真实切换。</p></div>
        <div className="history-actions">
          <label>保留 <input type="number" min="1" max="3650" value={retention} onChange={(event) => setRetention(Number(event.target.value))} /> 天</label>
          <button type="button" className="secondary-button" disabled={loading} onClick={() => void saveRetention()}>保存</button>
          <button type="button" className="secondary-button" disabled={loading} onClick={() => void runExport()}><Download />导出 CSV</button>
          <button type="button" className="icon-button" aria-label="刷新历史" disabled={loading} onClick={() => void load()}><RefreshCw className={loading ? "spin" : ""} /></button>
        </div>
      </header>

      <section className="history-filters" aria-label="历史筛选">
        <select value={filter.window} onChange={(event) => update("window", event.target.value as HistoryWindow)}>
          <option value="1h">最近 1 小时</option><option value="24h">最近 24 小时</option><option value="7d">最近 7 天</option><option value="30d">最近 30 天</option>
        </select>
        <select value={filter.outlet_id ?? ""} onChange={(event) => update("outlet_id", event.target.value || null)}>
          <option value="">全部出口</option>{history?.outlets.map((outlet) => <option key={outlet.outlet_id} value={outlet.outlet_id}>{outlet.label}{outlet.deleted ? "（已删除）" : ""}</option>)}
        </select>
        <select value={filter.kind ?? ""} onChange={(event) => update("kind", (event.target.value || null) as HistoryOutletKind | null)}>
          <option value="">全部类型</option><option value="subscription">订阅</option><option value="local_proxy">本地客户端</option><option value="unknown">旧版未知</option>
        </select>
        <select value={filter.status ?? ""} onChange={(event) => update("status", (event.target.value || null) as HealthStatus | null)}>
          <option value="">全部状态</option><option value="healthy">健康</option><option value="degraded">降级</option><option value="down">故障</option><option value="unknown">未知</option>
        </select>
        <select value={filter.event_type ?? ""} onChange={(event) => update("event_type", (event.target.value || null) as HistoryEventType | null)}>
          <option value="">全部事件</option><option value="probe">健康样本</option><option value="state">故障状态</option><option value="route_switch">真实切换</option>
        </select>
      </section>

      {error ? <div className="history-message error">历史加载失败：{error}</div> : null}
      {loading && !history ? <div className="history-message">正在后台查询本机历史…</div> : null}
      {history ? (
        <>
          <section className="history-metrics">
            {history.metrics.map((metric) => (
              <article key={metric.outlet_id}>
                <div><strong>{metric.label}</strong>{metric.deleted ? <span>已删除</span> : null}</div>
                <dl>
                  <div><dt>在线率</dt><dd>{showsProbeMetrics ? `${metric.availability_percent.toFixed(1)}%` : "—"}</dd></div>
                  <div><dt>P50 / P95</dt><dd>{showsProbeMetrics ? `${metric.p50_latency_ms ?? "—"} / ${metric.p95_latency_ms ?? "—"} ms` : "—"}</dd></div>
                  <div><dt>故障</dt><dd>{showsFailureMetrics ? `${metric.failure_count} 次 · ${formatDuration(metric.failure_duration_seconds)}${metric.ongoing_failure ? " · 进行中" : ""}` : "—"}</dd></div>
                  <div><dt>确认切换</dt><dd>{showsSwitchMetrics ? `${metric.confirmed_route_switches} 次` : "—"}</dd></div>
                  <div><dt>样本</dt><dd>{showsProbeMetrics ? metric.sample_count : "—"}</dd></div>
                </dl>
              </article>
            ))}
            {!loading && history.metrics.length === 0 ? <div className="history-message">当前筛选范围没有健康样本。</div> : null}
          </section>

          <section className="history-records">
            <div className="section-heading-row"><h2>事件与真实切换</h2><span>{new Date(history.window_start).toLocaleString()} — {new Date(history.window_end).toLocaleString()}</span></div>
            <div className="table-scroll">
              <table><thead><tr><th>时间</th><th>出口</th><th>类型</th><th>详情</th></tr></thead>
                <tbody>{history.records.map((record, index) => (
                  <tr key={`${record.event_type}-${record.occurred_at}-${index}`}>
                    <td>{new Date(record.occurred_at).toLocaleString()}</td>
                    <td><span className="outlet-name">{record.outlet_label}</span>{record.deleted ? <small className="deleted-tag">已删除</small> : null}</td>
                    <td>{record.event_type === "route_switch" ? "真实切换" : record.event_type === "state" ? "状态" : "样本"}</td>
                    <td className="mono">{eventDescription(record)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            {!loading && history.records.length === 0 ? <div className="history-message">当前筛选范围没有事件。</div> : null}
            <div className="history-pagination">
              <button type="button" className="secondary-button" disabled={loading || history.page === 0} onClick={() => setFilter((value) => ({ ...value, page: history.page - 1 }))}>上一页</button>
              <span>共 {history.total_count} 条 · 第 {history.total_pages === 0 ? 0 : history.page + 1} / {history.total_pages} 页 · 每页最多 {filter.page_size} 条</span>
              <button type="button" className="secondary-button" disabled={loading || history.next_page === null} onClick={() => setFilter((value) => ({ ...value, page: value.page + 1 }))}>下一页</button>
            </div>
          </section>
        </>
      ) : null}
    </main>
  );
}
