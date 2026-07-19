import { LoaderCircle, Play, RefreshCw, Square } from "lucide-react";
import { EventTimeline } from "./components/EventTimeline";
import { LatencyChart } from "./components/LatencyChart";
import { OutletTable } from "./components/OutletTable";
import { ProtectedBanner } from "./components/ProtectedBanner";
import { RouteRail } from "./components/RouteRail";
import type { DashboardSnapshot, RouteMode } from "./types";

interface DashboardProps {
  snapshot: DashboardSnapshot;
  busy: boolean;
  notice: string | null;
  onModeChange: (mode: RouteMode, manualOutlet: string | null) => void;
  onRefresh: () => void;
  onUdpRevalidate: () => void;
  onCoreToggle: () => void;
}

const formatUpdatedAt = (value: string) => new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
}).format(new Date(value));

export function Dashboard({ snapshot, busy, notice, onModeChange, onRefresh, onUdpRevalidate, onCoreToggle }: DashboardProps) {
  const coreRunning = snapshot.mihomo.state === "running";
  const mode = snapshot.routing.mode;
  const selectableOutlets = snapshot.routing.outlets.filter((outlet) => outlet.enabled && outlet.configured);
  const manualOutlet = snapshot.routing.manual_outlet ?? selectableOutlets[0]?.outlet_id ?? "";

  return (
    <main className={`main-content ${busy ? "is-busy" : ""}`}>
      <header className="topbar">
        <div><h1>网络总览</h1><span>最近更新 {formatUpdatedAt(snapshot.updated_at)}</span></div>
        <div className="top-actions">
          <button className={`secondary-button ${coreRunning ? "stop" : ""}`} onClick={onCoreToggle} disabled={busy} type="button">
            {busy ? <LoaderCircle className="spin" /> : coreRunning ? <Square /> : <Play />}
            {coreRunning ? "停止开发核心" : "启动开发核心"}
          </button>
          <button className="icon-button" aria-label="立即检测" title="立即检测" onClick={onRefresh} disabled={busy} type="button">
            <RefreshCw className={busy ? "spin" : ""} />
          </button>
          <button className="secondary-button" onClick={onUdpRevalidate} disabled={busy || coreRunning} type="button">
            验证 UDP
          </button>
        </div>
      </header>
      {notice && <div className="notice" role="status">{notice}</div>}
      <ProtectedBanner entry={snapshot.entry} />

      <div className="mode-row">
        <h2>路由模式</h2>
        {([ ["priority", "优先级"], ["fastest", "最低延迟"], ["manual", "手动"] ] as const).map(([value, label]) => (
          <label key={value}>
            <input
              type="radio"
              name="mode"
              value={value}
              checked={mode === value}
              disabled={busy || !snapshot.routing.controller_ready || (value === "manual" && selectableOutlets.length === 0)}
              onChange={() => onModeChange(value, value === "manual" ? manualOutlet || null : null)}
            />
            <span>{label}</span>
          </label>
        ))}
        {mode === "manual" && (
          <select value={manualOutlet} disabled={busy || selectableOutlets.length === 0} onChange={(event) => onModeChange("manual", event.target.value)}>
            {selectableOutlets.map((outlet) => <option key={outlet.outlet_id} value={outlet.outlet_id}>{outlet.label}</option>)}
          </select>
        )}
        <small>{snapshot.routing.message}</small>
      </div>
      <RouteRail snapshot={snapshot} />
      <OutletTable snapshot={snapshot} />
      <div className="lower-grid"><LatencyChart samples={snapshot.samples} /><EventTimeline events={snapshot.events} switches={snapshot.route_switches} /></div>
    </main>
  );
}
