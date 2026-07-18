import { LoaderCircle, Play, RefreshCw, Save, Square } from "lucide-react";
import { useState } from "react";
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
  onSubscriptionSave: (value: string) => void;
  onRefresh: () => void;
  onCoreToggle: () => void;
}

const formatUpdatedAt = (value: string) => new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
}).format(new Date(value));

export function Dashboard({ snapshot, busy, notice, onModeChange, onSubscriptionSave, onRefresh, onCoreToggle }: DashboardProps) {
  const [subscriptionUrl, setSubscriptionUrl] = useState("");
  const coreRunning = snapshot.mihomo.state === "running";
  const mode = snapshot.routing.mode;
  const manualOutlet = snapshot.routing.manual_outlet ?? "chaoshihui";

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
        </div>
      </header>
      {notice && <div className="notice" role="status">{notice}</div>}
      <ProtectedBanner protectedEntry={snapshot.protected_entry} developmentEntry={snapshot.development_entry} />

      {!snapshot.routing.subscription_configured && (
        <form className="subscription-setup" onSubmit={(event) => {
          event.preventDefault();
          onSubscriptionSave(subscriptionUrl);
          setSubscriptionUrl("");
        }}>
          <div><strong>订阅 A 尚未配置</strong><small>地址只写入本机私密文件，不进入日志、数据库或界面快照。</small></div>
          <input
            type="password"
            value={subscriptionUrl}
            onChange={(event) => setSubscriptionUrl(event.target.value)}
            placeholder="粘贴 HTTPS 订阅地址"
            autoComplete="off"
            disabled={busy || coreRunning}
          />
          <button className="secondary-button" type="submit" disabled={busy || coreRunning || !subscriptionUrl}><Save />保存</button>
        </form>
      )}

      <div className="mode-row">
        <h2>路由模式</h2>
        {([ ["priority", "优先级"], ["fastest", "最低延迟"], ["manual", "手动"] ] as const).map(([value, label]) => (
          <label key={value}>
            <input
              type="radio"
              name="mode"
              value={value}
              checked={mode === value}
              disabled={busy || !snapshot.routing.controller_ready}
              onChange={() => onModeChange(value, value === "manual" ? manualOutlet : null)}
            />
            <span>{label}</span>
          </label>
        ))}
        {mode === "manual" && (
          <select value={manualOutlet} disabled={busy} onChange={(event) => onModeChange("manual", event.target.value)}>
            {snapshot.routing.subscription_configured && <option value="subscription-a">订阅 A</option>}
            <option value="chaoshihui">超实惠</option>
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
