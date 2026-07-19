import { useCallback, useEffect, useState } from "react";
import { Construction } from "lucide-react";
import { Dashboard } from "./Dashboard";
import { HistoryPage } from "./HistoryPage";
import { Sidebar, type ViewId } from "./components/Sidebar";
import { StatusBar } from "./components/StatusBar";
import {
  getDashboardSnapshot,
  revalidateUdpCapabilities,
  refreshGuardian,
  setRouteMode,
  startDevelopmentCore,
  stopDevelopmentCore,
} from "./lib/bridge";
import type { DashboardSnapshot, RouteMode } from "./types";

export default function App() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [view, setView] = useState<ViewId>("overview");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSnapshot(await getDashboardSnapshot());
    } catch (error) {
      setNotice(String(error));
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 15_000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 6_000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const runBusy = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
    } catch (error) {
      setNotice(String(error));
    } finally {
      setBusy(false);
    }
  };

  const handleRefresh = () => runBusy(async () => {
    setSnapshot(await refreshGuardian());
    setNotice("多目标检测已完成；状态、延迟和真实切换已写入本机历史。");
  });

  const handleUdpRevalidate = (authorizedSubscriptionTargets: string[]) => runBusy(async () => {
    setSnapshot(await revalidateUdpCapabilities(authorizedSubscriptionTargets));
    setNotice(authorizedSubscriptionTargets.length >= 2
      ? "UDP 能力已重新验证；订阅目标仅用于本次端到端探测，不会写入配置、数据库或摘要。"
      : "本地客户端 UDP 能力已重新验证；订阅出口因缺少至少两个获准目标而保持未知。");
  });

  const handleCoreToggle = () => runBusy(async () => {
    if (!snapshot) return;
    if (snapshot.mihomo.state === "running") {
      const status = await stopDevelopmentCore();
      setNotice(status.message);
      await load();
      return;
    }
    const status = await startDevelopmentCore();
    setNotice(status.message);
    await load();
  });

  const handleModeChange = (mode: RouteMode, manualOutlet: string | null) => runBusy(async () => {
    setSnapshot(await setRouteMode(mode, manualOutlet));
    setNotice("已通过 Mihomo Controller 更新真实选择器策略。");
  });

  if (!snapshot) {
    return <div className="loading-screen"><span className="brand-mark">V</span><p>正在读取本机状态…</p></div>;
  }

  return (
    <div className="app-shell">
      <Sidebar active={view} onChange={setView} />
      <div className="content-column">
        {view === "overview" ? (
          <Dashboard
            snapshot={snapshot}
            busy={busy}
            notice={notice}
            onModeChange={handleModeChange}
            onRefresh={handleRefresh}
            onUdpRevalidate={handleUdpRevalidate}
            onCoreToggle={handleCoreToggle}
          />
        ) : view === "history" ? (
          <HistoryPage snapshot={snapshot} onNotice={setNotice} />
        ) : (
          <main className="placeholder-view">
            <Construction />
            <h1>设置</h1>
            <p>通用设置页面仍在后续范围内；历史保留策略已放在历史页就近管理。</p>
            <button type="button" onClick={() => setView("overview")}>返回总览</button>
          </main>
        )}
        <StatusBar snapshot={snapshot} />
      </div>
    </div>
  );
}
