import { useCallback, useEffect, useState } from "react";
import { Construction } from "lucide-react";
import { Dashboard } from "./Dashboard";
import { Sidebar, type ViewId } from "./components/Sidebar";
import { StatusBar } from "./components/StatusBar";
import {
  getDashboardSnapshot,
  refreshGuardian,
  saveSubscriptionUrl,
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
    setSnapshot(await refreshGuardian());
  });

  const handleModeChange = (mode: RouteMode, manualOutlet: string | null) => runBusy(async () => {
    setSnapshot(await setRouteMode(mode, manualOutlet));
    setNotice("已通过 Mihomo Controller 更新真实选择器策略。");
  });

  const handleSubscriptionSave = (value: string) => runBusy(async () => {
    await saveSubscriptionUrl(value);
    await load();
    setNotice("订阅地址已保存到仅限当前用户访问的本机私密配置；启动开发核心后生效。");
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
            onSubscriptionSave={handleSubscriptionSave}
            onRefresh={handleRefresh}
            onCoreToggle={handleCoreToggle}
          />
        ) : (
          <main className="placeholder-view">
            <Construction />
            <h1>{view === "history" ? "历史" : "设置"}</h1>
            <p>完整页面仍在后续范围内；当前总览已经显示真实健康状态和路由切换。</p>
            <button type="button" onClick={() => setView("overview")}>返回总览</button>
          </main>
        )}
        <StatusBar snapshot={snapshot} />
      </div>
    </div>
  );
}
