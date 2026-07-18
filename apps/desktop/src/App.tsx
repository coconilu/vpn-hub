import { useCallback, useEffect, useState } from "react";
import { Construction } from "lucide-react";
import { Dashboard } from "./Dashboard";
import { Sidebar, type ViewId } from "./components/Sidebar";
import { StatusBar } from "./components/StatusBar";
import { getDashboardSnapshot, refreshGuardian, startDevelopmentCore, stopDevelopmentCore } from "./lib/bridge";
import type { DashboardSnapshot, RouteMode } from "./types";

export default function App() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [view, setView] = useState<ViewId>("overview");
  const [mode, setMode] = useState<RouteMode>("priority");
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
    const timer = window.setTimeout(() => setNotice(null), 4_500);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const handleRefresh = async () => {
    setBusy(true);
    try {
      setSnapshot(await refreshGuardian());
      setNotice("检测已完成，结果已写入 Guardian 历史库");
    } catch (error) {
      setNotice(String(error));
    } finally {
      setBusy(false);
    }
  };

  const handleCoreToggle = async () => {
    if (!snapshot) return;
    setBusy(true);
    try {
      const status = snapshot.mihomo.state === "running" ? await stopDevelopmentCore() : await startDevelopmentCore();
      setNotice(status.message);
      await load();
    } catch (error) {
      setNotice(String(error));
    } finally {
      setBusy(false);
    }
  };

  if (!snapshot) return <div className="loading-screen"><span className="brand-mark">V</span><p>正在读取本地状态…</p></div>;

  return (
    <div className="app-shell">
      <Sidebar active={view} onChange={setView} />
      <div className="content-column">
        {view === "overview" ? (
          <Dashboard snapshot={snapshot} mode={mode} busy={busy} notice={notice} onModeChange={setMode} onRefresh={handleRefresh} onCoreToggle={handleCoreToggle} />
        ) : (
          <main className="placeholder-view"><Construction /><h1>{view === "history" ? "历史" : "设置"}</h1><p>入口已预留；当前阶段先完成总览、实时检测和开发核心管理。</p><button type="button" onClick={() => setView("overview")}>返回总览</button></main>
        )}
        <StatusBar snapshot={snapshot} />
      </div>
    </div>
  );
}
