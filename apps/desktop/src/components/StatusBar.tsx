import { Box, Monitor, ShieldCheck } from "lucide-react";
import type { DashboardSnapshot } from "../types";

export function StatusBar({ snapshot }: { snapshot: DashboardSnapshot }) {
  const guardianActive = snapshot.summaries.length > 0;
  return (
    <footer className="status-bar">
      <span><i className={`dot ${guardianActive ? "healthy" : "neutral"}`} /><ShieldCheck />Guardian {guardianActive ? "已记录" : "待检测"}</span>
      <span><i className={`dot ${snapshot.mihomo.state === "running" ? "healthy" : "neutral"}`} /><Box />Mihomo {snapshot.mihomo.state === "running" ? "运行中" : "已停止"}</span>
      <span><Monitor />统一入口 {snapshot.entry.host}:{snapshot.entry.port} · 系统代理未修改</span>
    </footer>
  );
}
