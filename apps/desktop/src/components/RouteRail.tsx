import { Box, Globe2, Monitor } from "lucide-react";
import type { DashboardSnapshot } from "../types";

export function RouteRail({ snapshot }: { snapshot: DashboardSnapshot }) {
  const active = snapshot.mihomo.state === "running";
  return (
    <section className="route-section" aria-labelledby="route-title">
      <div className="section-heading-row">
        <h2 id="route-title">当前路由</h2>
        <span className={active ? "route-state running" : "route-state"}>
          {active ? "开发链路已建立" : "开发核心未启动"}
        </span>
      </div>
      <div className={`route-rail ${active ? "is-active" : ""}`}>
        <div className="route-node"><Monitor /><span><strong>应用</strong><small>显式测试请求</small></span></div>
        <div className="route-edge"><span>127.0.0.1:36666</span></div>
        <div className="route-node"><Box /><span><strong>Mihomo</strong><small>本地代理内核</small></span></div>
        <div className="route-edge"><span>127.0.0.1:16666</span></div>
        <div className="route-node end"><Globe2 /><span><strong>互联网</strong><small>经超实惠出口</small></span></div>
      </div>
    </section>
  );
}
