import { Box, Globe2, Monitor } from "lucide-react";
import type { DashboardSnapshot } from "../types";

const outletLabel: Record<string, string> = {
  "subscription-a": "订阅 A",
  chaoshihui: "超实惠",
  "fail-closed": "Fail Closed",
};

export function RouteRail({ snapshot }: { snapshot: DashboardSnapshot }) {
  const active = snapshot.mihomo.state === "running";
  const current = snapshot.routing.current_outlet;
  const target = current ? outletLabel[current] ?? current : "等待首次健康决策";
  return (
    <section className="route-section" aria-labelledby="route-title">
      <div className="section-heading-row">
        <h2 id="route-title">当前路由</h2>
        <span className={active ? "route-state running" : "route-state"}>
          {active ? `${snapshot.routing.mode} · ${target}` : "开发核心未启动"}
        </span>
      </div>
      <div className={`route-rail ${active ? "is-active" : ""}`}>
        <div className="route-node"><Monitor /><span><strong>应用</strong><small>显式测试请求</small></span></div>
        <div className="route-edge"><span>127.0.0.1:36666</span></div>
        <div className="route-node"><Box /><span><strong>Mihomo</strong><small>本机真实选择器</small></span></div>
        <div className="route-edge"><span>{target}</span></div>
        <div className="route-node end"><Globe2 /><span><strong>互联网</strong><small>{current === "fail-closed" ? "已拒绝直连回退" : "经当前健康出口"}</small></span></div>
      </div>
    </section>
  );
}
