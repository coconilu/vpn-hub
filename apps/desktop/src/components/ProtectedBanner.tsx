import { LockKeyhole } from "lucide-react";
import type { PortSnapshot } from "../types";

interface ProtectedBannerProps {
  entry: PortSnapshot;
}

export function ProtectedBanner({ entry }: ProtectedBannerProps) {
  return (
    <section className="protected-banner" aria-label="端口保护状态">
      <div className="protected-title">
        <LockKeyhole aria-hidden="true" />
        <strong>配置驱动入口 · 系统代理保持不变</strong>
      </div>
      <div className="protected-value">
        <span>统一入口</span>
        <strong>{entry.host}:{entry.port}</strong>
        <i className={entry.reachable ? "dot healthy" : "dot neutral"} />
      </div>
      <div className="protected-value production">
        <span>监听范围</span>
        <strong>Loopback only</strong>
        <em>不启用 LAN</em>
      </div>
    </section>
  );
}
