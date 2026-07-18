import { LockKeyhole } from "lucide-react";
import type { PortSnapshot } from "../types";

interface ProtectedBannerProps {
  protectedEntry: PortSnapshot;
  developmentEntry: PortSnapshot;
}

export function ProtectedBanner({ protectedEntry, developmentEntry }: ProtectedBannerProps) {
  return (
    <section className="protected-banner" aria-label="端口保护状态">
      <div className="protected-title">
        <LockKeyhole aria-hidden="true" />
        <strong>开发模式 · 未接管 6666</strong>
      </div>
      <div className="protected-value">
        <span>测试入口</span>
        <strong>127.0.0.1:{developmentEntry.port}</strong>
        <i className={developmentEntry.reachable ? "dot healthy" : "dot neutral"} />
      </div>
      <div className="protected-value production">
        <span>生产入口</span>
        <strong>127.0.0.1:{protectedEntry.port}</strong>
        <em>保持不变</em>
      </div>
    </section>
  );
}
