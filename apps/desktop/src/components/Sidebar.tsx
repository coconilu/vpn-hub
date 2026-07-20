import { History, LayoutDashboard, Settings, ShieldCheck } from "lucide-react";

export type ViewId = "overview" | "history" | "settings";

interface SidebarProps {
  active: ViewId;
  onChange: (view: ViewId) => void;
}

const items = [
  { id: "overview" as const, label: "总览", icon: LayoutDashboard },
  { id: "history" as const, label: "历史", icon: History },
  { id: "settings" as const, label: "设置", icon: Settings },
];

export function Sidebar({ active, onChange }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark"><ShieldCheck aria-hidden="true" /></span>
        <span>VPN Hub</span>
      </div>
      <nav aria-label="主导航">
        {items.map(({ id, label, icon: Icon }) => (
          <button
            className={`nav-item ${active === id ? "is-active" : ""}`}
            key={id}
            onClick={() => onChange(id)}
            type="button"
          >
            <Icon aria-hidden="true" />
            <span>{label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-safety">
        <ShieldCheck aria-hidden="true" />
        <div><strong>安全开发模式</strong><span>系统代理保持不变</span></div>
      </div>
    </aside>
  );
}
