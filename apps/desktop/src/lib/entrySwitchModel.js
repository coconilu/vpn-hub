const LOOPBACK_V4 = /^127(?:\.\d{1,3}){3}$/;

export function buildEntrySwitchFoundationPreview(current, target, applySystemProxy, confirmed) {
  const issues = [];
  const normalizedHost = target.host.toLowerCase() === "localhost" ? "127.0.0.1" : target.host;
  const ipv4Parts = normalizedHost.split(".").map(Number);
  const loopback = normalizedHost === "::1" || normalizedHost === "[::1]"
    || (LOOPBACK_V4.test(normalizedHost) && ipv4Parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255));
  if (!loopback) issues.push({ code: "loopback_required", message: "入口只能绑定显式 loopback 地址。" });
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
    issues.push({ code: "invalid_port", message: "入口端口必须在 1–65535 之间。" });
  }
  if (current.host === target.host && current.port === target.port) {
    issues.push({ code: "entry_unchanged", message: "目标入口与当前入口相同。" });
  }
  if (!confirmed) issues.push({ code: "confirmation_required", message: "请确认理解切换顺序和回滚边界。" });
  issues.push({
    code: "isolated_acceptance_pending",
    message: "真实端口 ownership 与 WinINet 系统代理尚待隔离 Windows 验收；当前版本不会执行切换。",
  });
  return {
    apply_system_proxy: applySystemProxy,
    executable: false,
    issues,
    steps: [
      "取得交互用户 authority，并校验一次性 consent、配置代际与快照指纹",
      "暂存新配置和应用自管核心；未知或第三方占用立即拒绝",
      "验证 Controller ownership、全部启用出口与 Fail Closed",
      "提交应用入口；旧入口在此之前保持不变",
      applySystemProxy
        ? "使用 CAS 应用 WinINet 用户代理并回读验证；失败恢复完整 manual/PAC/auto-detect/override 快照"
        : "不调用任何系统代理 backend",
    ],
  };
}
