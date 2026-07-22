const LOOPBACK_V4 = /^127(?:\.(?:0|[1-9]\d{0,2})){3}$/;

export function isSupportedLoopbackHost(value) {
  const normalizedHost = value.toLowerCase() === "localhost" ? "127.0.0.1" : value;
  const ipv4Parts = normalizedHost.split(".").map(Number);
  return normalizedHost === "::1" || normalizedHost === "[::1]"
    || (LOOPBACK_V4.test(normalizedHost)
      && ipv4Parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255));
}

export function buildEntrySwitchFoundationPreview(current, target, applySystemProxy, confirmed) {
  const issues = [];
  if (!isSupportedLoopbackHost(target.host)) issues.push({ code: "loopback_required", message: "入口只能绑定显式 loopback 地址。" });
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
    issues.push({ code: "invalid_port", message: "入口端口必须在 1–65535 之间。" });
  }
  if (current.host === target.host && current.port === target.port) {
    issues.push({ code: "entry_unchanged", message: "目标入口与当前入口相同。" });
  }
  if (!confirmed) issues.push({ code: "confirmation_required", message: "请确认理解切换顺序和回滚边界。" });
  return {
    apply_system_proxy: applySystemProxy,
    executable: issues.length === 0,
    issues,
    steps: [
      "取得交互用户 authority，并校验一次性 consent、配置代际与快照指纹",
      "暂存新配置和应用自管核心；未知或第三方占用立即拒绝",
      "验证 Controller ownership、全部启用出口与 Fail Closed",
      "精确停止旧核心后验证新入口；失败时先确认新核心停止，再恢复旧入口",
      applySystemProxy
        ? "使用 query → compare → WinINet apply 并立即回读；检测到并发修改时回滚且不覆盖第三方新值"
        : "不调用任何系统代理 backend",
    ],
  };
}
