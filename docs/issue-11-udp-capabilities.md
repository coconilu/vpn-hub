# Issue #11：动态出口 UDP 能力与 TCP-only 约束

UDP 能力是与 Guardian TCP 健康状态独立的、以稳定 `outlet_id` 为键的证据模型。一次 UDP 失败不会把 TCP 健康出口标记为 `down`，也不会进入 `probe_samples` 或 `outlet_state`。

| 状态 | 含义 | UDP 路由行为 |
| --- | --- | --- |
| `supported` | 当前模型和探测版本有受控正向证据 | 可进入 `VPN-HUB-UDP` 候选 |
| `tcp_only` | 受控测试明确不支持 UDP | 必须排除 |
| `unknown` | 未验证、环境错误、证据不足或冲突 | 默认排除 |

每条证据包含 `observed_at`、`evidence_version`、`probe_version`、`model_version` 和脱敏 `reason_code`。SQLite `user_version=3` 使用 `udp_capability_current` 保存当前摘要，使用只追加的 `udp_capability_history` 保留重新验证前的结论。表中不保存探测目标、响应、节点、订阅、认证信息或出口 IP。

## 探测与重新验证

- `local_proxy` 的 `http` 接入按传输协议明确为 `tcp_only`。
- `socks5` / `socks5h` 使用原生 SOCKS5 `UDP ASSOCIATE`，目标是本进程临时创建的随机 loopback UDP echo；控制连接在整个探测期间保持存活。
- `UDP ASSOCIATE` 被协议明确拒绝时判为 `tcp_only`；关联成功但 echo 未回包仍可能是代理对 loopback 目标的路由差异，因此保持 `unknown`。代理不可达、响应损坏等环境错误同样保持 `unknown`，更不改变 TCP 健康。
- 订阅出口只有在 provider 已就绪且至少两个独立受控端到端结果一致时才成为 `supported` 或 `tcp_only`；不足或冲突保持 `unknown`。桌面端当前没有内置外部 UDP 目标，因而不会把真实业务目标或未经批准的公共服务当探测器，订阅默认保持 `unknown`。
- Issue #43 移除了总览中的手动外部 UDP 验证表单，普通用户不再需要准备或授权外部 Echo 目标。受控重新验证后端仍保留给隔离开发诊断；没有当前有效证据的订阅出口保持 `unknown`，重新启动时生成器继续读取最新证据。
- 端口完全来自动态出口配置；代码不绑定供应商或固定端口。仓库自动化只使用随机 loopback 端口，并显式排除开发默认端口和用户现场端口。

## 路由约束

生成配置包含两个独立选择器：

```text
NETWORK,UDP -> VPN-HUB-UDP -> supported outlets | REJECT
other       -> VPN-HUB-MASTER -> Guardian TCP decision | REJECT
```

`VPN-HUB-UDP` 启动时首先选择 `REJECT`。Guardian 只有在 TCP 路由决策指向的出口同时具有当前 `supported` 证据时，才把 UDP 选择器同步到该出口；`tcp_only`、`unknown`、全部不可用和手动 Fail Closed 都同步到 `REJECT`。生成配置没有 `DIRECT`。

固定 Mihomo `v1.19.28` 的隔离验收使用随机 loopback 端口、自持 sidecar 与 UDP echo，验证了 `NETWORK,UDP` 规则语法、Controller 选择器同步和正向 UDP 回包。验收不读取真实订阅、节点、认证信息或真实出口 IP，也不会触碰系统代理、TUN、Service 或第三方客户端。
