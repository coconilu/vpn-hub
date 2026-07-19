# Issue #3：双出口自动切换开发版

## 已实现拓扑

```text
应用 -> 127.0.0.1:36666 -> VPN-HUB-MASTER
                              |-- VPN-HUB-SUBSCRIPTION-A -> Mihomo proxy provider
                              |-- VPN-HUB-CHAOSHIHUI -> 127.0.0.1:16666
                              `-- REJECT（全部不可用或手动出口异常）
```

- 唯一开发入口是 `127.0.0.1:36666`。
- Controller 仅绑定 `127.0.0.1:39090`，每次生成 256-bit 随机 secret。
- `VPN-HUB-MASTER` 启动时首先选择 `REJECT`；只有健康判断完成且 Controller 确认切换后才开放出口。
- 配置没有 `DIRECT`，因此全部出口失败时不会回退到本机直连。
- 本功能没有修改系统代理、TUN 或 `127.0.0.1:6666` 的代码路径。

## 本机私密配置

桌面端首次运行会在 `%LOCALAPPDATA%\VPN Hub\private-routing.toml` 创建私密配置，并通过 Windows ACL 将文件权限收敛给当前用户与 `SYSTEM`。运行时配置和 provider 缓存保存在同一目录下的 `runtime`，也应用相同权限策略。Mihomo 的 stdout/stderr 会直接丢弃，不持久化原始输出；AppState 初始化时会无条件删除旧版本留下的 raw log，删除失败会用不含路径或原内容的诊断阻断核心启动。

在总览的密码输入框粘贴订阅地址并保存。应用只向界面返回“已配置/未配置”，不会返回地址。以下内容不会写入 SQLite 或普通事件日志：订阅 URL/token、provider 节点信息、Controller secret、探测目标响应。

仓库中的 [private-routing.example.toml](../config/private-routing.example.toml) 只说明结构，`subscription_url` 必须保持为空。

## 三种真实模式

| 模式 | Controller 行为 | 异常行为 |
|---|---|---|
| 优先级 | 按 `priority` 选择第一个稳定健康出口 | 当前出口失败时立即切换；高优先级恢复后等待冷却期再回切 |
| 最低延迟 | 选择本周期多目标样本中位数延迟最低的稳定健康出口 | 只有双方延迟可比、改善超过阈值且冷却期结束才切换，避免抖动 |
| 手动 | 直接选择指定的健康出口 | 指定出口不可用时选择 `REJECT`，不偷换到其他出口 |

失败和恢复阈值来自 Guardian 配置。默认连续 2 次失败才进入 `down`，连续 3 次成功才恢复。默认冷却期 60 秒、最低延迟改善阈值 150ms。

每次检测分别通过 Controller delay API 对三个 HTTPS 目标发起请求。至少两个目标成功才满足多数派；单目标失败只会降级，不会直接判定整个出口断线。

## 历史记录

SQLite `user_version=2` 新增多目标成功数和 `route_switches` 表。后者只在 Controller 返回成功后记录切换时间、前后出口、模式、脱敏原因和耗时。UI 显示的是该确认结果，不再使用单独的前端状态冒充真实切换。

## Provider 更新不等于第三方客户端换节点

| 能力 | 本项目能否控制 |
|---|---|
| Mihomo 订阅 A provider 按配置周期拉取 | 能，默认 180 秒 |
| Mihomo 在订阅 provider 内执行 `url-test` | 能 |
| 选择订阅 A 或超实惠作为 VPN Hub 出口 | 能，通过 loopback Controller |
| 要求超实惠客户端在其内部切换节点 | 不能；没有经过验证的公开接口 |

本项目不会通过 UI 自动化、逆向私有 IPC 或未公开接口控制第三方客户端。

## 验收与限制

自动化测试覆盖配置安全约束、无 `DIRECT`、Controller 非 loopback 拒绝、优先级故障切换/恢复冷却、最低延迟迟滞、手动 Fail Closed、全部出口失败和 SQLite 切换记录。

2026-07-18 至 2026-07-19 的受控现场验收已确认：用户可通过 v0.2 密码框在本机保存真实订阅，私密文件 ACL、provider cache 和 Controller 启动符合约束；优先级模式可经订阅 A 从 `36666` 访问外网；手动模式可经超实惠从 `36666` 访问外网；最低延迟模式的迟滞、`16666` 故障切换与三次成功恢复、手动出口不可用时 Fail Closed 与恢复均有 Controller、历史或端到端请求证据。完整脱敏证据见 [Issue #3 受控现场验收：真实订阅与双出口](compatibility/2026-07-18-issue-3-live-subscription.md)。

| 现场验收项 | 状态 |
|---|---|
| 本机私密订阅、ACL、provider cache、Controller ready | 已确认 |
| 优先级模式选择订阅 A，并经 `36666` 发起真实外网请求 | 已确认 |
| 手动模式选择超实惠，Controller/历史一致，并经 `36666` 发起真实外网请求 | 已确认 |
| 最低延迟模式字段、Controller 选择与 `150 ms` 迟滞 | 已确认 |
| `16666` 两次失败后的真实切换及 `36666` 外网请求 | 已确认 |
| `16666` 连续三次成功恢复与无抖动行为 | 已确认 |
| 手动出口不可用时 Fail Closed、禁止偷换及恢复 | 已确认 |
| 订阅 A 失败后的真实切换 | 现场未完成，已拆分到 Issue #5；不能标记为通过 |
| 两个出口同时不可用时 live all-down | 现场未完成，已拆分到 Issue #5；不能标记为通过 |

最低延迟模式已通过后续用户直接操作和 Controller/端到端结果完成验证，不依赖此前误指向 Codex 窗口句柄的自动化操作。手动模式中的 `manual_outlet_unavailable` Fail Closed 发生时订阅 A 仍健康，它只证明“禁止偷换手动出口”，不能冒充两个出口同时不可用的 live all-down。订阅凭据不得通过终端参数、CI、Issue、PR 或测试日志注入；若服务端返回的不是 Mihomo/Clash proxy-provider 兼容格式，开发核心会保持 Fail Closed，不能把兼容性伪报为通过。

用户已批准把订阅 A 真实故障切换和双出口同时不可用的 live all-down 拆分到 Issue #5。Issue #3 的交付边界是本 PR 已有的自动化覆盖，以及本轮真实 `16666` 故障切换、恢复和手动 Fail Closed 现场验收；拆分不代表两项隔离 live 验收已经通过。Issue #3 与 PR 保持 open/Draft，等待独立复审后再由维护者决定是否转为 Ready。

本阶段不包含 SpeedCat `26666`、`6666` 接管、TUN、完整 UDP、Windows Service、托盘、签名或长连接无缝迁移。
