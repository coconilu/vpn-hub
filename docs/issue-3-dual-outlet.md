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

桌面端首次运行会在 `%LOCALAPPDATA%\VPN Hub\private-routing.toml` 创建私密配置，并通过 Windows ACL 将文件权限收敛给当前用户与 `SYSTEM`。运行时配置、provider 缓存和 Mihomo 日志保存在同一目录下的 `runtime`，也应用相同权限策略。

在总览的密码输入框粘贴订阅地址并保存。应用只向界面返回“已配置/未配置”，不会返回地址。以下内容不会写入 SQLite 或普通事件日志：订阅 URL/token、provider 节点信息、Controller secret、探测目标响应。

仓库中的 [private-routing.example.toml](../config/private-routing.example.toml) 只说明结构，`subscription_url` 必须保持为空。

## 三种真实模式

| 模式 | Controller 行为 | 异常行为 |
|---|---|---|
| 优先级 | 按 `priority` 选择第一个稳定健康出口 | 当前出口失败时立即切换；高优先级恢复后等待冷却期再回切 |
| 最低延迟 | 选择多目标样本中平均延迟最低的稳定健康出口 | 只有改善超过阈值且冷却期结束才切换，避免抖动 |
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

真实订阅格式与双出口外网请求必须由用户在本机密码框录入订阅后验证；订阅凭据不得通过终端参数、CI、Issue、PR 或测试日志注入。若服务端返回的不是 Mihomo/Clash proxy-provider 兼容格式，开发核心会保持 Fail Closed，不能把兼容性伪报为通过。

本阶段不包含 SpeedCat `26666`、`6666` 接管、TUN、完整 UDP、Windows Service、托盘、签名或长连接无缝迁移。
