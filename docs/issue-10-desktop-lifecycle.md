# Issue #10：桌面托盘与生命周期恢复

## 行为契约

桌面壳只负责把窗口、托盘和操作系统事件投递给单例 coordinator。状态 reducer 生成 effect，coordinator 串行执行 effect；Guardian、应用自管 Mihomo 和恢复探测不会因重复窗口事件而启动第二份。

| 事件 | 状态/effect | 对应用自管核心的影响 |
| --- | --- | --- |
| 关闭窗口 | `HideWindow` | 不停止，应用留在托盘 |
| 托盘“打开”/左键 | `ShowAndFocusWindow` | 不启动或重启 |
| 托盘“停止应用自管核心” | `StopOwnedCore` | 只停止 `AppState` 当前持有的 child |
| 明确退出 / OS shutdown | stop → permit exit → `app.exit` | 先回收 owned child，再退出；重复事件幂等 |
| owned child 意外退出 | 通知 → 有界退避 → restart → full probe | 只恢复可证明 ownership 的核心 |
| 配置提交 | coalesce → full probe → tray refresh | 重新读取当前动态配置，不缓存入口或出口 |
| 睡眠间隔 / 网络 fingerprint 变化 | coalesce → full probe | 保留数据库阈值、路由 cooldown 和 Fail Closed 状态机 |

## 动态托盘投影

托盘菜单每次从 `PrivateRoutingConfig`、Guardian 数据库摘要和当前 `RoutingEngine` 重新构建，展示：

- 当前配置的 loopback `entry_host:entry_port`；
- 当前稳定 `outlet_id`，无可用出口时明确显示 `fail-closed`；
- 配置顺序下的所有逻辑出口及 enabled/disabled、health 状态；
- 只在确有应用 owned child 时启用“停止应用自管核心”。

新增、删除、停用、重排或修改入口后不复用旧投影。托盘不展示订阅 URL、节点、token、secret reference、探测目标或本机出口 endpoint。

## 通知与恢复

通知由 Rust 后端通过 Tauri notification plugin 发送，前端没有新增通知权限。通知只从以下状态跃迁产生：

- outlet 进入 down、从 down/degraded 恢复 healthy；
- 真实逻辑出口切换、进入 Fail Closed；
- 配置入口冲突；
- owned core 意外退出、连续启动失败和恢复。

相同语义 key 在时间窗内去重；历史事件还有独立的有界 seen 集合，因此周期 probe 不会重复发送旧事件。正文仅使用经过过滤的 stable ID、允许的安全 label、配置入口和计数。

Windows 网络变化检测通过隐藏的 owned `ipconfig /all` 子进程计算内存 fingerprint：输出不记录、不持久化，2 秒内未结束即只终止并等待该 owned child。连续采样的 monotonic time gap 用于识别睡眠/唤醒。两类信号在 5 秒窗口合并为一次全量探测。

## 安全边界

- 不安装 Service，不修改系统代理、TUN、防火墙，不控制第三方客户端。
- 未知 listener 或未知 PID 只报告端口冲突，永不 kill/restart。
- coordinator 退出时只调用 `AppState::stop_development_core`，该方法只持有应用自己 spawn 的 `Child`。
- 自动恢复先以 startup Fail Closed 启动，完成一次 Guardian 全量健康决策后才视为恢复；健康决策失败则停止 owned child 并继续有界退避。
- 网络/睡眠恢复复用现有 Guardian 数据库阈值和 RoutingEngine cooldown，不清空健康证据，不承诺已有长连接无缝迁移。

## 验证策略

自动测试覆盖 reducer transition table、重复/重叠事件、hide vs exit、unexpected exit/backoff、动态投影、通知 transition/dedupe/脱敏、恢复信号 coalesce。现有 runtime 隔离测试继续证明随机 loopback 入口冲突不会终止未知 listener。真实桌面验收不得关闭用户正在运行的应用或代理；未能唯一确认隔离窗口时，以 headless state-machine、Tauri compile 和 browser mock 为准。
