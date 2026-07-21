# Issue #10：桌面托盘与生命周期恢复

## 行为契约

桌面壳只负责把窗口、托盘和操作系统事件投递给单例 coordinator。控制入口使用固定大小的原子位集与 `Notify`：重复信号会合并，`Exit`、`Stop` 不会因队列已满而丢失；Guardian、恢复启动和网络采样在受控后台任务中执行，不阻塞事件接收。

| 事件 | 状态 / effect | 对应用自管核心的影响 |
| --- | --- | --- |
| 关闭窗口 | `HideWindow` | 不停止，应用留在托盘 |
| 托盘“打开” / 左键 | `ShowAndFocusWindow` | 不启动或重启 |
| 托盘“停止核心 / 取消恢复” | durable `pending_stop` → bounded retry → `StopOwnedCore` | 取消手动启动、自动恢复和退避；只停止 `AppState` 当前持有或迟到发布的 owned child |
| 明确退出 / OS shutdown | cancel + bounded join → durable stop → permit exit | 每次等待与清理尝试都有 3 秒硬边界；若事务忙则保持事件循环并重试，确认 owned child 已清理后才允许退出 |
| owned child 意外退出 | 通知 → 有界退避 → restart → full Guardian | 独立 PID watcher 以 250ms 周期核对同一 owned PID |
| 配置提交 | 普通变更：`RefreshTray` → probe；运行时变更：受控 stop → restart → full Guardian | 运行时变更只有在新核心 PID、Controller ownership 和首次 Guardian 全部确认后才完成提交 |
| 手动路由模式 / 出口变更成功 | `RefreshTray` → collect transitions | Guardian 决策成功后立即刷新并发送一次跃迁通知，不追加 probe |
| 睡眠间隔 / 网络 fingerprint 变化 | coalesce → full Guardian | 保留数据库阈值、路由 cooldown 和 Fail Closed 状态机 |

## 并发与恢复事务

恢复启动、手动启动、停止和配置应用共享同一把 routing transaction 锁。自动恢复从启动前检查、child 发布、首次 Guardian 决策到最终提交均处于这条事务边界内。Stop 使用持久内存意图和 recovery epoch fence：命令最多等待 3 秒，未确认时返回 `stopping`，但 coordinator 会保持事件接收与有界重试，绝不提前投影 `stopped`。只有 `AppState` 确认没有 owned 或待发布 child 后，所有并发 Stop waiter 才一起完成；重复 Stop 和已经停止时的 Stop 都安全。配置应用只有在提交成功后才提升 epoch，预览过期、验证失败或提交失败不会取消既有退避恢复。

手动启动在首次 Guardian 前后都核对同一 PID、入口 listener 和 Controller listener 的进程归属。Controller 不可验证时，直连 Guardian fallback 只适用于普通无核心巡检，不能让手动启动成功。Stop 会设置手动启动的取消标记；若 child 在 Stop 后迟到发布，只精确清理该 PID，并丢弃 stale completion。

启动中的 child 由 `PendingChild` 守卫，在发布前出错、取消或任务被 abort 时都会 kill 并 wait，避免迟到子进程。`mihomo -t` 也使用可取消的 owned child 与异步状态轮询；控制任务首次等待超时后 abort，再执行一次有界 join，不做无上限等待。

恢复 worker 在 child 发布后立即记录预期 PID，并在首次 Guardian 前后都核对：

1. recovery epoch 仍是本次事务；
2. 取消标记未设置；
3. `AppState` 仍持有同一个 PID，且该进程存活。

任一条件不满足都会仅停止该 owned PID，不把 direct fallback 或已被替换的 PID 视为成功。恢复中的 child 早退会归类为本次启动失败并继续既有 attempt / terminal 策略，不会被普通取消分支吞掉。第一次自动替换也只有在首次完整 Guardian 成功后才产生 `CoreRecovered`。

连续自动启动最多尝试 5 次；达到上限后进入终止态并只发送一次去重通知。只有明确的用户配置提交或新的网络恢复信号可以重置该终止态，普通定时 tick 不会无限重试。

## 动态托盘投影

托盘菜单每次从 `PrivateRoutingConfig`、Guardian 数据库摘要和当前 `RoutingEngine` 重新构建，展示：

- 当前配置的 loopback `entry_host:entry_port`；
- 当前稳定 `outlet_id`，无可用出口时明确显示 `fail-closed`；
- 配置顺序下的所有逻辑出口及 enabled/disabled、health 状态；
- 在已有 owned child、手动启动中、自动恢复、退避等待或终止恢复态时启用“停止核心 / 取消恢复”；即使当前尚无 child，也允许用户幂等取消恢复。

新增、删除、停用、重排或修改入口后不复用旧投影。托盘不展示订阅 URL、节点、token、secret reference、探测目标或本机出口 endpoint。

## 通知与网络采样

通知由 Rust 后端通过 Tauri notification plugin 发送，且只从状态跃迁产生：出口 down / recovered、真实逻辑出口切换、进入 Fail Closed、配置入口冲突、owned core 意外退出、连续启动失败及恢复。相同语义 key 在时间窗内去重，正文只使用过滤后的 stable ID、安全 label、配置入口和计数。

Windows 网络变化检测使用隐藏的 owned `ipconfig /all` 子进程。stdout 由专用 reader 与子进程并行排空并流式计算 hash，不保留或记录原始输出。采样最多 2 秒；超时只 kill/wait 本次创建的 child，并始终 join reader。只有子进程成功退出且 reader 完整结束时才接受 fingerprint；失败样本保留上一份 fingerprint，不制造虚假网络变化。睡眠 / 唤醒和网络变化信号会在 mailbox 中合并。

## 安全边界

- 不安装 Service，不修改系统代理、TUN 或防火墙，不控制第三方客户端。
- 未知 listener 或未知 PID 只报告端口冲突，永不 kill/restart。
- coordinator 只通过 `AppState` 回收应用自己 spawn 并持有的 `Child`。
- 自动恢复以 startup Fail Closed 启动，完成一次 Guardian 全量健康决策后才视为恢复；决策失败则停止 owned child。
- 网络 / 睡眠恢复复用现有 Guardian 数据库阈值和 RoutingEngine cooldown，不清空健康证据，不承诺已有长连接无缝迁移。

## 验证策略

自动测试覆盖 reducer transition、重复事件、hide vs exit、启动 / 停止 epoch 乱序、有界退避与五次终止、恢复 child 早退、首次恢复提交、动态投影、手动路由即时刷新与单次 transition、通知去重与脱敏、固定容量 mailbox 洪泛、慢任务双重有界取消与 join、真实 `AppState` 事务串行化、失败配置不推进 recovery epoch、可取消校验 child、取消前不发布 child、未发布 child 的 RAII 回收、owned PID 早退 / 变化，以及网络采样的大输出、变化、失败、超时与清理。

真实桌面验收不得关闭用户正在运行的应用或代理，也不得接管 live 6666。无法唯一确认隔离窗口时，以 headless state-machine、Tauri compile、前端测试和 debug no-bundle 构建为准。
