# Issue #32：运行中安全应用设置并重启自管核心

> 后续决策：Issue #42 / ADR-004 已将首次完整 Guardian 从同步提交条件移到后台，并优先使用同 PID Controller reload。本文保留为旧重启事务与恢复边界的历史依据；冲突处以 ADR-004 为准。

## 事务边界

设置页保留一次性预览票据。预览是纯读操作；当路由运行配置或订阅凭据发生变化且自管核心正在运行时，返回 `requires_managed_core_restart`，而不是要求用户先手动停止。

一次确认后的顺序固定为：

```text
预览票据与候选 `mihomo -t` 校验
  -> authoritative owned PID + Controller ownership 复核
  -> coordinator Stop（停止优先，取消后台/迟到启动）
  -> 再次校验票据和候选
  -> 原子提交到 runtime_validation_pending
  -> 启动 Fail Closed 新核心
  -> 同一 PID 的入口/Controller listener 复核
  -> 首次 Controller Guardian 周期
  -> finalized + 清理回滚点
```

设置应用使用独立的 async gate 串行化完整流程；每个配置、路由和 Guardian 临界段仍在既有 routing transaction lock 下执行。Stop 本身通过 coordinator 获取 routing lock，因此应用命令不会在持锁状态等待 Stop，避免锁重入死锁。停止前后都会重新校验一次性票据，预览被覆盖或草稿变化时不会提交。

## ownership 与 Fail Closed

- 只接受 Supervisor authority 返回的 owned PID；桌面进程还要求该 PID 同时持有配置入口和随机 secret 的 loopback Controller listener。
- 本次闭环只提交 `DesktopOwned` 核心实际读取的用户设置文件。Helper-owned 核心读取安装器保护的 ProgramData manifest/runtime config；在新增受保护的 Helper 设置部署协议前，预览和应用都会明确拒绝运行时变更，不能把只写用户目录误报为成功重载。
- PID、authority 或 Controller 任一项不可证明时，在停止和持久化之前失败；未知 listener、外部 Mihomo 和第三方客户端绝不被停止或改写。
- 新核心始终从 `REJECT` 选择器启动，不存在 `DIRECT` fallback。首次 Guardian 前后的迟到停止、PID 变化和 Controller ownership 丢失都会精确清理本次 owned child。
- 本流程不调用系统代理、TUN、DNS、Windows Service 或第三方客户端接口，也不接管 live `6666`。

## 回滚与崩溃恢复

运行中重载新增 durable `runtime_validation_pending` 阶段。该阶段保留 private/Guardian 主文件及 `.bak` 快照、Secret Store rollback ref 和无明文 journal：

| 失败点 | 结果 |
|---|---|
| 候选校验、ownership 或精确停止失败 | 当前配置不变；可证明的当前核心保持不变或明确保持停止 |
| 提交前文件/凭据失败 | 既有设置事务恢复旧文件和旧凭据 |
| 新核心启动、PID/Controller 回读或首次 Guardian 失败 | 停止本次 owned child，强制恢复最后有效配置；没有用户 Stop 时尝试恢复旧核心 |
| 用户 Stop/取消与启动完成竞争 | recovery epoch 使 Stop 优先；恢复配置但不发布迟到核心 |
| 应用在 `runtime_validation_pending` 崩溃 | 下次初始化回滚旧文件和旧凭据，不把未验证候选当作已提交配置；若异常终止后候选子进程仍存活，则只报告为 external，不越权停止 |
| 旧核心恢复失败 | 本次手动恢复立即进入 terminal Fail Closed，不追加后台重试 |

历史保留清理和出口目录同步只在新核心通过权威回读后执行。事务已写入 `finalized` 后即使清理临时回滚点失败，也保留已验证的新配置，并由下次初始化幂等清理。

## 验证

自动测试覆盖一次性票据、并发设置 gate、运行中预览、未知 PID 不停止、HelperOwned 拒绝、`runtime_validation_pending` 直接持久化与崩溃回滚、Secret Store 恢复和既有 Guardian/生命周期回归。完整 stop → restart → Guardian 闭环仍需固定 Mihomo 的隔离验收；真实网络测试只允许显式授权的隔离环境与随机 loopback 端口。
