# ADR-004：安全配置提交与外部连接健康解耦

- 状态：Accepted
- 日期：2026-07-22
- 关联：Issue #42；D-005、D-009、D-011、D-012

## 背景

旧流程把候选校验、设置事务、核心重启、首次完整 Guardian 和 provider/外部目标请求串在一次前台操作中。Guardian 又按“出口 × 目标”串行执行，使不可控的远端超时进入保存按钮的完成条件。安全检查本身不是两分钟延迟的必要原因；真正的问题是本地安全生效和外部连接可用没有分层。

## 决策

“配置已生效”的权威边界止于本地：原子持久化、exact-owned PID、loopback 入口、受鉴权 Controller 和 `MASTER`/`UDP` 双 `REJECT` 回读。provider 下载、出口探测、UDP 能力和自动选路在返回成功后由带 generation/cancellation 的后台任务完成。

运行中配置优先对同一 owned PID 执行 Controller reload；安全回读失败时只精确停止该 PID，并在有界预算内重启。取消若发生在 runtime 已触达核心之后，必须完成“停止候选运行态 → 回滚持久化 → 恢复最后有效核心”的补偿，不能只返回取消错误。

Guardian 使用有界并发和单轮全局 deadline，保留部分结果。任何外部失败都不能把选择器降级到 `DIRECT`，也不能覆盖较新的配置 generation。

## 替代方案

| 方案 | 结论 | 原因 |
|---|---|---|
| 保留同步首次 Guardian，仅缩短单请求超时 | 拒绝 | 仍把出口数和外部网络质量线性叠加到保存延迟 |
| 所有变更都停止并重启核心 | 拒绝 | 可用但中断多，且浪费 Mihomo 已有的受鉴权 reload 能力 |
| 保存后立即返回，不做本地回读 | 拒绝 | 可能把未监听、错误 PID 或失去 Fail Closed 的状态误报为成功 |
| 单一明文 JSON 任意字段直写 | 拒绝 | 破坏 schema、Secret Store、原子恢复和权限边界，不能解决 runtime 权威性 |

## 后果

正面结果是普通设置不重启核心，入口/出口变更通常同 PID 生效，远端慢响应不再阻塞前台。代价是 UI 和状态模型必须明确区分“配置已生效”与“连接可用”，后台任务必须处理取消、部分结果和 provider 重试。

D-011 中“首次 Guardian 权威回读前保持可回滚”的要求由 D-012 收窄：可回滚承诺持续到本地 runtime 与双 `REJECT` 权威回读完成；首次完整 Guardian 不再是提交点。PID、Controller ownership、回滚、Secret Store 和 Fail Closed 约束保持不变。

## 迁移与回滚

该变更不迁移用户明文数据，也不改变 Secret Store key。回滚代码时，既有配置和事务 journal 仍可由旧恢复逻辑读取；应先停止应用自管核心，再回滚二进制，避免新后台 generation 与旧同步流程并存。若热重载兼容性在固定 Mihomo 版本上回归，可单独关闭 warm reload 并保留有界 exact-owned restart，而无需恢复同步 Guardian。
