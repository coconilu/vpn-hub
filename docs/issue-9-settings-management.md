# Issue #9：安全设置管理

设置页把统一入口、动态出口、Guardian 参数和历史保留期组合成一个可预览的设置草稿。订阅凭据不属于草稿：读取接口只返回 `configured / missing / unavailable / corrupted`，覆盖值只存在于一次 `apply_settings` 入参和 Windows 受保护存储调用路径中。

## 校验与预览

`preview_settings` 是纯读操作，不接收凭据值。它复用版本化路由配置校验，并额外拒绝：

- 没有启用出口（Guardian 的 monitor-only 空出口配置仍然合法）；
- 非 loopback 入口或本地出口、重复/保留 ID、类型偷换、入口端口冲突；
- 不安全名称、非 HTTPS 探测目标和不合理的超时、阈值、冷却、刷新与保留期；
- 删除当前出口但未选择启用的替代出口，也未明确进入 Fail Closed；
- 入口切换或其他不属于普通设置事务的受保护操作。自管 Mihomo 运行中修改路由或凭据不再作为预览错误；预览会标记需要按 Issue #32 执行受控重启。

预览只返回字段级问题和脱敏变更摘要。它不会启动 Mihomo、绑定端口、写配置、读取凭据原文或改变系统网络设置。

## 持久化事务

应用操作由现有 routing transaction lock 串行化，并使用无明文 durable journal：

```text
prepared
  -> backups_ready
  -> credentials_staged
  -> private_committed
  -> guardian_committed
  -> commit_decided -> finalized（普通设置）
  -> runtime_validation_pending -> finalized（运行中重载）
```

事务开始时会：

1. 快照 private/Guardian 的主文件和 `.bak`；
2. 把已有订阅凭据复制到同一 Windows Secret Store 的临时 rollback ref；
3. 在隔离临时目录生成候选 Mihomo YAML，并用仓库锁定 binary 的 `-t` 校验；
4. 原子替换 private 与 Guardian 配置；
5. 写入 durable `commit_decided` 后才删除不再引用或明确删除的 current credential，并提交历史保留期；
6. 清理 rollback ref、文件快照和 journal。

journal 只记录 phase、文件存在位、secret ref、动作和目标保留期，不记录订阅 URL、token、Controller secret 或节点信息。

## 崩溃恢复

应用启动时先恢复未完成事务，再加载路由配置：

- `commit_decided` 之前：恢复四个文件快照和旧凭据；没有旧值的新凭据会删除；
- 普通设置的 `commit_decided` 之后：保留已提交配置，幂等完成凭据删除与 retention；
- 运行中重载的 `runtime_validation_pending`：应用崩溃或新核心未通过 Controller/Guardian 回读时恢复四个旧文件与旧凭据；只有权威回读成功后才进入 `finalized`；
- 恢复结束后才清理 rollback ref 和 journal，因此清理中再次崩溃仍可重试。

自动测试模拟了每个 pre-commit phase、新凭据暂存和 commit decision 后的重启恢复。固定 Mihomo 验收只使用临时目录与随机、未绑定的 loopback 端口，不启动核心，也不接触 3666/6666。

## UI 状态和安全边界

设置页明确显示 loading、dirty、preview、applying、success 和 error 状态；使用原生 label、按钮、select、password input、focus error summary 和 `aria-live` 状态。窄窗口会把表单和出口行折叠成单列。

普通设置没有修改系统代理、防火墙、TUN、Service 或第三方客户端的 API，也没有 DIRECT 故障策略。运行中需要改变 Mihomo 的设置会先校验候选配置和 ownership，再精确停止 owned core；新核心失败时恢复最后有效配置。
