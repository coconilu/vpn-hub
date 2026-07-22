# Issue #42：快速配置与连接主路径

## 用户可见语义

配置提交和外部网络健康不再是同一个完成条件。

| 状态 | 完成条件 | 是否阻塞“应用” |
|---|---|---:|
| 配置已生效 | 候选已原子持久化；owned runtime 已读取；loopback 入口、受鉴权 Controller 和双 `REJECT` 已权威回读 | 是，且有硬超时 |
| 正在连接 | 配置已生效，但 provider 或出口健康尚未完成 | 否 |
| 连接可用 | 后台 Guardian 已确认至少一个可选出口并完成选路 | 否 |
| 加载失败 | provider 或健康检查失败，可独立重试 | 否，不要求再次保存 |

```mermaid
flowchart LR
    A["短表单：本地服务或订阅"] --> B["自动校验与原子提交"]
    B --> C{"同 PID 热重载可验证？"}
    C -->|是| D["入口 / Controller / 双 REJECT 回读"]
    C -->|否| E["仅停止 exact-owned PID 并有界重启"]
    E --> D
    D --> F["配置已生效，正在连接"]
    F --> G["后台 provider 与 Guardian 并发"]
    G --> H["连接可用或显示失败 / 重试"]
```

设置页只需一次“应用设置”：先自动预览，再立即提交。运行中新增、修改、停用出口，更新订阅凭据、provider 参数、探测目标和入口端口时，优先通过受鉴权 Controller 热重载同一 owned Mihomo PID；热重载无法证明安全时才进入受控重启。系统代理、TUN、Service 等中断型或高权限操作仍保留独立授权边界。

## 时间预算与任务优先级

| 阶段 | 总预算 / 默认上限 | 超时结果 |
|---|---:|---|
| `mihomo -t` 候选校验 | 2 秒 | 终止并回收 child，候选不发布 |
| listener ownership 等待 | 3 秒 | 精确停止 owned child，保持 `REJECT` |
| owned 核心本地发布 | 5 秒 | 不发布迟到结果 |
| 同 PID Controller reload | 命令 1 秒，总路径 4 秒 | 回滚 runtime YAML，转受控重启 |
| 受控重启 fallback | 10 秒验收预算 | 成功恢复或明确 Fail Closed |
| Guardian 出口 × 目标 | 默认 4 并发、全局 8 秒 | 保留部分结果，未完成项记 deadline |
| 前台无反馈阈值 | 2 秒 | 显示阶段与取消入口 |

后台 Guardian 不再持有完整的 routing transaction lock。设置或入口操作会取消旧 generation；取消标志在写入探测结果和修改选择器前复核，因此迟到结果不能覆盖新配置。所有 owned child 的终止等待也有界，不再调用无期限 `wait`。

## 热重载、回退与取消

热重载成功只代表本地安全状态成立，不代表订阅已下载或出口可达。验证顺序固定为：

1. 复核 exact-owned PID 同时持有旧入口和 Controller；目标端口不得由第三方持有。
2. 将 `MASTER`、`UDP` 强制为 `REJECT` 并回读。
3. 原子候选配置已进入可回滚阶段后写 runtime YAML，通过受鉴权 Controller reload。
4. 同一 PID 必须持有目标入口与 Controller；旧入口必须释放；双 `REJECT` 再次回读。
5. 事务收尾后立即返回“配置已生效，正在连接”，再调度后台 Guardian。

任何一步失败都不会操作未知进程。fallback 先精确停止已证明 ownership 的 PID，再启动最后有效或候选配置。用户取消时，若尚未进入不可分割的本地提交则立即退出；若候选 runtime 已触达核心，则先精确停止、回滚配置并恢复最后有效核心后报告恢复结果。

## Provider 渐进状态

订阅凭据安全保存和本地配置生效不等待远端 provider。节点列表区分 `provider_loading`、`available` 和 `provider_failed`；“重试”只向当前受鉴权 Controller 发出有界更新请求，provider 就绪后无需再次保存即可进入后台选路。

## 脱敏性能证据

内存中最多保留 256 个快速路径样本，并按阶段输出 P50/P95。样本只有 `stage`、`duration_ms`、`result_code`、`outlet_count` 四个字段；不包含时间戳、订阅 URL、节点名、Controller secret、探测目标或第三方进程参数。

确定性测试覆盖 Guardian 并发上限、全局 deadline、取消后不提交迟到结果、child 总超时，以及性能字段白名单。固定 Mihomo `v1.19.28` 的 ignored 隔离测试使用随机 loopback 端口验证同 PID 入口热重载和双 `REJECT`，不访问真实订阅、节点或现场端口。

墙钟基准必须独立串行执行，避免默认并行测试的文件系统争用污染 P95：

```powershell
cargo test -p vpn-hub-desktop ordinary_settings_apply_p95_stays_below_one_second_without_a_core --locked -- --ignored --nocapture
cargo test -p vpn-hub-desktop owned_core_hot_reloads_entry_and_outlets_without_changing_pid --locked -- --ignored --nocapture
```

2026-07-22 最终独立串行样本：普通设置 20 次为 P50 `702ms` / P95 `729ms`；固定 Mihomo 隔离路径为 warm reload P50 `238ms` / P95 `334ms`、入口启动 P50 `975ms` / P95 `1001ms`、fallback restart P50 `985ms` / P95 `999ms`。测试中的严格门槛仍分别为 1 秒、5 秒、5 秒和 10 秒，没有因并行环境噪声而放宽。

## 安全边界

- 无健康出口始终保持 `REJECT`，不存在 `DIRECT` fallback。
- 只管理应用创建且能证明 PID、入口和 Controller ownership 的核心。
- 本地服务仍是用户提供的 loopback 黑盒出口；不关闭、重启或改写第三方客户端。
- 本变更不启用 TUN、DNS 接管、LAN 监听、Windows Service，也不默认修改系统代理。
- 实机验收必须使用随机 loopback 端口；不得接管 live `6666`，不得上传真实凭据或节点信息。
