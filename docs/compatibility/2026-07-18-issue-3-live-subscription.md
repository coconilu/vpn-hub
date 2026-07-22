# Issue #3 受控现场验收：真实订阅与双出口

日期：2026-07-18 至 2026-07-19

范围：VPN Hub v0.2 开发核心，入口 `127.0.0.1:36666`

结论：优先级模式的订阅 A 链路、手动 Local client 链路、最低延迟迟滞、`16666` 故障切换与恢复、手动 Fail Closed 与恢复均已完成真实现场验收。订阅 A 真实故障切换和双出口同时不可用的 live all-down 现场未完成，已由用户批准拆分到 Issue #5，不能标记为通过。

本文只记录脱敏结果，不包含订阅 URL/token、provider 节点名、Controller secret 或 provider 原文。

## 私密配置与启动

| 验收项 | 现场结果 | 状态 |
|---|---|---|
| 订阅录入 | 用户通过 v0.2 密码框在本机保存订阅并启动开发核心 | 已确认 |
| 私密文件 ACL | 仅当前用户与 `SYSTEM` 拥有 `FullControl` | 已确认 |
| Provider | provider cache 已生成 | 已确认 |
| Controller | loopback Controller ready | 已确认 |
| 主选择组约束 | `VPN-HUB-MASTER` 只允许 `REJECT`、`VPN-HUB-OUTLET-subscription-a`、`VPN-HUB-OUTLET-local-client` 三个固定项 | 已确认 |

## 优先级模式

现场 UI 显示当前优先出口为订阅 A。健康检测中，订阅 A 延迟约 `53–54 ms`、在线率 `100%`；Local client 延迟约 `838–906 ms`、在线率约 `60%`。历史记录中已有真实切换事件。

下表是同一现场的端到端请求结果。`36666` 表示通过 VPN Hub，`16666` 是 Local client 端口对照；时间为单次观测值，不代表长期性能基准。

| 目标 | 经 `36666` | 耗时 | 经 `16666` 对照 | 耗时 |
|---|---:|---:|---:|---:|
| Google | 204 | 0.295 s | 204 | 1.939 s |
| Gstatic | 204 | 0.228 s | 204 | 1.576 s |
| GitHub | 200 | 0.444 s | 200 | 2.310 s |
| Baidu | 200 | 0.386 s | 200 | 0.073 s |

结论：在优先级模式下，`36666` 已通过真实外网请求证明可经订阅 A 出口工作。上述对照只证明当次请求差异，不用于推断所有目标或所有时段的速度。

## 手动模式

用户通过 VPN Hub UI 切换为默认手动出口 Local client 后，现场获得以下一致证据：

| 证据 | 现场结果 |
|---|---|
| UI | 显示 `manual · Local client` |
| 切换记录 | 存在原因 `manual_selection` 的 `route_switch` 事件 |
| Controller | `VPN-HUB-MASTER` 确认为 `VPN-HUB-OUTLET-local-client` |

| 目标 | 经 `36666` | 耗时 |
|---|---:|---:|
| Google | 204 | 1.979 s |
| Gstatic | 204 | 0.986 s |
| Baidu | 200 | 0.059 s |

结论：UI 模式、持久化切换事件、Controller 实际选择和端到端外网请求四类证据一致，手动 Local client 链路已确认。

## 最低延迟模式与 `16666` 故障切换

2026-07-19，用户从手动 Local client 切换到 `fastest`（最低延迟）模式。模式字段已生效，但策略没有立即切换出口：

| 观测项 | 脱敏结果 |
|---|---|
| 订阅 A 延迟 | 约 `55–57 ms` |
| Local client 延迟 | 约 `187–188 ms` |
| 当次改善幅度 | 约 `131–133 ms` |
| 配置阈值 | `150 ms` |
| Controller 结果 | 保持 Local client，不切换 |
| 端到端结果 | `36666` 的真实出口与 `16666` 一致，Google 请求成功 |

当次改善低于阈值，因此保持当前健康出口符合最低延迟迟滞策略，不能把“延迟数字更低”直接等同于“必须立即切换”。

随后用户在最低延迟模式下关闭 Local client，得到以下状态序列：

| 检测阶段 | 健康状态与路由结果 |
|---|---|
| 第一次失败 | 尚未达到失败阈值，不切换 |
| 第二次失败 | Local client 进入 `down`；Controller 确认从 Local client 切到订阅 A，原因 `lowest_latency_policy` |
| 切换后外网请求 | `36666` 的 Google、Gstatic、GitHub、Baidu 均成功 |
| 用户重新启动 Local client 后的前两次成功 | 仍未达到恢复阈值，状态不提前恢复 |
| 第三次连续成功 | Local client 从 `down` 恢复为 `healthy`；路由仍保持订阅 A，没有抖动回切 |

这组结果确认了连续两次失败阈值、最低延迟模式的真实故障切换、连续三次成功恢复阈值和恢复后的无抖动行为。

## 手动模式 Fail Closed 与恢复

用户再次切到手动 Local client 并关闭 Local client 后，现场结果如下：

| 检测阶段 | 健康状态与路由结果 |
|---|---|
| 第一次失败 | 尚未达到失败阈值，不切换 |
| 第二次失败 | Controller 确认从 Local client 切到 `REJECT`，原因 `manual_outlet_unavailable` |
| 其他出口 | 订阅 A 仍为 `healthy`，但手动模式没有偷换出口 |
| Fail Closed 请求 | `36666` 的 Google、Baidu 均快速失败，HTTP `000`，没有获得 HTTP 响应 |
| 用户重新启动 Local client 后的前两次成功 | 仍保持未恢复状态 |
| 第三次连续成功 | Local client 恢复为 `healthy`；Controller 确认从 `REJECT` 切回 Local client |
| 恢复后请求 | `36666` 恢复可用，真实出口与 `16666` 一致 |

这里验证的是“手动指定出口不可用时 Fail Closed”。由于订阅 A 当时仍健康，这不属于也不能替代“双出口同时不可用”的 live all-down 验收。

## 测试后保护状态

测试结束后核对到以下状态，说明本轮验收没有接管既有 `6666` 系统代理链路：

| 项目 | 测试后状态 |
|---|---|
| `127.0.0.1:6666` | PID `64908` |
| `127.0.0.1:16666` | PID `70700` |
| `127.0.0.1:36666` / `127.0.0.1:39090` | Mihomo PID `38832` |
| Windows 系统代理 | `ProxyEnable=1`，`ProxyServer=127.0.0.1:6666` |

PID 只用于记录该次受控验收结束时的进程边界，不是稳定配置或后续诊断依据。

2026-07-19 最终状态为：用户已切回最低延迟模式；因当次延迟改善仍低于 `150 ms` 阈值，Controller 保持 Local client A，Google 请求成功。端口角色仍为 `6666` Local client B、`16666` Local client A、`36666/39090` Mihomo，Windows 系统代理仍为 `127.0.0.1:6666`。本轮未接管或改变既有系统代理链路。

## 验收矩阵

| 场景 | 状态 | 说明 |
|---|---|---|
| 本机私密订阅、ACL、provider cache、Controller ready | 已确认 | 未暴露任何私密原文 |
| 优先级模式选择订阅 A 并经 `36666` 访问外网 | 已确认 | UI、健康数据、切换历史和端到端请求已观察 |
| 手动选择 Local client 并经 `36666` 访问外网 | 已确认 | UI、事件、Controller 和端到端请求一致 |
| 最低延迟模式字段、Controller 选择与迟滞阈值 | 已确认 | 改善低于 `150 ms` 时保持当前健康出口，端到端请求成功 |
| `16666` 故障后的真实切换 | 已确认 | 两次失败后切到订阅 A，原因 `lowest_latency_policy`，四个外网目标均成功 |
| `16666` 恢复阈值与无抖动行为 | 已确认 | 连续三次成功后才恢复为健康，路由没有立即抖动回切 |
| 手动出口故障时 Fail Closed 与恢复 | 已确认 | 没有偷换到健康的订阅 A；恢复也遵守连续三次成功阈值 |
| 订阅 A 故障后的真实切换 | 现场未完成，已拆分到 Issue #5 | 尚未执行隔离现场故障注入，不能标记为通过 |
| 两个出口同时不可用时 live all-down | 现场未完成，已拆分到 Issue #5 | 自动化已有覆盖，但尚无双出口同时故障的现场证据；手动 Fail Closed 不计入此项，也不能标记为通过 |

Issue #3 的交付边界是本 PR 的自动化覆盖，以及本文已确认的真实 `16666` 故障切换、恢复和手动 Fail Closed 现场验收。两项隔离 live 验收由 Issue #5 继续跟踪；Issue #3 与 PR 保持 open/Draft，等待独立复审后再由维护者决定是否转为 Ready。
