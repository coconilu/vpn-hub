# 实施路线图

## 阶段与退出条件

| 阶段 | 目标 | 关键产物 | 退出条件 |
|---|---|---|---|
| Phase 0 | 兼容性验证 | 端口、并行运行、SOCKS5 TCP/UDP、订阅格式报告 | 两个本地出口可同时稳定工作，或明确记录阻断结论 |
| Phase 1 | 无界面原型 | Mihomo 配置生成器、三出口策略、手工故障测试 | `6666` 稳定入口与三出口切换通过测试 |
| Phase 2 | Guardian 与记录 | Rust 守护进程、SQLite schema、健康状态机 | 可重现地记录检测、断线、恢复和切换事件 |
| Phase 3 | 桌面客户端 | Tauri UI、托盘、表格、趋势图、设置页 | 普通用户无需修改 YAML 即可使用 |
| Phase 4 | 系统集成与发行 | 可选 TUN、Windows Service、签名安装包、升级与恢复 | 安装、升级、异常退出和卸载测试全部通过 |

## Phase 3 当前进度（2026-07-19）

| 项目 | 状态 | 说明 |
|---|---|---|
| Tauri 2 + React/TypeScript 桌面壳 | 已完成 | Windows NSIS 开发安装包可构建并启动 |
| 总览表格、延迟图与事件时间线 | 已完成 | 使用 Guardian SQLite 的脱敏数据 |
| Guardian 后台周期 | 已完成 | 应用启动立即检测，之后默认每 180 秒检测 16666 |
| Mihomo 开发进程管理 | 已完成 | 只管理本应用创建的 36666 进程，并保护 6666 所有者 |
| 双出口与真实模式 | 实现完成/隔离验收已拆分 | 订阅 A + Local client、loopback Controller、三种模式、`16666` 故障切换与手动 Fail Closed 已验收；剩余两项由 Issue #5 跟踪，PR 仍待独立复审 |
| 多目标检测与切换历史 | 已完成 | 多数派健康判断；失败、恢复和 Controller 确认切换写入 SQLite |
| 真实订阅格式与双出口外网 | 主要现场链路已验收 | 本机私密订阅、两出口分别访问外网已确认；订阅 A 故障和双出口 live all-down 未完成，已拆分到 Issue #5 |
| 动态出口历史筛选、统计与脱敏 CSV | 已完成 | 1h/24h/7d/30d；稳定出口快照；P50/P95、故障区间；流式 CSV 与 retention |
| 完整设置页 | 未完成 | 历史保留期已就近实现；其余设置仍为占位页 |
| 托盘、通知和自动恢复 | 未完成 | 在三出口接入前不宣称完成 |
| 正式 6666 接管 | 明确延期 | 用户仍在使用现有 Local client B；当前代码没有接管命令 |

## Phase 4 当前进度（2026-07-20）

| 项目 | 状态 | 说明 |
|---|---|---|
| Windows Helper | 代码完成/待签名安装验收 | LocalService、认证 named pipe、owned child/job 与动态配置监督已实现；当前开发机未安装或运行 Service |
| TUN 计划与恢复 | 计划层完成/真实 backend 阻断 | typed plan、generation/fencing、snapshot → stage → apply → verify → commit journal、失败/崩溃/卸载幂等恢复由 fake backend 验收 |
| Windows 应用身份排除 | `unsupported` | 官方 Mihomo Windows TUN 字段不能证明按进程排除；在 WFP/ALE adapter 独立安全评审前保持默认关闭和 Fail Closed |
| Windows release foundation | 安全前置完成/正式发布无条件阻断 | required PR jobs exact-head、双隔离 unsigned dev NSIS、same-run normalized consistency、官方 npm CycloneDX dependency graph、canonical migration contract 已自动化；机器生成的 Authenticode/update-signature/clean-VM attestation verifier、#14 executor 均未具备，Issue #15 保持 open |
| 桌面入口 | 已接入安全预览 | 设置页显示默认关闭、风险确认禁用原因、动态 outlet 计划 generation 与缺失身份；不会误记为已启用 |
| 真实系统验收 | 待隔离 Windows 环境 | 必须验证 IPv4/IPv6、TCP/UDP/DNS、睡眠/崩溃/断电/卸载恢复，不得在日常开发机执行 |

## Phase 0 检查表

- [x] 客户端 A 可将 Mixed Port 修改为 `16666`。
- [ ] 客户端 B 可将 Mixed Port 修改为 `26666`。
- [x] 客户端 A 的 `16666` 与客户端 B 当前的 `6666` 可以同时监听；待 B 迁移后复验完整目标端口组合。
- [ ] 两个目标内部端口均可通过 SOCKS5 完成 TCP 请求；客户端 A 的 `16666` 已通过，客户端 B 的 `26666` 待验证。
- [ ] 分别验证 SOCKS5 UDP；不支持时记录为 `TCP only`。
- [x] 确认订阅源格式以及 Mihomo provider 的兼容性。
- [ ] 验证关闭两个客户端的系统代理、TUN、Allow LAN 和链式代理后仍可作为本地出口使用；客户端 A 已通过，客户端 B 待迁移后验证。
- [ ] 测量每个出口的连接建立时间、延迟、连续失败和恢复行为；Local client 侧已完成，订阅 A 故障与双出口 all-down 已拆分到 Issue #5。

## 开发完成定义

每个阶段必须同时具备：实现、自动化检查、手工验收记录、失败回滚方式和文档更新。仅有界面或单次演示不视为完成。
