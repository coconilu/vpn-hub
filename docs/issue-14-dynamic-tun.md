# Issue #14：动态出口下的可选 TUN、DNS 接管与防递归回滚

## 当前结论

截至 2026-07-20，TUN 的计划、状态机、事务 journal、fake Windows backend 与桌面安全预览已经实现；生产 Windows adapter 只校验 typed plan，并明确返回 `windows_verified_application_identity_exclusion_unavailable`。当前开发机未创建 TUN、未修改路由/DNS/适配器/防火墙/WFP/注册表/系统代理，也未运行 Mihomo 或 Windows Service。

这不是“功能已真实接管系统”。它是一道刻意的安全门：只有独立隔离环境中的 Windows backend 能证明按应用身份排除、全协议防泄漏和可靠恢复后，才能把 `supported` 改为 true。

## 官方能力核对

访问日期均为 2026-07-20。

| 来源 | 已确认能力 | 对本项目的约束 |
|---|---|---|
| [Mihomo TUN 配置](https://wiki.metacubex.one/en/config/inbound/tun/) | `auto-route` 可配置全局路由；Windows `strict-route` 会添加规则以抑制多宿主 DNS 泄漏；Windows/MacOS 不能自动劫持发往 LAN 的 DNS；UID 排除仅 Linux，package 排除仅 Android | 官方字段没有 Windows 按进程排除，不能把 `PROCESS-NAME` 当作安全身份；DNS 必须覆盖 TCP/UDP、IPv4/IPv6 并独立验收 |
| [Microsoft Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-) | ALE 是可依据 normalized application identity 与用户身份分类连接的 WFP 层 | 它能提供身份分类，但普通 permit/block 不会自动改变 TUN 路由；真实 backend 还需可审计的 packet-routing/TUN bypass executor |
| [Microsoft Windows Filtering Platform API](https://learn.microsoft.com/en-us/windows/win32/api/_fwp/) | 官方 API 提供 `FwpmGetAppIdFromFileName0` 和 IPv4/IPv6 ALE connect layers | 未来 adapter 必须把 typed identity filter 与路由执行协同，并使用最小 provider/sublayer/filter 权限和可恢复事务；不得拼接 shell 命令 |

## 产品行为

| 条件 | 行为 |
|---|---|
| 默认安装/升级 | TUN 关闭；不弹 UAC、不改系统网络 |
| 首次请求启用 | 必须确认当前版本风险；能力 unsupported 时确认控件禁用，且不会记录为已启用或已同意 |
| 普通统一入口模式 | 与 TUN 计划相互独立；TUN 失败会恢复切换前 snapshot，不影响普通模式配置 |
| 多个订阅出口 | 每个保留稳定 outlet ID；TUN plan 只保存脱敏后的 outlet ID 与 transport，凭据、订阅 URL、节点和 Controller secret 不进入 plan/journal/status |
| 多个本地出口 | 每个必须有稳定 outlet ID、明确 loopback endpoint、用户登记的本地绝对 executable path 和 SHA-256 |
| 动态增删 outlet | settings preview generation 随草稿指纹变化；计划只包含当前启用且登记的 outlet，不残留已删除身份 |
| all-down | IPv4/IPv6 × TCP/UDP/DNS 全部 `Rejected`，不生成或回退 `DIRECT` |

交易层只接受 `TunPlanBuilder` 产生的 opaque validated plan：原始策略字段私有，类型不实现 `Deserialize`，因此 IPC、journal 或其他不可信字节不能直接构造交易输入。Builder 同时保留不参与序列化的 canonical outlet provenance；每次进入 transaction/backend 前都会从 registry、local endpoint 与 exact executable rule 重建并比对。即使攻击者把 subscription 的 registry/eligible 或 local 的 declaration/endpoint/process/eligible 一起改到内部自洽，也会因不匹配 Builder provenance 被拒绝；该 provenance 是完整结构，不是可随字段一起替换的 hash。

## 进程身份与 disposition

“排除清单”不是“这些进程可以任意直连”。计划把身份与网络 disposition 分离：

| 角色 | disposition |
|---|---|
| GUI / Helper | `ControlPlaneDenyEgress`：外网拒绝，只允许必要 loopback IPC |
| VPN Hub-owned Core | `OwnedCoreUpstreamOnly`：仅计划内上游 transport |
| 登记的 local client | `RegisteredOutletInfrastructureBypass`：以 normalized app identity 精确匹配的最小基础设施 bypass |
| 未知进程 | 不扫描、不匹配、不停止、不修改 |

路径和 SHA-256 都必须匹配；UNC、相对路径、父目录跳转、非 `.exe`、非小写 64 位 SHA-256 均拒绝。真实 adapter 还必须在打开文件句柄后核对 final path、reparse point、签名/ACL 与 TOCTOU，不能仅相信字符串。

## 协议矩阵与 Issue #11 对齐

计划对 IPv4/IPv6 各生成 Application TCP、Application UDP、DNS TCP、DNS UDP 四个验证向量：

- 有健康 TCP 出口时 TCP 向量才可 `Tunneled`。
- 只有带当前有效 UDP 证据的健康出口才能让 UDP 向量 `Tunneled`；有效性统一调用 Core 的版本、probe/model、outlet ID、配置 fingerprint 与 generation 校验。
- TCP-only、unknown 或 stale UDP 证据不会被猜测为 UDP 可用。
- all-down 或 backend capability 不完整时全部 `Rejected`。

## 事务与恢复

```mermaid
flowchart LR
    A["preprovisioned protected authority file"] --> B["exclusive OS lock + identity/generation fence"]
    B --> C["load journal, then snapshot routes / DNS / adapters / TUN"]
    C --> D["durable journal: snapshotted"]
    D --> E["stage typed plan"]
    E --> F["apply"]
    F --> G["verify leak matrix"]
    G --> H["commit"]
    E -. failure/cancel .-> R["restore + verify snapshot"]
    F -. failure/crash .-> R
    G -. failure .-> R
    H -. disable/stop/uninstall/recovery .-> R
    R --> I["persist restored, clear journal, release lock"]
```

签名 installer 必须预置专用 `tun-authority.lease`，只允许 LocalService/SYSTEM/Administrators 写入，交互用户不能替换或删除；Helper 不会在关键路径创建它。事务先取得文件级排他 OS lock，再读取 journal 或创建 snapshot，并持有到 apply/recover/clear 完成；不能锁 journal inode，因为 journal 会原子替换。authority wrapper 同时校验 install ID、authority ID 与 generation。

每个 OS 边界后先持久化 phase，再进入下一阶段。journal 使用同目录临时文件、文件和目录 durability barrier 与 Windows 可替换的备份策略；主文件损坏时可读相同的 `.bak`。第二 authority、stale generation 和未恢复的旧 journal 都被拒绝。所有 rollback 都必须在 restore 后调用 `verify_restored`；只有验证成功才能写 `rolled_back`。restore 或验证失败统一返回 `RollbackFailed`，保留原 phase 的 journal；即使首次 journal save 失败，也会在回滚失败时 best-effort 保存 snapshot 状态供重启恢复。Disable 不能走 apply，也绝不把当前已启用状态拍成恢复目标；它只能恢复已有 committed Enable snapshot，验证恢复后写入 `restored`，最后清理 journal。恢复或清理失败可安全重试。

升级与卸载必须严格执行 `EnterFailClosed → StopOwnedJob → RestoreTunSnapshot → cleanup/replace → verify`，任一步失败即中止后续删除或替换。

journal 只允许长度受限的 opaque route/DNS/adapter/TUN record；单条、总大小、数量和 secret-shaped 内容都有上限。它不保存命令文本、订阅、节点、token、密码、Controller secret 或访问目标。

## 已自动化验证

- 默认关闭、当前版本风险确认、生产 unsupported Fail Closed。
- 多 subscription / 多 local_proxy、动态删除/新增、stable ID 和 exact identity。
- GUI/Helper deny、Core 最小上游、local client 精确基础设施 bypass、unknown process no-touch。
- canonical outlet registry 与 TCP/UDP eligible subset 防篡改；本地 endpoint 和 executable identity 一一对应；plan 不含订阅 secret。
- opaque plan 不可反序列化或由外部改写；自洽 subscription 注入及自洽 local declaration/endpoint/process 注入均被 canonical Builder provenance 拒绝。
- TCP-only 与 UDP evidence 分离；Core 会拒绝 outlet ID、evidence/probe/model 版本、配置 fingerprint/generation 或状态被篡改的证据；all-down 全矩阵 Reject。
- 专用 authority 文件必须预置；真实双 handle 排他锁、plan identity/generation 在 snapshot 前拒绝。
- snapshot/stage/apply/verify/commit 每个 OS 失败点与每个 journal save 失败点回滚。
- 所有 backend mutation 与首次/后续 journal save 的 rollback 都执行 restore + verify；验证失败保留 journal，并覆盖 transaction 重建后的 recover 重试。
- Disable 不重新 snapshot；crash/cancel/restart/uninstall 统一恢复并验证 committed Enable snapshot，`restored` 保存/清理失败均可幂等重试。
- 真实 `FileTunJournalStore` 连续多 phase save/load/backup/clear（仅文件系统，不执行网络系统调用）。

## 真实 Windows destructive acceptance 剩余 gate

以下测试只能在可恢复的隔离 Windows VM/物理测试机执行，当前仓库测试不得运行：

1. 签名 installer 安装最小权限 WFP/ALE identity provider/filter、可审计的 packet-routing/TUN bypass executor 与 TUN adapter；证明 permit/block 之外的真实绕过语义，并验证 ACL、升级和卸载。
2. 对 GUI/Core/Helper/多个登记 local client 的 normalized app identity 做正反例与二进制替换/重解析攻击测试。
3. IPv4/IPv6、TCP/UDP、DNS TCP/UDP、LAN DNS、Wi-Fi 切换、睡眠、登录和网络变化矩阵。
4. 在每个 apply 边界强杀进程/断电，重启后验证 route/DNS/adapter/TUN 恢复到 snapshot。
5. all-down、单个 TCP-only outlet、全部 UDP evidence stale 时确认没有真实 IP/DNS 直连。
6. 卸载后确认无 WFP filter、路由、DNS、虚拟网卡、Service、owned process 或 journal 残留。

在这些 gate 全部通过前，生产状态必须持续为 `unsupported`。
