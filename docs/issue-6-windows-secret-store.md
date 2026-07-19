# Issue #6：Windows 受保护凭据与多订阅

VPN Hub 的普通路由配置只保存稳定的 `subscription_id` 与 `secret_ref`。真实订阅 URL 由当前 Windows 用户的 Credential Manager 保存，运行时只在生成 Mihomo 临时配置的短路径中受控读取。

## 存储边界

| 数据 | 保存位置 | 对外可见内容 |
| --- | --- | --- |
| `subscription_id`、标签、启用状态、刷新周期 | `private-routing.toml` | 原值；不属于凭据 |
| `secret_ref` | `private-routing.toml` | 原值；只用于稳定寻址 |
| 订阅 URL / token | Windows Credential Manager | UI、命令返回、SQLite、日志和普通配置只显示状态 |
| Controller secret | 仅进程内存与当前 Mihomo 临时配置 | 每次启动随机生成，不写普通配置、SQLite 或日志 |
| 本地代理认证 | 当前配置明确拒绝 endpoint 中的 userinfo | 将来支持认证时必须复用 Secret Store，不得写入 endpoint |

Windows 凭据使用 `VPNHub:subscription:<secret_ref>` 作为目标名，并指定 `Local` persistence。它由 Windows 按当前登录用户隔离，不随普通配置备份或换机复制，也不能由另一个普通 Windows 账户读取。

## 操作模型

| 操作 | 行为 |
| --- | --- |
| 创建 / 覆盖 | 先按 `subscription_id` 查找配置中的 `secret_ref`，校验 HTTPS URL 后只覆盖对应凭据 |
| 受控读取 | 仅解析配置中已声明的订阅；不会枚举或读取其他 Windows 凭据 |
| 状态枚举 | 返回 `configured`、`missing`、`unavailable` 或 `corrupted`，不返回凭据值 |
| 删除凭据 | 只删除目标 `secret_ref`；保留稳定订阅 ID，状态变为 `missing` |
| 删除订阅 | 配置管理功能在移除 outlet 前必须先调用凭据删除；失败时不得静默遗留 |

桌面后端提供 `list_subscription_credentials`、`set_subscription_credential` 和 `delete_subscription_credential` 三个 Tauri 命令。设置页属于后续 Issue；本 Issue 不新增 UI，也不允许任何读取命令回显订阅值。

## 旧配置迁移

没有 `version` 的旧配置可能包含一个明文 `subscription_url`。启动时迁移顺序如下：

```text
校验旧配置
  -> 读取旧目标凭据（用于回滚）
  -> 写入 legacy.subscription-a
  -> 原子保存只含 secret_ref 的 versioned 配置与备份
  -> 完成
```

- 凭据写入失败：不改原文件，明文仍只有原来的一份。
- 配置提交失败：先恢复迁移前的主配置与备份快照，再恢复原有凭据；旧配置保持原状。
- 回滚也失败：返回单独的脱敏 `RollbackFailed`，阻止 Mihomo 启动并保持 Fail Closed。
- 迁移成功：主配置和 `.bak` 都不再包含 `subscription_url` 或其值。

## 生命周期

| 场景 | 语义 |
| --- | --- |
| 应用升级 | 目标名和 `secret_ref` 稳定，凭据继续可用；不得重新导入明文 |
| 普通配置备份 / 恢复 | 只备份引用；新机器或新用户显示 `missing`，需要重新录入 |
| 移动数据目录 | 不移动凭据；同一 Windows 用户仍按稳定引用解析 |
| 卸载 | 安装器必须在用户明确选择“删除本机凭据”后逐项清理；无授权时不静默删除 |
| 删除单个订阅 | 只清理该订阅的凭据，不影响其他订阅 |

自动化测试使用每次随机生成的无效域名 URL。Windows 集成测试在写入前清理目标，并用析构守卫保证测试结束时删除三个临时凭据。

## 安全与运行边界

- 不修改 Windows 系统代理，不启用 TUN，不安装 Service，不控制第三方客户端。
- 不探测、占用或切换用户现有的 `127.0.0.1:6666`。
- 受保护存储和迁移错误统一映射为脱敏状态，不拼接 Windows 平台错误或凭据内容。
- 凭据缺失时对应订阅不会进入 Mihomo 选择器；全部出口不可用时继续 Fail Closed。
