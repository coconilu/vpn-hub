# Issue #7：配置驱动的统一入口与动态出口

VPN Hub 的产品入口与出口集合由 `%LOCALAPPDATA%\VPN Hub\private-routing.toml` 的版本化配置驱动。默认入口是 `127.0.0.1:3666`，但端口和 loopback 地址都可以修改；应用启动前会校验端口冲突，并且不会修改 Windows 系统代理。

## 配置边界

| 类型 | 配置保存 | 运行时行为 |
| --- | --- | --- |
| 统一入口 | `entry.host`、`entry.port` | 生成唯一的 Mihomo Mixed Port |
| `subscription` | 稳定 ID、标签、`secret_ref`、刷新周期 | 一条订阅生成一个 provider 和逻辑出口；真实 URL 由凭据解析器提供 |
| `local_proxy` | 稳定 ID、标签、loopback endpoint | 支持 `http`、`socks5`、`socks5h`，转换为 Mihomo 本地上游 |

出口数组的顺序就是 `priority` 模式的优先顺序。`enabled = false` 会保留稳定 ID 和位置，但不会生成、探测或参与路由。删除数组项即删除出口；SQLite 历史仍以原 `outlet_id` 保留。

完整的三订阅、两本地出口示例见 [`config/private-routing.example.toml`](../config/private-routing.example.toml)。版本化配置只保存 `secret_ref`，不保存订阅 URL、节点或 token。

## Fail Closed

Mihomo 主选择器始终以 `REJECT` 为第一个候选，并且不会生成 `DIRECT`。未解析凭据的订阅不会进入选择器；所有启用出口不可用时，`priority`、`fastest` 和 `manual` 都选择 `fail-closed`，Controller 再把它映射为 `REJECT`。

## 兼容迁移与回滚

没有 `version` 字段的 v0 双出口配置会在加载时映射为动态出口：

- `subscription-a` 迁移为一个 `subscription`，使用兼容 `secret_ref`；
- v0 结构中的唯一非订阅出口迁移为 `local-client` 类型的 `local_proxy`；
- 旧 `priority` 顺序和手动选择引用映射到通用 ID；路由模式与探测参数保持不变；
- priority 缺槽、重复或出现多个本地候选时拒绝迁移，不猜测出口身份；
- 兼容加载不会把订阅 URL写入摘要、数据库或 UI。

每次保存都先验证完整配置，再通过临时文件替换主文件，并保留一份最后有效备份。主文件损坏或校验失败时会回读该备份；若主文件和备份都无效，应用不会生成或启动 Mihomo，保持 Fail Closed。

## 明确不做

- 不修改 Windows 系统代理；
- 不绑定或切换用户当前的 `6666`；
- 不启用 TUN、安装 Service 或控制第三方客户端；
- 不为每条订阅额外暴露监听端口；
- 不在本 Issue 实现 Windows Secret Store，真实多订阅凭据由 Issue #6 接入。
