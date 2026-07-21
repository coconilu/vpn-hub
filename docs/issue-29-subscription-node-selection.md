# Issue #29：订阅节点选择

## 目标与边界

| 项目 | 约束 |
|---|---|
| 数据来源 | 仅本应用自管、带随机 secret 的 loopback Mihomo Controller |
| 可管理对象 | 已启用且凭据状态为 `configured` 的 `subscription` 出口 |
| 展示字段 | 节点名称、代理类型、健康状态、Mihomo 已知的最近延迟 |
| 明确排除 | server、port、UUID、密码、token、订阅 URL、第三方客户端内部节点 |
| 持久化 | VPN Hub 不保存节点名称或列表；Mihomo 以 `store-selected` 保存 `url-test` 组的 fixed 节点 |
| 失败行为 | PUT 前失败不会修改选择；PUT 已发送后若无法权威回读，只报告“结果未确认”并要求刷新，不对实际节点作错误承诺 |

## 运行流程

```mermaid
sequenceDiagram
    participant UI as 节点选择页
    participant App as Tauri 命令
    participant M as Loopback Mihomo Controller

    UI->>App: 读取订阅节点目录
    App->>App: 过滤启用且凭据可用的订阅
    App->>M: GET /proxies
    M-->>App: selector all/now 与安全展示字段
    App-->>UI: 运行时节点卡片
    UI->>App: 选择候选节点
    App->>M: 重新读取并确认候选仍存在
    App->>M: PUT /proxies/{subscription-selector}
    App->>M: GET /proxies 重新读取
    App-->>UI: 已确认的当前节点
```

节点选择使用由 `outlet_proxy_name(subscription_id)` 派生的订阅 selector。提交前必须再次确认节点仍在该 selector 的 `all` 集合中；提交后必须以 Controller 返回的 `now` 为准，前端不做乐观成功。

## 手动选择的存活期

订阅出口当前是 Mihomo `url-test` 组。手动选择会设置该组的 fixed 节点，并由 `store-selected` 在 selector 名称稳定时跨重载保存。只要该节点仍存在且健康，`url-test` 会优先使用它；节点不健康时，Mihomo 可以临时改用其他健康节点，恢复健康后再回到 fixed 节点。用户再次选择、取消 fixed 状态、节点从 provider 消失或 selector 被替换时，这个选择不再生效。

当前 Guardian 和路由模式只切换外层 `MASTER_SELECTOR`/`UDP_SELECTOR`，不会改写订阅内部的 fixed 节点。未来如果新增会操作订阅内部 selector 的自动策略，必须在同一事务锁下定义清晰的优先级，并在 UI 中显式提示，不能静默覆盖手动选择。

## 状态模型

| 状态 | UI 行为 |
|---|---|
| `available` | 展示节点、搜索并允许选择 |
| `core_unavailable` | Controller 未配置、连接失败、HTTP/响应无效时提示检查本应用自管核心；不探测其他进程 |
| `provider_unavailable` | 提示等待 provider；原选择保持不变 |
| 无可管理订阅 | 引导到设置页启用订阅并保存凭据 |

浏览器预览只使用合成节点名称，用于布局与交互验收；不会启动 Mihomo、绑定入口或修改 Windows 系统网络。

## 验证

```powershell
cargo test -p vpn-hub-core controller --lib
cargo test -p vpn-hub-desktop --lib
cd apps/desktop
npm test
npm run build
```

真实订阅验收只能在用户明确授权的隔离环境中进行，且不得把节点名称、订阅 URL、Controller secret 或运行日志复制到 Issue、PR 或测试证据。
