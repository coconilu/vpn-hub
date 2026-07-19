# Issue #8：动态出口历史、统计与脱敏 CSV

## 安全边界

历史层只读取 Guardian 已经产生的健康样本、状态转换、Controller 已确认的路由切换和 UDP 能力结论。它不读取或保存订阅 URL、token、节点名、Controller secret、本机出口 IP、探测目标或用户访问目标。

出口显示名称写入历史前还会经过保守脱敏；URL、IP、凭据形状或控制字符会被替换为“已脱敏出口”。原因和模式只接受短的安全代码。CSV 只从这一安全投影生成，不从配置表或运行时配置生成。

## schema v4

SQLite `user_version = 4` 在单一事务内从 v2 或 v3 升级：

| 数据 | v4 行为 |
| --- | --- |
| `outlets` | 增加 `kind`、`enabled`、`deleted_at`；配置删除变成墓碑，不删除历史外键 |
| `probe_samples`、`state_events` | 保存写入时的脱敏 `outlet_label`、`outlet_kind` 快照 |
| `route_switches` | 保存 from/to 的稳定 ID 和脱敏 label/kind 快照 |
| `history_settings` | 单例保留期，范围 1–3650 天，默认 30 天 |
| 索引 | 时间 + outlet + status，以及真实切换的时间 + from/to |

旧数据无法可靠推断出口类型时保留 `unknown`，不会猜成订阅或本地客户端。迁移失败回滚整个事务并保留旧 `user_version`；高于 v4 的数据库在任何写入前被拒绝。

## 查询与统计口径

查询固定支持 `1h`、`24h`、`7d`、`30d`，并可按稳定 `outlet_id`、`subscription/local_proxy/unknown`、健康状态和 `probe/state/route_switch` 事件类型筛选。事件以 `(occurred_at, source_order, row_id)` 稳定倒序，每页最多 500 条。桌面命令使用 `spawn_blocking`，SQLite 查询不会占用 Tauri async/UI 线程。

统计只受时间、出口和 kind 约束；状态和事件类型用于事件明细筛选，不改变同一时间窗的出口总体口径：

| 指标 | 固定定义 |
| --- | --- |
| 在线率 | `(healthy + degraded) / 全部健康样本 × 100%`；`unknown` 和 `down` 都不算在线 |
| P50 / P95 | 对非 `down` 且 latency 非空的样本升序，使用 nearest-rank：`ceil(N × p)` |
| 故障次数 | 与窗口相交的 `down` 区间数；窗口开始时已故障也计一次 |
| 故障时长 | 每段 `down` 区间与查询窗口的交集；未恢复故障截断到查询时刻 |
| 同时间戳 | 同一数据源按 SQLite 自增 ID 顺序解释，避免恢复/故障次序不确定 |
| 真实切换 | 仅 `record_route_switch` 中 Controller 成功确认后写入的切换，不从策略意图推测 |

没有样本时返回空指标和空事件，不合成 `0 ms` 或虚构在线率。

## CSV 与性能

CSV 列顺序和 RFC 3339 时间格式稳定。所有单元格使用 RFC 4180 双引号转义；去掉前导空白后以 `= + - @` 开头的值会加前置单引号，防止 Excel/表格软件执行公式。导出用 SQLite 单游标逐行写入本机私有 runtime 目录，内存不随 30 天样本量线性增长。

自动化规模夹具覆盖三个出口各 14,400 个样本（30 天、180 秒周期，共 43,200 行），同时验证查询计划命中时间索引、分页查询和流式导出的宽松上限，避免把机器波动变成脆弱 CI。

## retention 与 UDP 边界

清理仅删除过期的健康样本、已闭合的旧状态证据、路由切换和非 current UDP 历史。每个出口最新状态事件始终保留，因此进行中的故障不会失去起点；`udp_capability_current` 引用的证据始终保留。schema、设置、当前 outlet 状态和 Fail Closed 路由状态不在 retention 清理范围内。

UDP capability history 是“该配置版本是否有 UDP 证据”的审计流；健康样本是 TCP/HTTPS 可用性；route switch 是 Controller 已确认的主选择器变更。三者可同窗展示，但不会互相推导或覆盖。
