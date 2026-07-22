# Issue #3 本机 Controller 与 Fail Closed 验收

日期：2026-07-18

## 验收范围

本轮只验证不含订阅凭据的链路：

```text
127.0.0.1:36666 -> Mihomo VPN-HUB-MASTER
                    |-- REJECT（初始状态）
                    `-- VPN-HUB-LOCAL-CLIENT -> 127.0.0.1:16666 -> HTTPS
```

未停止或重启 Local client A/B；未修改 Windows 系统代理。

## 结果

| 检查 | 结果 |
|---|---|
| 生成的运行时配置通过 Mihomo 启动 | 通过 |
| Controller 使用随机 secret 且只监听 loopback | 通过 |
| 初始选择器为 `REJECT`，HTTPS 请求失败关闭 | 通过 |
| Controller 将真实选择器切到 `VPN-HUB-LOCAL-CLIENT` | 通过 |
| `36666 -> 16666` 完成 Gstatic HTTPS 请求 | 通过 |
| 测试结束释放 `36666` 和 Controller 端口 | 通过 |
| 测试前后 `6666` 监听 PID | 均为 `64908` |
| 测试前后系统代理 | 均为 `127.0.0.1:6666` |

对应 ignored 测试：

```powershell
cargo test -p vpn-hub-desktop starts_and_stops_only_the_isolated_development_core -- --ignored --nocapture
cargo test -p vpn-hub-desktop controller_selects_local_outlet_for_real_https -- --ignored --nocapture
cargo test -p vpn-hub-desktop initial_selector_is_fail_closed -- --ignored --nocapture
```

## 未验证

真实订阅 A 未通过终端或测试环境注入，以避免凭据出现在命令记录。订阅 provider 格式兼容性、订阅出口的国内/海外请求及两个真实出口之间的故障注入，需用户安装后在桌面端密码框录入并现场验收。
