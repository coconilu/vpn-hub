# Mihomo 开发隔离

## 目标

在不触碰用户当前 `127.0.0.1:6666` 的情况下，验证下面这条链路：

```text
显式测试请求 → VPN Hub 开发入口 127.0.0.1:36666
             → Mihomo OUT-LOCAL-A
             → 本地客户端 A 127.0.0.1:16666
```

开发配置不会设置 Windows 系统代理，没有 TUN、外部控制 API 或 DIRECT 回退。

## Sidecar 供应链

`tools/mihomo.lock.json` 固定官方发布版本、Windows AMD64 资产、文件大小和 GitHub Release API 提供的 SHA-256。下载脚本在解压前同时验证大小与哈希，下载产物保存在被 Git 忽略的 `.tools/`。

```powershell
.\scripts\fetch-mihomo.ps1
```

更新版本时必须先从 [MetaCubeX/mihomo 官方 Release](https://github.com/MetaCubeX/mihomo/releases) 核对资产和 digest，再提交 lock 文件变更。仓库不提交第三方二进制。

## 配置验证

```powershell
$info = & .\scripts\fetch-mihomo.ps1
& $info.Executable -t -f .\config\mihomo\development.yaml
```

配置文件是 `config/mihomo/development.yaml`，只绑定 `36666` 并把 `16666` 声明为 SOCKS5 上游。正式应用应通过结构化配置生成器产生运行时配置，而不是让用户手工编辑 YAML。

安全启动脚本会先验证配置和端口所有权，再以前台进程运行开发实例。按 Ctrl+C 停止后，它会复核 `6666` 的所有者没有变化：

```powershell
.\scripts\start-mihomo-development.ps1
```

保持该窗口运行，在另一个终端显式测试开发入口：

```powershell
curl.exe --proxy socks5h://127.0.0.1:36666 https://www.baidu.com/
curl.exe --proxy socks5h://127.0.0.1:36666 https://www.gstatic.com/generate_204
```

## 运行安全

开发实例启动前必须确认：

- `6666` 的所有者保持不变；
- `36666` 尚未被占用；
- `16666` 的所有者是预期的第三方核心；
- 只通过命令显式指定 `36666` 发出测试请求；
- 停止时只终止本次启动并记录 PID 的 Mihomo 进程。
