# 08 · 平台差异

所有平台差异集中在 `internal/platform`，上层不感知。

## 1. 能力矩阵

| 能力 | macOS | Linux | Windows |
|---|---|---|---|
| TUN 设备 | `utunN`（系统自动分配） | `/dev/net/tun` | Wintun |
| 提权 | root | root 或 `CAP_NET_ADMIN` | 管理员 |
| 路由工具 | `route` | `ip` | `netsh` |
| DNS 分区 | `/etc/resolver/` | systemd-resolved | NRPT |
| 打包 | 单二进制 | 单二进制 | 单 exe（内嵌 wintun.dll） |

## 2. TUN 设备

### 2.1 选择

推荐用 `golang.zx2c4.com/wireguard/tun` 这**一个**依赖统一三平台——它已经处理了：

- macOS 的 `utun` 控制接口与 4 字节地址族前缀
- Linux 的 `/dev/net/tun` + `IFF_TUN | IFF_NO_PI`
- Windows 的 Wintun（dll 可通过 `go:embed` 内嵌）

> 这是 `AGENTS.md` 允许的例外：它是设备抽象层，不是 VPN 协议实现。若不想引入，
> 也可自己写三份实现，但工作量与坑都明显更大。

### 2.2 macOS 要点

- `utun` 写入的每个包前面要加 4 字节地址族头（`AF_INET` = 2，大端）。选上面那个库可自动处理。
- 设备名不能自己指定，由内核分配（`utun0`、`utun1`…），要读回实际名字。
- 配置地址：`ifconfig utun5 inet 10.8.0.2 10.8.0.2 netmask 255.255.255.255`
- 配置 MTU：`ifconfig utun5 mtu 1400`

### 2.3 Linux 要点

- 打开 `/dev/net/tun`，`ioctl(TUNSETIFF)` 带 `IFF_TUN | IFF_NO_PI`
- 需要 `CAP_NET_ADMIN`，或 root
- 配置地址：`ip addr add 10.8.0.2/32 dev tun0`；`ip link set tun0 mtu 1400 up`

### 2.4 Windows 要点

- Wintun 需要管理员权限创建适配器
- 适配器名固定为 `vpnkit`，便于路由命令引用
- 内嵌 dll：`//go:embed wintun.dll`，启动时释放到临时目录并 `LoadLibrary`（该库已封装）
- 卸载残留适配器：`netsh wintun delete` 不可用，靠库的 cleanup

## 3. 权限检测

`doctor` 与 `up` 开始时检查：

| 平台 | 检查方式 |
|---|---|
| macOS/Linux | `os.Geteuid() == 0`，或尝试打开 TUN 设备看是否 `EPERM` |
| Windows | 尝试创建 Wintun 适配器，失败即判权限不足 |

权限不足 → 退出码 5，提示用 `sudo` 或提升权限运行。

## 4. 信号处理

| 信号 | 行为 |
|---|---|
| `SIGINT` / `SIGTERM` | 执行 `down` 流程后退出 |
| `SIGHUP` | 忽略（避免终端断开导致掉线） |
| Windows 控制台关闭事件 | 同上，用 `SetConsoleCtrlHandler` |

**必须**保证 `down` 流程在信号处理里跑到（含回滚）。超时 10 秒后强制退出。

## 5. 进程模型

单进程。不安装系统服务、不写 launchd/systemd 单元、不注册 Windows 服务。

因此：

- `up` 后进程必须常驻（前台运行或用户自己 `&`）
- `up --daemon` 可选实现：`fork` 到后台并写 pid 文件。第一版可以不做。

## 6. 各平台构建产物

```
dist/
├── vpnkit-darwin-amd64
├── vpnkit-darwin-arm64
├── vpnkit-linux-amd64
├── vpnkit-linux-arm64
├── vpnkit-windows-amd64.exe
└── vpnkit-windows-arm64.exe
```

见 `docs/10-build.md`。
