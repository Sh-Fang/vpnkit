# 07 · 分流：路由与 DNS

这是本项目的核心。目标：**内网流量进隧道，其余一切照旧。**

## 1. 总原则

1. **不改默认路由。** `0.0.0.0/0` 永远指向物理网关。
2. **只加内网网段。** 目标网段来自服务端下发的资源列表。
3. **DNS 分区。** 只有内网域名走隧道 DNS。
4. **先记后改。** 所有变更先写入 `state.json`，`down` 时按记录恢复。

## 2. 路由

### 2.1 需要加的路由

对资源列表里的每个内网网段：

```
目标: <cidr>     设备: <tun 设备>     网关: 无（点对点）
```

### 2.2 防回环（关键）

隧道的服务端地址本身**绝不能**走进隧道，否则连接自己就断了。启动顺序：

1. 先为 `<server_ip>/32` 加一条**走物理接口**的明细路由（如果它当前走默认路由则通常可省，但显式加更安全）
2. 再建 TUN、再加内网网段路由

若 `--server` 是域名，先解析成 IP，路由用 IP。

### 2.3 各平台命令

**macOS**

```bash
# 加
route -n add -net 10.0.0.0/8 -interface utun5
route -n add -host 203.0.113.9 -interface en0      # 防回环

# 查
netstat -rn -f inet

# 删
route -n delete -net 10.0.0.0/8 -interface utun5
```

**Linux**

```bash
ip route add 10.0.0.0/8 dev tun0
ip route add 203.0.113.9/32 via 192.168.1.1 dev eth0
ip route show
ip route del 10.0.0.0/8
```

**Windows**

```
netsh interface ipv4 add route 10.0.0.0/8 "vpnkit" 0.0.0.0
netsh interface ipv4 delete route 10.0.0.0/8 "vpnkit"
route print -4
```

### 2.4 路由失败的处理

> **不要**学"路由加不上就整体断开"的做法。

正确行为：

| 情况 | 处理 |
|---|---|
| 部分网段加失败 | 记录失败网段，继续跑（其余网段可用），`status` 里标出 |
| 全部失败 | 回滚退出，退出码 6 |
| 网段与已有路由冲突 | 跳过该网段并警告，不覆盖现有路由 |

## 3. DNS 分区

### 3.1 为什么必须做

如果像常见做法那样把系统 DNS 整个指向隧道内解析器：

- 每个新域名多一次隧道往返（内网 RTT 通常远高于本地）
- 公网 CDN 会解析到远端节点，下载速度进一步下降

所以只让**内网域名**走隧道 DNS。

### 3.2 配置模型

```toml
[dns]
# 内网域名后缀，只有匹配这些后缀的解析才走隧道 DNS
suffixes = ["corp.example.com", "internal.example.com"]
# 隧道 DNS 服务器地址；留空则用 SEND_IP 下发的网关地址
servers = ["10.0.0.53"]
```

隧道 DNS 服务器地址不在内网网段内时，自动为它补一条指向 TUN 的 /32 路由；否则分区解析的查询会经默认路由从物理网卡发出。该地址与隧道服务端地址相同时不补（会回环），只告警。

### 3.3 各平台实现

**macOS** —— `/etc/resolver/<suffix>`

```
# /etc/resolver/corp.example.com
nameserver 10.0.0.53
```

写入后对**该后缀**生效，其他域名不受影响。删除文件即恢复。
需要 root。macOS 一般无需重启 `mDNSResponder`，若未生效可 `dscacheutil -flushcache`。

**Linux** —— systemd-resolved（主流发行版默认）

```bash
resolvectl dns tun0 10.0.0.53
resolvectl domain tun0 '~corp.example.com' '~internal.example.com'
# 恢复
resolvectl revert tun0
```

`~` 前缀表示"仅路由匹配域"，这是分区解析的关键。
无 systemd-resolved 的环境（如 Alpine）不支持分区，此时退化为提示用户手动配置，不要直接改 `/etc/resolv.conf`。

**Windows** —— NRPT（名称解析策略表）

```powershell
Add-DnsClientNrptRule -Namespace ".corp.example.com",".internal.example.com" `
                      -NameServers 10.0.0.53
# 列出
Get-DnsClientNrptRule
# 删除
Get-DnsClientNrptRule | Where-Object {$_.Comment -eq "vpnkit"} | Remove-DnsClientNrptRule -Force
```

给每条规则加 `-Comment "vpnkit"`，便于精确清理。

### 3.4 兜底

拿不到内网域名后缀时（服务端未下发）：

- 不改 DNS（保持系统原状）
- `status` 打印警告：内网域名可能需要用 IP 访问
- 提供 `--dns-suffix` 参数让用户手填

**绝对不要**在这种情况下把系统 DNS 全量指向隧道。

## 4. MTU

| 项 | 值 |
|---|---|
| 默认 | 1400（来自网关配置 `mtu`） |
| 上限 | `min(网关下发值, 1400)` |
| 建议 | 若出现大包卡死，降到 1380 |

设置 TUN 设备 MTU，不要改物理网卡 MTU。

## 5. 传输选择（影响下载速度）

协议支持两种承载：

| 承载 | 特点 | 建议 |
|---|---|---|
| TCP | 裸 IP 包塞进单一 TCP 流 = TCP-over-TCP，一丢包内外层重传叠加，吞吐塌陷 | 不推荐用于下载 |
| UDP | 避开 TCP-over-TCP，丢包由内层协议自行处理 | **优先**，前提是 `udpport != 0` |

实现顺序：先做 TCP 打通链路，再把 UDP 做成可切换的传输后端（`--transport tcp|udp`）。
`udpport` 为 0 时强制 TCP。

## 6. 变更记录与恢复

`~/.config/vpnkit/state.json`：

```json
{
  "pid": 12345,
  "tun": "utun5",
  "routes_added": ["10.0.0.0/8", "172.16.0.0/12"],
  "bypass_added": ["203.0.113.9/32"],
  "dns_files": ["/etc/resolver/corp.example.com"],
  "nrpt_added": []
}
```

规则：

- `up` 第一步写该文件，最后一步删除
- `up` 启动时若发现文件已存在 → 上次异常退出 → 先按其内容清理，再继续
- `down` 按文件内容逆序清理，**清理失败不中断**，收集所有错误后一次性报告

## 7. 验收

见 `docs/00-product.md` §5 的 P3、P4。补充几条可自动化的检查：

```bash
vpnkit up --dry-run          # 打印将执行的路由/DNS 命令，不执行
vpnkit status --json         # 输出当前路由与 DNS 状态
vpnkit doctor                # 检查权限、TUN 可用性、路由工具存在性
```
