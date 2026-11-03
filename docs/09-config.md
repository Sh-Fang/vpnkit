# 09 · 配置

## 1. 本地配置

`~/.config/vpnkit/config.toml`，权限 `0600`。

```toml
[server]
host      = "vpn.example.com"
port      = 443
# 认证方式
auth      = "password"        # password | cert

[auth]
user           = "alice"
mitm_field     = "mitm_result"   # 或 "mitm"
send_rand_code = false

[tunnel]
mtu                = 1400
transport          = "tcp"       # tcp | udp
heartbeat_interval = "10s"
heartbeat_timeout  = "30s"
connect_timeout    = "10s"
handshake_timeout  = "15s"

[split]
# 由服务端资源列表推导；也可在此手工追加
extra_routes = []
# 强制走物理网卡的地址（防回环），一般自动填充
bypass = []

[dns]
suffixes = ["corp.example.com"]
servers  = ["10.0.0.53"]

[log]
level  = "info"                  # debug | info | warn | error
format = "text"                  # text | json
```

优先级：命令行参数 > 环境变量（`VPNKIT_*`）> 配置文件 > 内置默认值。

不得在配置文件中存密码。密码来源：

1. 交互式输入（默认）
2. `VPNKIT_PASSWORD` 环境变量
3. 系统钥匙串（将来项）

## 2. 状态文件

| 文件 | 内容 | 生命周期 |
|---|---|---|
| `session-<host>.json` | 会话令牌 | 登录后写入，`logout` 或鉴权失败时删除 |
| `device-id` | 设备标识（32 位大写 hex） | `devid pin` 写入，长期保留 |
| `state.json` | 运行时变更记录 | `up` 写入，`down` 删除 |

全部 `0600`，全部不进仓库。

## 3. 网关下发的配置

认证成功后 `GET /por/conf.csp` 返回一个 XML。需要解析的节点：

```xml
<Conf>
  <Mline  enable="1" number="2" list="10.0.0.1:443;10.0.0.2:443;" interval="5" timeout="10"/>
  <Htp    enable="0" auto="1" param="7|0|1|200|100" port="443" mtu="1400"/>
  <WebCache enable="0" mode="0" count="0" url=""/>
  <Bandwidth recvlimit="0" sendlimit="0"/>
  <TcpApplication userMode="1" compress="0" maxthread="50" maxsession="2"/>
  <L3VPN  iptunDns="0.0.0.0" iptunDnsBak="0.0.0.0"/>
  <Security interval="0" ignoreResult="0"/>
  <Other  login_name="lpt" sddn_enable="0" enableAutoRelogin="0"/>
</Conf>
```

| 节点/属性 | 含义 | 本项目如何使用 |
|---|---|---|
| `Mline.list` | 线路候选列表 `host:port;` | 依次尝试，失败换下一条 |
| `Mline.interval` / `timeout` | 线路探测间隔/超时（秒） | 择线策略参数 |
| `Htp.mtu` | 隧道 MTU | 作为 TUN MTU，见 `docs/07` §4 |
| `Htp.port` | 服务端口 | 默认隧道端口 |
| `Bandwidth.recvlimit` / `sendlimit` | 服务端限速（bps，0 = 不限） | 仅用于 `status` 展示与告警 |
| `TcpApplication.compress` | 是否压缩 | 已知恒为 0，见 `docs/04` §3.1 |
| `TcpApplication.maxsession` | 单用户最大并发会话数 | 决定可同时建几条数据通道 |
| `L3VPN.iptunDns` | 隧道内 DNS | `--dns-servers` 未指定时的默认值 |
| `Other.isHidUser` | 当前账号是否启用了设备绑定 | 为 1 时才需要上报设备标识 |

解析要求：

- 用容错解析：缺失节点用默认值，**不要因单个节点缺失而整体失败**
- 未知节点忽略
- 不要假设节点顺序

## 4. 资源列表

`GET /por/rclist.csp` 返回可访问的内网资源。本项目只关心其中的**网段**部分：

```
每个资源 → 目标地址/掩码 → 归一化为 CIDR
```

处理规则：

| 情况 | 处理 |
|---|---|
| 单主机资源（`/32`） | 加明细路由 |
| 网段资源 | 加网段路由 |
| 域名资源 | 加入 `dns.suffixes`，不加路由 |
| 重复/包含关系 | 先按前缀长度降序，再合并被包含的条目 |
| 私网网段数量 > 64 | 警告；建议改用更粗的汇总路由 |

## 5. 配置校验

`up` 之前做一次校验，失败给明确提示：

| 检查 | 失败行为 |
|---|---|
| `server.host` 非空 | 退出码 2 |
| `server.port` 在 1–65535 | 退出码 2 |
| `mtu` 在 576–1500 | 退出码 2 |
| `transport == udp` 但 `udpport == 0` | 降级为 tcp 并警告 |
| `dns.suffixes` 非空但 `dns.servers` 为空 | 用 `L3VPN.iptunDns`，仍为空则禁用 DNS 分区并警告 |
| 路由工具不存在 | 退出码 6，提示安装 iproute2 等 |

## 6. 环境变量

| 变量 | 对应配置 |
|---|---|
| `VPNKIT_SERVER` | `server.host` |
| `VPNKIT_USER` | `auth.user` |
| `VPNKIT_PASSWORD` | 密码（仅认证时读取，不落盘） |
| `VPNKIT_LOG_LEVEL` | `log.level` |
| `VPNKIT_CONFIG` | 配置文件路径 |

环境变量里的密码在 `status`、`doctor` 输出中必须屏蔽。
