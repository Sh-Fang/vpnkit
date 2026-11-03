# vpnkit

跨平台命令行 VPN 客户端。目标是**只把需要走内网的流量送进隧道**，其余上网、下载、视频完全不受影响。

- 单一 Go 二进制，`darwin` / `linux` / `windows` × `amd64` / `arm64`
- 无 GUI、不安装系统服务，`up` / `down` 即开即关（进程前台常驻）
- 隧道承载裸 IPv4 包，客户端不需要用户态 TCP/IP 栈
- 分流基于路由表与分区 DNS，不改默认路由

---

## 这套文档是什么

这是一份**自包含**的工程文档：实现所需的协议格式、状态机、加密原语、平台差异、配置模型、测试方法全部在 `docs/` 内。
读完之后不需要任何外部资料即可开工。

**如果你是接手的 AI 或工程师，按这个顺序读：**

| 顺序 | 文档 | 读它是为了 |
|---|---|---|
| 1 | [docs/00-product.md](docs/00-product.md) | 知道要做什么、做到什么程度算完成 |
| 2 | [docs/01-architecture.md](docs/01-architecture.md) | 知道代码怎么分层、模块边界在哪 |
| 3 | [docs/02-auth.md](docs/02-auth.md) | 实现第一步：拿到会话令牌 |
| 4 | [docs/03-tunnel.md](docs/03-tunnel.md) | 实现第二步：建立隧道 |
| 5 | [docs/04-commands.md](docs/04-commands.md) | 实现第三步：跑通命令状态机 |
| 6 | [docs/07-split-routing.md](docs/07-split-routing.md) | 实现第四步：分流（本项目的核心价值） |
| 7 | 其余 | 按需查阅 |

---

## 快速开始

```bash
go build -o vpnkit ./cmd/vpnkit

./vpnkit login --server vpn.example.com --user alice
./vpnkit up
./vpnkit status
./vpnkit down
```

`up` / `down` 需要 root（macOS/Linux）或管理员（Windows）。加 `--dry-run` 只打印将要执行的路由与 DNS 变更，不落盘。

### 不需要真实网关的本地试跑

```bash
make build testserver
./bin/testserver --script happy &          # 假网关：https 127.0.0.1:8443，隧道 127.0.0.1:8444
VPNKIT_PASSWORD=secret ./bin/vpnkit login --server 127.0.0.1:8443 --ca-file testserver-ca.pem --user alice
./bin/vpnkit up --dry-run --server 127.0.0.1:8443 --ca-file testserver-ca.pem
./bin/vpnkit up --fake-tun --verbose --server 127.0.0.1:8443 --ca-file testserver-ca.pem   # 无需 root
./bin/vpnkit status; ./bin/vpnkit down
```

`--fake-tun` 用内存 TUN、路由/DNS 只打印不执行，只用于测试协议与状态机。

---

## 设计原则

1. **默认路由神圣不可侵犯。** 任何情况下都不接管 `0.0.0.0/0`，只加内网网段。
2. **DNS 分区。** 只有内网域名走隧道 DNS，公网域名走本地解析器。
3. **线格式冻结。** `docs/03`、`docs/04` 里定义的字节布局是硬约束，改动必须同步改文档并升协议版本号。
4. **失败可回滚。** 任何一步失败都要撤销已做的路由/DNS 变更，不允许留下半连接状态。
5. **可观测。** `--verbose` 输出每一帧的 opcode 与长度；`status` 输出统计量。

---

## 目录结构（目标形态）

```
vpnkit/
├── cmd/vpnkit/           # CLI 入口，cobra 或 flag
├── internal/
│   ├── auth/             # 认证协议（docs/02）
│   ├── tunnel/           # 握手、帧编解码、RC4（docs/03）
│   ├── command/          # 命令状态机（docs/04）
│   ├── devid/            # 设备标识（docs/06）
│   ├── route/            # 路由与 DNS 分流（docs/07）
│   └── platform/         # 三平台差异封装（docs/08）
├── pkg/wire/             # 纯函数：字节编解码，无副作用，易于单测
└── docs/
```

`pkg/wire` 与 `internal/tunnel` 之间不得有反向依赖；`platform` 之下不得 import 业务包。

---

## 当前状态

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 文档与协议规格 | ✅ 完成（本套文档） |
| P1 | 认证链路 | ✅ 已实现，testserver 验收通过 |
| P2 | 隧道建立（控制通道） | ✅ 已实现，testserver 验收通过 |
| P3 | 路由分流 + 内网可达 | 🟡 已实现；命令生成与 dry-run 已验证，真实 TUN/路由待 root 环境验证 |
| P4 | DNS 分区 | 🟡 已实现；同上，待 root 环境验证 |
| P5 | UDP 承载与性能调优 | 待实现（`--transport udp` 目前回退 TCP 并告警） |

真机联调前请先看 `docs/12` 末尾的联调检查表：所有待实测假设点都会以 `assumption=<key>` 记入日志。

详见 [docs/12-roadmap.md](docs/12-roadmap.md)。

---

## 安全声明

照录 `docs/05` §4，不做美化：

1. 握手使用预置会话凭证，**不做前向保密**。
2. RC4 已被密码学界证明不再安全，且此处密钥可由程序本身确定。
3. 因此这套加密**只提供流量混淆，不提供机密性**。任何拿到本程序或能抓包的人都能还原内容。
4. 不要把本工具用于传输确实需要保密的数据；它的价值在**分流与易用性**，不在加密。
