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
| P1 | 认证链路 | 待实现 |
| P2 | 隧道建立（控制通道） | 待实现 |
| P3 | 路由分流 + 内网可达 | 待实现 |
| P4 | DNS 分区 | 待实现 |
| P5 | UDP 承载与性能调优 | 待实现 |

详见 [docs/12-roadmap.md](docs/12-roadmap.md)。
