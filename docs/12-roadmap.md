# 12 · 里程碑

每个里程碑都有可执行的完成判据（DoD）。**不要跳阶段**：后一阶段的调试依赖前一阶段可信。

---

## P0 · 文档与规格 ✅

**产出**：本套文档、`AGENTS.md`、目录骨架。

**DoD**：新人/AI 只读文档就能说出要实现哪些模块。

---

## P1 · 认证链路（2–3 天） ✅

**范围**：`internal/auth`、`cmd/vpnkit` 的 `login` / `logout`。

**任务**

1. `GET /por/login_auth.csp` 解析（容错：JSON → 正则 → 报错）
2. RSA PKCS#1 v1.5 加密（大写 hex）
3. `POST /por/login_psw.csp` 表单提交
4. 令牌落盘 `0600`，`logout` 删除
5. 设备标识模块 `internal/devid`（`docs/06`）

**DoD**

- [x] 对 `testserver` 完成登录，密码被正确解密校验通过
- [x] 令牌文件权限 `0600`
- [x] 密码不出现在 `ps`、日志、配置中
- [x] 401 → 退出码 3
- [x] `devid show` / `devid pin` 可用，输出符合 `[0-9A-F]{32}`
- [x] 启用设备绑定的账号：`NextAuth=4` 时按 `docs/02` §4.1 提交特征码完成认证
- [x] 设备未绑定时按 §4.2 提交绑定申请，并给出「等待管理员审批」的明确提示
- [ ] 上述两条在真实网关上走通（本地 testserver 已覆盖）

**风险**：公钥位置在不同网关上不一致 → 两处都取，以最后一次为准。

---

## P2 · 隧道建立（3–5 天） ✅

**范围**：`pkg/wire`、`internal/tunnel`、`internal/command`。

**任务**

1. `pkg/wire` 六个纯函数 + 表驱动测试
2. 握手时序（82/122/43/76/40）
3. `serverMsg` 校验与错误分类
4. 命令分发骨架（先只处理 code 0/10/11/14/15）
5. 心跳 goroutine
6. 状态机 `internal/session`

**DoD**

- [x] 对 `testserver` 完成握手，进入 `Running`
- [x] `--verbose` 打印五段长度正确
- [x] `bad-magic` 剧本 → 明确错误，退出码 4
- [x] `kick` 剧本 → `Stopped`，退出码 7，不重连
- [x] `busy-then-ok` 剧本 → 退避后成功
- [x] `go test -race` 无数据竞争

**风险**：握手模板可能已失效（`docs/03` §2.4）。若真机被拒，单独记录为 `ErrHandshakeRejected`，不要在其他逻辑里混淆。

---

## P3 · 分流（3–4 天） 🟡 Windows 已验证，Linux / macOS 待验证

**范围**：`internal/route`、`internal/platform/tun`。

**任务**

1. TUN 设备创建与关闭（三平台）
2. 路由增删，防回环
3. `state.json` 记录与异常恢复
4. `--dry-run`
5. 收发 goroutine（12 字节头 + 裸 IPv4）

**DoD**（Windows 已用 testserver + 真实 Wintun 验证，网段用 `198.18.0.0/24`；Linux / macOS 未验证）

- [x] `up` 后默认路由**逐字节未变**
- [x] 只有剧本下发的网段指向 TUN
- [x] `ping` 内网通、`ping 8.8.8.8` 走物理网卡
- [x] `down` 后路由表与 `up` 前无差异（含服务端地址已有 /32 路由的情况）
- [x] `kill -9` 后再 `up` 能自动清理残留
- [ ] 三平台 `doctor` 通过（Windows 已通过）

**风险**：路由失败会破坏网络 → 必须实现回滚，且回滚本身要能失败重试。

---

## P4 · DNS 分区（2 天） 🟡 Windows 已验证，Linux / macOS 待验证

**范围**：`internal/route/dns_*.go`。

**任务**：`/etc/resolver`（macOS）、`resolvectl`（Linux）、NRPT（Windows）；无后缀时降级不改 DNS。

**DoD**

- [x] 内网域名走隧道 DNS，公网域名走本地（Windows；需处理空的组策略 NRPT 键，见 `docs/07` §3.3）
- [x] `down` 后 DNS 完全恢复（Windows）
- [ ] systemd-resolved 缺失时有明确提示，不改 `/etc/resolv.conf`
- [x] Windows NRPT 规则带 `Comment=vpnkit`，可精确清理
- [x] Windows 开着 Clash 系统代理时，内网走 VPN、国内直连、国外走代理三路同时可用（系统代理例外，`docs/07` §3.3）

---

## P5 · 性能与 UDP（3–5 天）

**范围**：`internal/tunnel/udp.go`，调优。

**任务**

1. UDP 承载（`udpport != 0` 时可用）
2. `--transport tcp|udp`
3. 缓冲区与并发调优
4. `status --json` 统计（收发包数、字节数、RTT）

**DoD**

- [ ] 同样内容下载，UDP 承载吞吐高于 TCP 承载（若网关支持）
- [ ] 8 小时稳定性：RSS 波动 < 20%
- [ ] 网络切换后 30 秒内自愈（本机 testserver 无法模拟：与客户端同机，流量不经过网卡；服务端断开后的退避重连已验证）

---

## 将来项（不在当前范围）

| 项 | 说明 |
|---|---|
| 按进程分流 | 需要平台级网络扩展/过滤驱动，工作量远大于本项目 |
| 系统钥匙串存密码 | 提升易用性 |
| 多配置并存 | `--profile` |
| GUI | 明确非目标 |
| 自有加密层 | 在隧道之上叠自有 TLS/QUIC，见 `docs/05` §4 |

---

## 联调检查表（真机）

只在上面全部 DoD 通过后执行：

1. [ ] `login` 真实网关成功
2. [ ] `up --dry-run` 输出的路由/DNS 命令合理
3. [ ] `up` 进入 `Running`
4. [ ] 内网系统可访问
5. [ ] 公网下载速度与不连时差异 < 10%
6. [ ] `status` 显示下发网段与虚拟 IP
7. [ ] `down` 后网络完全恢复
8. [ ] 记录：`enc`/`zip`/`udpport` 实际值、下发网段数
9. [ ] 全程 `--trace` 运行，保留日志文件；`grep assumption=` 核对每个假设点（`docs/11` §8.2）

第 8、9 项的结果要回填到 `docs/03`、`docs/04` §3 和 `docs/09` §3，把 `TODO(待实测)` 消掉。
