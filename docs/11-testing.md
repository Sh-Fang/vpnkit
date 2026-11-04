# 11 · 测试

原则：**离线可测。** 除最后的真机联调外，全部逻辑都能在没有真实网关的情况下验证。

## 1. 分层测试

| 层 | 方式 | 是否需网络 | 是否需 root |
|---|---|---|---|
| `pkg/wire` 编解码 | 表驱动单测 | 否 | 否 |
| `internal/tunnel` RC4 | 已知向量单测 | 否 | 否 |
| `internal/auth` | 假网关 httptest | 否 | 否 |
| `internal/command` 状态机 | 假服务端 | 否 | 否 |
| `internal/route` | 命令生成单测 + `--dry-run` | 否 | 否 |
| 端到端 | 假服务端 + 真实 TUN | 本地回环 | 是 |
| 真机联调 | 真实网关 | 是 | 是 |

## 2. 假网关（`testserver/`）

一个本地 TCP + HTTP 服务，实现同样的线格式。它让你可以在 P1–P4 全程不碰真网关。

### 2.1 职责

```
testserver/
├── httpauth.go     # /por/login_auth.csp, /por/login_psw.csp, /por/conf.csp, /por/rclist.csp
├── tunnel.go       # TCP 监听 :443 语义的假隧道
├── scripts.go      # 可编排的应答序列（剧本）
└── cmd/testserver/main.go
```

### 2.2 认证端点

| 端点 | 行为 |
|---|---|
| `GET /por/login_auth.csp` | 返回随机 `TwfID`、测试用 RSA 公钥、`CSRF_RAND_CODE` |
| `GET /public/psw_config` | 同上，可配置成返回**不同**的公钥（测兼容性） |
| `POST /por/login_psw.csp` | 用私钥解开密码，校验格式为 `password_csrf`，成功返回新 `TwfID` |
| `GET /por/conf.csp` | 返回可配置的 XML（`docs/09` §3） |
| `GET /por/rclist.csp` | 返回可配置的资源列表 |

密码校验用真 RSA 解密，能真正验证客户端加密是否正确——这是最有价值的一条测试。

### 2.3 隧道剧本

服务端行为要能编排，覆盖所有状态机分支。下面的 YAML 只表达语义：依赖白名单没有 YAML 库，
剧本以 Go 预置在 `testserver/scripts.go`（按"本令牌第几次建控制通道"给出步骤），`--script <名字>` 选择。

```yaml
rclist: ["10.0.0.0/8", "corp.example.com"]   # 由 HTTP 端 /por/rclist.csp 返回
script:
  - expect_bytes: 82          # ClientHello
  - send_bytes:  122
  - expect_bytes: 43
  - expect_bytes: 76
  - send_cmd: {code: 0, tapip: "10.8.0.2", lanip: "10.8.0.1",
               enc: 0, zip: 0, udpport: 0}   # 布局按 docs/04 §3.0 候选表编码
  - send_cmd: {code: 10}
  - send_cmd: {code: 11}
  - loop: {heartbeat_every: 10}
```

预置剧本：

| 剧本 | 覆盖 |
|---|---|
| `happy` | 正常接入 → 运行 → 主动断开 |
| `busy-then-ok` | 先回 code 5 三次，再成功（测退避） |
| `kick` | 运行中回 code 14（测被踢处理） |
| `shutdown` | 运行中回 code 8 |
| `reset` | 运行中回 code 3（测立即重连） |
| `bad-magic` | serverMsg 魔数错（测握手失败） |
| `silent` | 握手后不发心跳（测 watchdog） |
| `big-packets` | 持续推送大包（测 MTU 与分片） |
| `bad-sendip` | `SEND_IP` 中 `tapip` 为 `0.0.0.0`（测 `ErrSendIPLayout` 与原始 hex 日志） |
| `enc-required` | `SEND_IP` 中 `enc = 1`（测 `ErrEncryptionUnsupported`） |
| `no-valid` | 不发 10/11（测照常进入 `Running` 并告警） |
| `drop` | 首次运行中服务端直接断开，之后正常（测网络退避与恢复） |
| `unknown-cmd` | 运行中发未知码 99 与 4（测记录并忽略、连接保持） |

假网关的数据通道会对 ICMP echo 请求作答，配合内存 TUN 即可端到端验证收发。发往 53 端口的 UDP 查询也会得到应答：A 查询一律回 `198.18.0.10`，其他类型回空的 NOERROR，用于验证 DNS 分区走隧道。

无 root 时可用 `vpnkit up --fake-tun` 对着 testserver 跑完整 CLI：内存 TUN，路由/DNS 只打印不执行。

## 3. 单元测试要点

### 3.1 `pkg/wire`

表驱动，覆盖边界：

```go
func TestBuildClientMsg(t *testing.T) {
    // conn_type < 2 合法（控制通道），尾部 0xFFFFFFFF
    // 尾部标志：<2 → 0xFFFFFFFF；5/6/7/8 → htonl(arg)；其他 → 0
    // 偏移 8..11 == "JJYY"
    // 偏移 48..63 == token
    // 长度恒为 76
}
```

必须有的断言：

- `len(BuildClientHello()) == 82` 且前 5 字节为 `16 03 01 00 4d`
- `len(BuildCCSFinished()) == 43` 且前 6 字节为 `14 03 01 00 01 01`
- `ParseServerMsg` 对 `"XXXX"+...` 返回 `ErrBadServerMsg`
- `BuildDataFrame(op, pkt)` 的长度等于 `12+len(pkt)`，且 `pkt[4:8]` 等于总长

### 3.2 RC4

```go
// 关键用例：状态必须跨包连续
st := rc4.NewCipher(key)
var a, b []byte = pkt1, pkt2
st.XORKeyStream(a, a)
st.XORKeyStream(b, b)

st2 := rc4.NewCipher(key)
combined := append(append([]byte{}, pkt1...), pkt2...)
st2.XORKeyStream(combined, combined)
// 断言 a||b == combined
```

这个用例能抓住"每包重置状态"这个最容易犯的错。

### 3.3 路由命令生成

不真的执行命令，只断言生成的命令行正确：

```go
func TestRouteCommands(t *testing.T) {
    // macOS: ["route","-n","add","-net","10.0.0.0/8","-interface","utun5"]
    // linux: ["ip","route","add","10.0.0.0/8","dev","tun0"]
    // windows: ["netsh","interface","ipv4","add","route",...]
}
```

## 4. 端到端（本地）

需要 root，因为有真实 TUN。

```bash
sudo ./testserver --script happy &
sudo ./bin/vpnkit up --server 127.0.0.1 --dry-run    # 先看命令
sudo ./bin/vpnkit up --server 127.0.0.1
ping -c3 10.8.0.1
sudo ./bin/vpnkit down
```

断言：

- `up` 后默认路由未变
- 只有剧本里的网段指向 TUN
- `down` 后路由表恢复

## 5. 无 root 的 CI

CI 里跑不了 TUN，所以：

- 全部 `pkg/wire`、`internal/auth`、`internal/command` 测试必须无 root
- `internal/route` 只测命令生成，不执行
- TUN 相关通过接口注入一个 `fakeTUN`（内存管道），可测收发循环

`fakeTUN` 设计：

```go
type Device interface {
    Read([]byte) (int, error)
    Write([]byte) (int, error)
    MTU() (int, error)
    Name() (string, error)
    Close() error
}
```

生产实现包 `wireguard/tun`，测试实现是内存队列。

## 6. 手工验收

真机联调按 `docs/00-product.md` §5 逐条打勾。重点：

```bash
# 分流是否生效
netstat -rn -f inet | head -5        # macOS：default 必须指向物理网关
traceroute -n 8.8.8.8 | head -3      # 首跳必须是本地网关，不是隧道

# 恢复是否干净
vpnkit up; netstat -rn > /tmp/before
vpnkit down; netstat -rn > /tmp/after
diff /tmp/before /tmp/after          # 应无差异
```

## 7. 故障注入

| 注入 | 期望 |
|---|---|
| 掐断网络（关 Wi-Fi） | 进入 `Backoff`，恢复后自动重连 |
| `kill -9` 客户端 | 下次 `up` 检测到 `state.json` 并清理残留 |
| 服务端中途关闭连接 | 进入 `Backoff`，按策略重连 |
| 服务端回未知命令码 | 记录并忽略，连接保持 |
| TUN 设备被外部删除 | watchdog 检出，回滚退出 6 |

## 8. 联调诊断日志

没有抓包可供对照，第一次真机联调基本是唯一的取证机会。日志必须足以事后还原线上字节。

### 8.1 分级

| 级别 | 开关 | 内容 |
|---|---|---|
| info | 默认 | 状态转换、握手成败、下发网段数、退避原因 |
| debug | `--verbose` | 握手五段字节数；每条命令的命令码 + 40 字节完整 hex；clientMsg hex（会话令牌掩码）；所有数据帧 12 字节头 |
| trace | `--trace` | debug 全部 + 每个 IP 包的头部摘要（源/目的/协议/长度）。**不输出负载**——那是用户业务流量 |

### 8.2 假设点标记

每个待实测假设点（`AGENTS.md` §6）在被使用时打一条结构化日志，带固定键 `assumption`：

```
level=DEBUG msg="using assumption" assumption=ctrl_conn_type value=1
level=DEBUG msg="using assumption" assumption=sendip_layout value=candidate-v1
```

已定义的键：`handshake_template`、`rsa_exp`、`login_next_auth`、`clientmsg_prefix`、`ctrl_conn_type`、`token_encoding`、`sendip_layout`、`data_opcode`、`data_endian`、`rc4_key`、`valid_10_11`、`is_hid_user`，
以及实现中新增的 `data_conn`、`heartbeat_format`、`kick_reason`、`rclist_format`、`device_id_field`、`login_same_twfid`、`hid_response_tags`、`hid_probe`、`hid_submit`、`hid_result`、`hid_register`。
联调后 `grep assumption=` 即可列出本次运行依赖的全部假设及取值，据此回填 `docs/03`、`docs/04`。

### 8.3 脱敏

沿用 `AGENTS.md` §4：会话令牌、设备标识掩码（首尾各 4 字符），密码与 RSA 明文永不输出。hex dump 中令牌所在字节同样掩码。

### 8.4 输出位置

默认写 stderr。`--verbose` 或 `--trace` 时同时写 `~/.config/vpnkit/logs/vpnkit-<时间戳>.log`（权限 `0600`），保留最近 `log.file_keep`（默认 10）份。

