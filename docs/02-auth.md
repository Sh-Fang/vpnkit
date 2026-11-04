# 02 · 认证协议

认证层是标准 HTTPS + RSA，没有私有改造。可以独立于隧道实现和测试。

## 1. 请求序列

| 步 | 请求 | 作用 | 必需 |
|---|---|---|---|
| 1 | `GET /por/login_auth.csp` | 取会话令牌、RSA 公钥、CSRF 随机码 | ✅ |
| 2 | `GET /public/psw_config` | 再取一次公钥与 CSRF 码（部分网关以此为准） | 可选 |
| 3 | `POST /por/login_psw.csp?anti_replay=1&encrypt=1` | 提交账号与密码密文 | ✅ |
| 4 | 后续所有请求 | 带 `TWFID: <令牌>` 请求头（实现同时带 `Cookie: TWFID=<令牌>`，常见网关读 Cookie） | ✅ |
| 5 | `GET /por/conf.csp` | 全局配置（线路、带宽、隧道参数） | ✅ |
| 6 | `GET /por/rclist.csp` | 资源列表（内网网段与内网域名后缀的唯一来源，`docs/09` §4） | ✅ |

### 1.1 响应解析

第 1 步返回体中需要提取的字段：

| 字段 | 用途 |
|---|---|
| `TwfID` | 会话令牌，后续请求头 `TWFID` |
| `RSA_ENCRYPT_KEY` | 公钥模数 n（十六进制） |
| `RSA_ENCRYPT_EXP` | 公钥指数 e。实测 M7.6.8R2 写十进制 `65537`；也可能写十六进制 `10001`，两种都要认（见 §2） |
| `CSRF_RAND_CODE` | 密码拼接用随机码 |
| `RndImg` / `StartAuth` | 图形验证码是否启用 |

字段名可能出现在 HTML、JSON 或 JS 变量赋值中，解析器要容错：先按 JSON 解析，失败则用正则兜底，再失败则报格式错误（不要静默返回空值）。

> 实现提示：把第 1 步和第 2 步都做一次，以**最后一次拿到的**公钥与 CSRF 码为准。部分网关两处返回不一致。

## 2. 密码加密

```
plaintext = password + "_" + CSRF_RAND_CODE
cipher    = RSA_PKCS1_v1_5(plaintext, n, e)
field     = hex(cipher).upper()
```

注意事项：

- 是**大写**十六进制
- 拼接用下划线 `_`，不是别的分隔符
- PKCS#1 v1.5 填充，不是 OAEP
- 明文长度受密钥长度限制：模数 1024 位时明文最多 117 字节；密码 + `_` + 随机码超长时要报错而不是截断

Go 实现要点：

```go
n := new(big.Int); n.SetString(rsaKeyHex, 16)
e, _ := wire.ParseRSAExp(rsaExp) // 十进制 "65537"；"10001"、带 0x 或含 a–f 时按十六进制
pub := &rsa.PublicKey{N: n, E: e}
ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(plaintext))
```

## 3. 登录表单字段

`POST /por/login_psw.csp?anti_replay=1&encrypt=1`，`Content-Type: application/x-www-form-urlencoded`：

| 字段 | 值 |
|---|---|
| `svpn_name` | 账号 |
| `svpn_password` | 上一节算出的密文 |
| `svpn_req_randcode` | `CSRF_RAND_CODE` 原文 |
| `svpn_rand_code` | `md5(用户输入的图形验证码)`，未启用时留空 |
| `mitm_result` | 中间人检测结果，通常 `1` |

**兼容性提示**：不同网关版本对最后两个字段名不一致——`mitm_result` 与 `mitm` 都出现过；部分网关接受 `?type=cs` 且 `svpn_rand_code` 可留空。因此这两个字段必须做成配置项，不要写死。

配置项（`docs/09` 的 `[auth]` 段）：

```toml
[auth]
mitm_field = "mitm_result"   # 或 "mitm"
send_rand_code = false       # 未启用图形验证码时
```

## 4. 成功判定

登录成功后响应里会回写新的 `TwfID`。判定规则：

1. HTTP 200
2. 响应体（或 `Set-Cookie: TWFID`）包含新的令牌，且与请求前不同

实测 M7.6.8R2：成功时响应只有 `<ErrorCode>1</ErrorCode><Message>Auth is success</Message>`，不带 `TwfID`、
也不发 `Set-Cookie`，令牌沿用第 1 步拿到的那个。因此带明确成功码（`Result=1` 或 `ErrorCode=1`）时放行，
沿用原令牌，打 warn 与 `assumption=login_same_twfid`。

成功响应若带 `NextAuth` 且不是 `-1`，说明网关还要二次认证（短信、令牌、设备登记等），当前版本报 `ErrSecondFactor`，
退出码 3。`NextAuth`、`NextService` 的值记入 `assumption=login_next_auth`。

实测该网关固件 M7.6.8R2 对启用设备绑定的账号返回 `NextAuth=4 NextService=auth/hid`（hid = 硬件标识登记，
对应 SDK 枚举 `SFAuthTypeHardId=4`）。实测该步响应 `CurAuth=1 IsFirstAuth=1`，`NextServiceSubType`/
`ChallengeMsg`/`AuthInfo` 为空、另带一个新的 `CSRF_RAND_CODE`——即纯特征码提交、无短信/令牌式交互。

### 4.1 特征码二次认证（`NextAuth=4`）

这一步是一次**纯特征码挑战**：网关拿你在册的硬件指纹和提交值比对，不涉及短信验证码、令牌或交互。

请求由 Web 端 SDK 的 `loginHid` 发出，形状是固定的：

```
POST /por/login_hid.csp?manual_submit=1
Content-Type: application/x-www-form-urlencoded
Cookie: TWFID=<第 1 步的令牌>

hid=<32 位大写十六进制>&hostname=<base64 主机名>&macaddress=<aa-bb-cc-dd-ee-ff>&ignore=0&svpn_req_randcode=<CSRF>
```

四条硬约束，缺任何一条都会被网关判 `ErrorCode=20210`（`submit param error.`）：

1. 查询串是 **`manual_submit=1`**，不是 `type=cs&language=…&encrypt=1` 那一套。
2. 表单体是**四个**字段：`hid`、`hostname`、`macaddress`、`ignore=0`。只发 `hid` 会被判参数错误。
3. 字段名就是 `hid`，不是 `svpn_inputhid` 之类按 `auth/sms`→`svpn_inputsms` 规律外推的名字。
4. 参数只放表单体。拼进 URL 查询串会被网关按未知路径处理，直接 404。

**反重放握手**：网关判 `20210` 时会在响应里回一个新的 `CSRF_RAND_CODE`，这是"带上新值再试一次"的信号，
因此实现携带 `svpn_req_randcode`，并在被判 `20210` 时用响应里的新 CSRF 重试**一次**（不无限重试）。
三段的取值全部照官方 SDK 的形式（`docs/06` §3）：`hostname` 是**标准 base64** 的主机名，
`macaddress` 是**小写连字符**的 `aa-bb-cc-dd-ee-ff`。两者是给管理员审批时看的元数据，
网关真正比对的是 `hid`；但形状不对一样会被判 `20210`。

**响应**

- 成功：`<Result>1</Result>` 或 `<ErrorCode>1</ErrorCode>`，可能换发新 `TwfID`，也可能沿用原令牌。
- 还要求继续认证：带 `<NextAuth>`；本实现报 `ErrSecondFactor`，退出码 3。
- `20210`：提交内容不被接受。若带上新 CSRF 重试仍失败，实现会只读 GET 一次
  `/por/hardid.csp?manual_submit=1`（`assumption=hardid_page`，`--trace` 下带正文），
  那张页面的表单就是网关认可的字段清单，比继续猜可靠。

### 4.2 认证不过 = 设备没绑定

`login_hid.csp` 只负责**认证**，不负责**登记**。机器没在网关侧绑定过时，这一步必然失败——
此时要另发一次绑定申请，把机器送进管理员的审批队列：

```
POST /por/submithid.csp
Content-Type: application/x-www-form-urlencoded

hid=<特征码>&hostname=<base64 主机名>&macaddress=<aa-bb-cc-dd-ee-ff>
```

三个字段都在表单体里，没有查询串，也没有 `ignore`。三段值的形状与 §4.1 完全一致。

网关的特征码页（`GET /por/hardid.csp?manual_submit=1`）会直接说明该走哪条路，典型回执：

```xml
<Result>2</Result>
<ErrorCode>1</ErrorCode>
<Message>get hard id auth type success</Message>
<ADMIN_HINT>直接点击下方提交即可，会自动审核</ADMIN_HINT>
```

`ADMIN_HINT` 是给人看的，但它也是权威的流程说明：**设备没在册时认证必然不过，正确动作是提交绑定**。

因此实现按三段走：

1. `login_hid.csp` 认证。通过则直接完成。
2. 不通过（任何原因，含 `20210`）→ 提交 `submithid.csp`。
3. 提交成功且该网关自动审核 → **重跑一次登录**（递归深度上限 1），这一回网关不再要特征码。

提交后若网关要管理员审批，则报 `ErrDevicePending`（退出码 3）并把网关消息透传出来。

### 4.2.1 取特征码的本地接口

界面上显示的特征码来自客户端本地服务：`Q_HID` 查询返回 `hid|macAddress|hostName`
三段以 `|` 分隔的字符串，`Q_ALLHID` 返回完整清单。SDK 的 `getHid` 把它按 `|` 切开后
分别填进 §4.1 的三个字段——这就是三段值的来源，已核对到实现层。

本实现不依赖该本地服务，直接按 `docs/06` 计算，因此**算出的值必须与在册值一致**，
否则网关侧看到的是一台陌生设备。

### 4.3 默认不提交

自动提交会把机器登记进网关的设备绑定队列，属于有副作用的操作，因此**默认关闭**：
命中二次认证且未开启时，报 `ErrSecondFactor` 并提示加 `--register-device`（配置项 `auth.register_device`）。

开启后每次登录都会带上本机特征码。特征码由磁盘序列号与网卡列表现算，**要素一变值就变**——
换 Wi-Fi、插网线、起 docker 都会让网关把本机当成新设备，于是又要求审批一次。

因此实现了自动固化：`--register-device` 登录成功后，立即把本次用的三段值写入 `device-id`
（`docs/06` §5），之后一律用它。这样同一台机器只审批一次；换机器时删掉该文件或
`vpnkit devid pin` 重新固化即可。

### 4.4 取证日志

- `assumption=hid_submit`：端点 + 字段名 + 特征码掩码
- `assumption=hid_result`：返回码、`NextAuth`、可读消息、是否换发令牌
- `assumption=hid_register`：绑定申请端点的参数名与掩码后的取值（特征码明文不入日志）

图形验证码：`RndImg=1` 时当前版本直接报错（退出码 3），暂不支持拉取验证码图片；`--captcha` 仅用于已知验证码的场景。

证书：网关多为自签证书。默认**校验**证书；用 `server.ca_file`（或 `--ca-file`）信任指定 CA，
确认网络可信时才用 `server.insecure = true`（或 `--insecure`），后者会打 warn。
出厂证书自签且只有 `CN=sslvpn`、不带 SAN，与网关域名对不上，`ca_file` 也校验不过；此时用
`server.cert_sha256`（或 `--cert-sha256`）只信任这一张叶子证书，指纹不符报 `ErrCertMismatch` 并给出实际指纹。
指纹可用 `openssl s_client -connect <host>:443 | openssl x509 -noout -fingerprint -sha256` 获取。

失败时通常返回一个错误码字段与可读消息。要求：

- 错误消息要透传给用户（便于自助排查，例如密码错、账号锁定、需图形验证码）
- **不要**把原始响应体整体打进日志（可能含令牌）

## 5. 令牌存储

`~/.config/vpnkit/session.json`，权限 `0600`：

```json
{
  "server": "vpn.example.com",
  "user": "alice",
  "twfid": "…",
  "obtained_at": "2026-01-01T00:00:00Z",
  "expires_hint": 3600
}
```

规则：

- 令牌**不写日志**，`status` 输出时掩码为 `abcd…wxyz`
- 收到鉴权失败时删除该文件并返回退出码 3
- 不同 `--server` 的令牌分文件存放：`session-<host>.json`

## 6. 测试

用 `testserver/` 的假网关覆盖：

| 用例 | 期望 |
|---|---|
| 正常返回 | 令牌被正确提取并落盘 |
| 公钥在 `psw_config` 里与第 1 步不同 | 以第二次为准 |
| 令牌字段缺失 | 返回明确的格式错误，不 panic |
| 401 | 退出码 3，删除 session 文件 |
| 密码超长 | 返回明确错误，不截断 |
