# 02 · 认证协议

认证层是标准 HTTPS + RSA，没有私有改造。可以独立于隧道实现和测试。

## 1. 请求序列

| 步 | 请求 | 作用 | 必需 |
|---|---|---|---|
| 1 | `GET /por/login_auth.csp` | 取会话令牌、RSA 公钥、CSRF 随机码 | ✅ |
| 2 | `GET /public/psw_config` | 再取一次公钥与 CSRF 码（部分网关以此为准） | 可选 |
| 3 | `POST /por/login_psw.csp?anti_replay=1&encrypt=1` | 提交账号与密码密文 | ✅ |
| 4 | 后续所有请求 | 带 `TWFID: <令牌>` 请求头 | ✅ |
| 5 | `GET /por/conf.csp` | 全局配置（线路、带宽、隧道参数） | ✅ |
| 6 | `GET /por/rclist.csp` | 资源列表 | 可选 |

### 1.1 响应解析

第 1 步返回体中需要提取的字段：

| 字段 | 用途 |
|---|---|
| `TwfID` | 会话令牌，后续请求头 `TWFID` |
| `RSA_ENCRYPT_KEY` | 公钥模数 n（十六进制） |
| `RSA_ENCRYPT_EXP` | 公钥指数 e（十六进制，通常 `10001`） |
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
e := int(new(big.Int).SetString(rsaExpHex, 16).Int64())
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
2. 响应体包含新的令牌，且与请求前不同

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
