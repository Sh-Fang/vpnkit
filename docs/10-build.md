# 10 · 构建与发布

## 1. 环境

| 项 | 要求 |
|---|---|
| Go | 1.22 或更新 |
| 平台 | 任意都能交叉编译；`windows` 产物在 Linux 上可直接编出 |
| CGO | **关闭**（`CGO_ENABLED=0`），保证单文件、无 libc 依赖 |

## 2. 依赖

允许的第三方依赖（白名单）：

| 依赖 | 用途 | 必要性 |
|---|---|---|
| `golang.org/x/sys` | 平台系统调用 | 必需 |
| `golang.zx2c4.com/wireguard/tun` | 三平台 TUN 抽象 | 强烈建议 |

其余一律用标准库。**不要**引入：

- `gvisor`、`lwip`、任何用户态 TCP/IP 栈（本项目承载裸 IP，不需要）
- 任何 VPN 协议实现库
- 任何 Web 框架（CLI 不需要）

新增依赖必须在提交说明里写理由，并更新本表。

## 3. 构建

```bash
# 本机
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/vpnkit ./cmd/vpnkit

# 交叉编译
for os in darwin linux windows; do
  for arch in amd64 arm64; do
    ext=""; [ "$os" = "windows" ] && ext=".exe"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
      go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags)" \
      -o "dist/vpnkit-$os-$arch$ext" ./cmd/vpnkit
  done
done
```

`Makefile` 目标：`build`、`test`、`lint`、`dist`、`clean`。

## 4. 版本注入

```go
// cmd/vpnkit/main.go
var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
)
```

`-X main.version=...` 注入。`vpnkit --version` 输出三行。

## 5. 测试与静态检查

```bash
go vet ./...
go test ./... -race -count=1
go test ./pkg/wire -run Test -v          # 纯函数，表驱动
```

CI 顺序：`vet` → `test -race` → `build`（全平台矩阵）。

`-race` 必须开：并发收发是主要缺陷来源。

## 6. Windows 的 wintun.dll

若使用建议的 TUN 库，dll 通过 `//go:embed` 内嵌，运行时释放到临时目录。
注意：

- 释放路径用 `os.MkdirTemp` 生成，退出时删除
- 不要在只读目录里释放
- 杀毒软件可能拦截 dll 释放，`doctor` 里加一条检查并在失败时给出提示

## 7. 发布

| 项 | 约定 |
|---|---|
| 版本号 | 语义化版本，`v0.x.y` |
| 产物 | 6 个二进制 + `SHA256SUMS` |
| 校验 | 发布说明里贴 `SHA256SUMS` |
| 变化说明 | 按 `AGENTS.md` §7 的提交规范汇总 |

不提供自动更新。用户自行替换二进制。

## 8. 最小验证清单（每次发布前）

- [ ] 三平台各跑一次 `vpnkit doctor`
- [ ] `pkg/wire` 全部单测通过，含 RC4 连续状态用例
- [ ] `up --dry-run` 在三平台输出的命令都合法
- [ ] 帮助文本里没有出现内部术语（如具体网关产品名）
- [ ] `--version` 输出正确
