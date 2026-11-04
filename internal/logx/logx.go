// Package logx 统一日志：slog + trace 级 + 脱敏 + 假设点标记（docs/11 §8）。
package logx

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
)

// LevelTrace 比 debug 更低一级，用于每包 IP 头摘要（docs/11 §8.1）。
const LevelTrace = slog.Level(-8)

// ParseLevel 解析 docs/09 的 log.level。
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("未知日志级别 %q", s)
}

// Options 控制日志输出。
type Options struct {
	Level  slog.Level
	Format string    // text | json
	Stderr io.Writer // 默认 os.Stderr
	// FileDir 非空时同时写一份到 FileDir/vpnkit-<时间戳>.log（0600），
	// 用于 --verbose/--trace 的联调取证（docs/11 §8.4）。
	FileDir  string
	FileKeep int
}

// Setup 构建 logger；返回的 close 负责关闭日志文件。
func Setup(o Options) (*slog.Logger, func(), error) {
	w := o.Stderr
	if w == nil {
		w = os.Stderr
	}
	closeFn := func() {}
	var filePath string
	if o.FileDir != "" {
		if err := fsutil.MkdirPrivate(o.FileDir); err != nil {
			return nil, closeFn, err
		}
		filePath = filepath.Join(o.FileDir, "vpnkit-"+time.Now().Format("20060102-150405")+".log")
		f, err := fsutil.OpenPrivate(filePath)
		if err != nil {
			return nil, closeFn, err
		}
		w = io.MultiWriter(w, f)
		closeFn = func() { f.Close() }
		keep := o.FileKeep
		if keep <= 0 {
			keep = 10
		}
		Rotate(o.FileDir, keep)
	}
	hopts := &slog.HandlerOptions{Level: o.Level, ReplaceAttr: replaceLevel}
	var h slog.Handler
	if o.Format == "json" {
		h = slog.NewJSONHandler(w, hopts)
	} else {
		h = slog.NewTextHandler(w, hopts)
	}
	l := slog.New(h)
	if filePath != "" {
		l.Info("日志同时写入文件", "path", filePath)
	}
	return l, closeFn, nil
}

func replaceLevel(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if lv, ok := a.Value.Any().(slog.Level); ok && lv <= LevelTrace {
			a.Value = slog.StringValue("TRACE")
		}
	}
	return a
}

// Rotate 只保留最近 keep 份日志文件。
func Rotate(dir string, keep int) {
	m, _ := filepath.Glob(filepath.Join(dir, "vpnkit-*.log"))
	if len(m) <= keep {
		return
	}
	sort.Strings(m) // 文件名含时间戳，字典序即时间序
	for _, p := range m[:len(m)-keep] {
		_ = os.Remove(p)
	}
}

// Discard 返回丢弃一切输出的 logger，供测试与库默认值使用。
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 100}))
}

// Or 在 l 为 nil 时返回 Discard()。
func Or(l *slog.Logger) *slog.Logger {
	if l == nil {
		return Discard()
	}
	return l
}

// Trace 以 trace 级记录。
func Trace(l *slog.Logger, msg string, args ...any) {
	Or(l).Log(context.Background(), LevelTrace, msg, args...)
}

// Assumption 记录一个待实测假设点的取值（AGENTS.md §6，docs/11 §8.2）。
// 联调后 grep assumption= 即可还原本次运行依赖的全部假设。
func Assumption(l *slog.Logger, key string, value any, args ...any) {
	Or(l).Debug("using assumption", append([]any{"assumption", key, "value", value}, args...)...)
}

// Mask 掩码敏感值：保留首尾各 4 字符（AGENTS.md §4）。
// 不足 9 字符时全部掩掉，否则首尾 8 字符已覆盖全部内容。
func Mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// Span 是 hex dump 中需要掩码的字节区间 [Off, Off+Len)。
type Span struct{ Off, Len int }

// Hex 输出小写 hex，落在 masks 内的字节输出为 "**"。
// 用于 clientMsg 等含令牌报文的 debug dump（docs/11 §8.3）。
func Hex(b []byte, masks ...Span) string {
	if len(masks) == 0 {
		return hex.EncodeToString(b)
	}
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for i, c := range b {
		masked := false
		for _, m := range masks {
			if i >= m.Off && i < m.Off+m.Len {
				masked = true
				break
			}
		}
		if masked {
			sb.WriteString("**")
		} else {
			sb.WriteString(hex.EncodeToString([]byte{c}))
		}
	}
	return sb.String()
}
