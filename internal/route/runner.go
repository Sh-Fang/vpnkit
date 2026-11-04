package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Sh-Fang/vpnkit/internal/logx"
)

// Runner 抽象系统变更。Query 是只读查询，--dry-run 时仍会真实执行。
type Runner interface {
	Run(ctx context.Context, argv []string) ([]byte, error)
	Query(ctx context.Context, argv []string) ([]byte, error)
	WriteFile(path, content string) error
	RemoveFile(path string) error
	ReadFile(path string) ([]byte, error)
	LookPath(name string) bool
	LinkExists(name string) bool
}

// ExecRunner 真实执行命令。
type ExecRunner struct{ Log *slog.Logger }

func (r ExecRunner) Run(ctx context.Context, argv []string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	logx.Or(r.Log).Debug("exec", "cmd", ShellQuote(argv), "err", err, "out", strings.TrimSpace(string(out)))
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", ShellQuote(argv), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (r ExecRunner) Query(ctx context.Context, argv []string) ([]byte, error) {
	return r.Run(ctx, argv)
}

func (ExecRunner) WriteFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func (ExecRunner) RemoveFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (ExecRunner) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (ExecRunner) LookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (ExecRunner) LinkExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// DryRunner 只打印将要执行的变更，不落盘（docs/07 §7）。只读查询照常执行，让输出尽量接近真实。
type DryRunner struct {
	Out    io.Writer
	Reader Runner // 只读查询的执行者，通常是 ExecRunner；nil 时查询返回错误
	mu     sync.Mutex
}

func (d *DryRunner) print(format string, a ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.Out, format+"\n", a...)
}

func (d *DryRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	d.print("+ %s", ShellQuote(argv))
	return nil, nil
}

func (d *DryRunner) Query(ctx context.Context, argv []string) ([]byte, error) {
	if d.Reader == nil {
		return nil, errors.New("dry-run: 未配置查询执行者")
	}
	return d.Reader.Query(ctx, argv)
}

func (d *DryRunner) WriteFile(path, content string) error {
	d.print("+ write %s <<EOF\n%sEOF", path, content)
	return nil
}

func (d *DryRunner) RemoveFile(path string) error {
	d.print("+ rm -f %s", path)
	return nil
}

func (d *DryRunner) ReadFile(path string) ([]byte, error) {
	if d.Reader == nil {
		return nil, os.ErrNotExist
	}
	return d.Reader.ReadFile(path)
}

func (d *DryRunner) LookPath(name string) bool {
	return d.Reader != nil && d.Reader.LookPath(name)
}

func (d *DryRunner) LinkExists(name string) bool {
	return d.Reader == nil || d.Reader.LinkExists(name)
}
